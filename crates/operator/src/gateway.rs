//! A gateway: the Deployment, Service, PodDisruptionBudget and HPA that
//! put dvarapala in front of one backend Service port for one policy.

use std::collections::BTreeMap;

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::autoscaling::v2::{
    CrossVersionObjectReference, HorizontalPodAutoscaler, HorizontalPodAutoscalerSpec, MetricSpec,
    MetricTarget, ResourceMetricSource,
};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMapVolumeSource, Container, ContainerPort, EnvFromSource, EnvVar, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile, SecretEnvSource, SecurityContext,
    Service, ServicePort, ServiceSpec, TCPSocketAction, TopologySpreadConstraint, Volume,
    VolumeMount,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use crate::crd::{Autoscaling, PolicySpec};
use crate::policy::{self, FILE};

pub const MANAGED_BY: (&str, &str) = ("app.kubernetes.io/managed-by", "dvarapala-operator");
pub const APP: (&str, &str) = ("app.kubernetes.io/name", "dvarapala-gateway");
pub const GATEWAY: &str = "dvarapala.franzramadhan.dev/gateway";
pub const BACKEND: &str = "dvarapala.franzramadhan.dev/backend";
pub const POLICY: &str = "dvarapala.franzramadhan.dev/policy";
/// On the gateway Service: `passthrough` or `protecting`.
pub const PHASE: &str = "dvarapala.franzramadhan.dev/phase";
/// On the pod template: rolls the gateway when a restart key changes.
pub const RESTART_HASH: &str = "dvarapala.franzramadhan.dev/restart-hash";

const LISTEN: i32 = 8080;
const METRICS: i32 = 9090;
const MOUNT: &str = "/etc/dvarapala";

/// One backend Service port behind one policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Gateway {
    pub name: String,
    pub namespace: String,
    pub backend: String,
    pub port: i32,
    pub port_name: Option<String>,
    pub app_protocol: Option<String>,
    pub policy: String,
    pub http2: bool,
}

/// The gateway Service's name: `<service>-dvp-<hash>`, at most 63
/// characters, the same for the same service, port and policy.
pub fn name(service: &str, port: &str, policy: &str) -> String {
    let h = policy::hash(&format!("{service}/{port}/{policy}"));
    let mut s: String = service.chars().take(63 - 5 - 8).collect();
    while s.ends_with('-') {
        s.pop();
    }
    format!("{s}-dvp-{}", &h[..8])
}

/// The gateway for `port` (a number or a port name) of `backend`, or why
/// that backend is left as it is.
pub fn plan(backend: &Service, port: &str, policy: &str, grpc: bool) -> Result<Gateway, String> {
    let svc = backend.metadata.name.clone().unwrap_or_default();
    let reason = |r: &str| Err(format!("{svc}:{port}: {r}"));
    let spec = backend.spec.clone().unwrap_or_default();
    if spec.type_.as_deref() == Some("ExternalName") {
        return reason("ExternalName Service");
    }
    if spec.selector.as_ref().is_none_or(BTreeMap::is_empty) {
        return reason("Service without a selector");
    }
    let found = spec
        .ports
        .iter()
        .flatten()
        .find(|p| p.port.to_string() == port || p.name.as_deref() == Some(port));
    let Some(p) = found else {
        return reason("no such port");
    };
    if p.protocol.as_deref().is_some_and(|x| x != "TCP") {
        return reason("not a TCP port");
    }
    if p.app_protocol.as_deref() == Some("https") {
        return reason("https backends are not supported yet");
    }
    Ok(Gateway {
        name: name(&svc, port, policy),
        namespace: backend.metadata.namespace.clone().unwrap_or_default(),
        backend: svc,
        port: p.port,
        port_name: p.name.clone(),
        app_protocol: p.app_protocol.clone(),
        policy: policy.into(),
        http2: grpc || p.app_protocol.as_deref() == Some("kubernetes.io/h2c"),
    })
}

fn labels(g: &Gateway) -> BTreeMap<String, String> {
    [
        MANAGED_BY,
        APP,
        (GATEWAY, &g.name),
        (BACKEND, &g.backend),
        (POLICY, &g.policy),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

fn selector(g: &Gateway) -> BTreeMap<String, String> {
    BTreeMap::from([(GATEWAY.into(), g.name.clone())])
}

fn meta(g: &Gateway) -> ObjectMeta {
    ObjectMeta {
        name: Some(g.name.clone()),
        namespace: Some(g.namespace.clone()),
        labels: Some(labels(g)),
        ..ObjectMeta::default()
    }
}

/// The Service routes point at: first the backend's pods (`protecting`
/// false), then the gateway's.
pub fn service(g: &Gateway, backend: &Service, protecting: bool) -> Service {
    let spec = backend.spec.clone().unwrap_or_default();
    let target = spec
        .ports
        .iter()
        .flatten()
        .find(|p| p.port == g.port)
        .and_then(|p| p.target_port.clone())
        .unwrap_or(IntOrString::Int(g.port));
    let mut m = meta(g);
    let phase = if protecting {
        "protecting"
    } else {
        "passthrough"
    };
    m.annotations = Some(BTreeMap::from([(PHASE.into(), phase.into())]));
    Service {
        metadata: m,
        spec: Some(ServiceSpec {
            selector: if protecting {
                Some(selector(g))
            } else {
                spec.selector
            },
            ports: Some(vec![ServicePort {
                name: g.port_name.clone(),
                port: g.port,
                target_port: Some(if protecting {
                    IntOrString::Int(LISTEN)
                } else {
                    target
                }),
                app_protocol: g.app_protocol.clone(),
                protocol: Some("TCP".into()),
                ..ServicePort::default()
            }]),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

fn env(name: &str, value: String) -> EnvVar {
    EnvVar {
        name: name.into(),
        value: Some(value),
        value_from: None,
    }
}

fn quantities(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, Quantity>> {
    Some(
        pairs
            .iter()
            .map(|(k, v)| ((*k).into(), Quantity((*v).into())))
            .collect(),
    )
}

pub fn deployment(g: &Gateway, p: &PolicySpec, image: &str, restart_hash: &str) -> Deployment {
    let upstream = format!("http://{}.{}.svc:{}", g.backend, g.namespace, g.port);
    let protocol = if g.http2 { "http2" } else { "http1" };
    let resources = p.gateway.resources.clone().unwrap_or(ResourceRequirements {
        requests: quantities(&[("cpu", "50m"), ("memory", "16Mi")]),
        limits: quantities(&[("memory", "64Mi")]),
        ..ResourceRequirements::default()
    });
    let container = Container {
        name: "dvarapala".into(),
        image: Some(image.into()),
        args: Some(vec![
            "serve".into(),
            "--config".into(),
            format!("{MOUNT}/{FILE}"),
        ]),
        env: Some(vec![
            env("DVARAPALA__LISTEN", format!("0.0.0.0:{LISTEN}")),
            env("DVARAPALA__UPSTREAM", upstream),
            env("DVARAPALA__UPSTREAM_PROTOCOL", protocol.into()),
            env("DVARAPALA__METRICS__LISTEN", format!("0.0.0.0:{METRICS}")),
            env("DVARAPALA__CONFIG_WATCH", "10s".into()),
        ]),
        env_from: p.secret_ref.as_ref().map(|s| {
            vec![EnvFromSource {
                secret_ref: Some(SecretEnvSource {
                    name: s.name.clone(),
                    optional: None,
                }),
                ..EnvFromSource::default()
            }]
        }),
        ports: Some(vec![
            ContainerPort {
                name: Some("http".into()),
                container_port: LISTEN,
                ..ContainerPort::default()
            },
            ContainerPort {
                name: Some("metrics".into()),
                container_port: METRICS,
                ..ContainerPort::default()
            },
        ]),
        readiness_probe: Some(Probe {
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(LISTEN),
                host: None,
            }),
            period_seconds: Some(2),
            ..Probe::default()
        }),
        resources: Some(resources),
        security_context: Some(SecurityContext {
            run_as_non_root: Some(true),
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                add: None,
            }),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                localhost_profile: None,
            }),
            ..SecurityContext::default()
        }),
        volume_mounts: Some(vec![VolumeMount {
            name: "config".into(),
            mount_path: MOUNT.into(),
            read_only: Some(true),
            ..VolumeMount::default()
        }]),
        ..Container::default()
    };
    let pod_labels: BTreeMap<String, String> = [MANAGED_BY, APP, (GATEWAY, &g.name)]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    Deployment {
        metadata: meta(g),
        spec: Some(DeploymentSpec {
            // an HPA owns the count when autoscaling is on
            replicas: p.gateway.autoscaling.is_none().then(|| replicas(p)),
            selector: LabelSelector {
                match_labels: Some(selector(g)),
                match_expressions: None,
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(pod_labels),
                    annotations: Some(BTreeMap::from([(RESTART_HASH.into(), restart_hash.into())])),
                    ..ObjectMeta::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    automount_service_account_token: Some(false),
                    topology_spread_constraints: Some(vec![TopologySpreadConstraint {
                        max_skew: 1,
                        topology_key: "kubernetes.io/hostname".into(),
                        when_unsatisfiable: "ScheduleAnyway".into(),
                        label_selector: Some(LabelSelector {
                            match_labels: Some(selector(g)),
                            match_expressions: None,
                        }),
                        ..TopologySpreadConstraint::default()
                    }]),
                    volumes: Some(vec![Volume {
                        name: "config".into(),
                        config_map: Some(ConfigMapVolumeSource {
                            name: policy::config_map_name(&g.policy),
                            ..ConfigMapVolumeSource::default()
                        }),
                        ..Volume::default()
                    }]),
                    ..PodSpec::default()
                }),
            },
            ..DeploymentSpec::default()
        }),
        status: None,
    }
}

fn replicas(p: &PolicySpec) -> i32 {
    p.gateway.replicas.unwrap_or(2).max(1)
}

pub fn pdb(g: &Gateway) -> PodDisruptionBudget {
    PodDisruptionBudget {
        metadata: meta(g),
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector {
                match_labels: Some(selector(g)),
                match_expressions: None,
            }),
            ..PodDisruptionBudgetSpec::default()
        }),
        status: None,
    }
}

pub fn hpa(g: &Gateway, p: &PolicySpec, a: &Autoscaling) -> HorizontalPodAutoscaler {
    HorizontalPodAutoscaler {
        metadata: meta(g),
        spec: Some(HorizontalPodAutoscalerSpec {
            scale_target_ref: CrossVersionObjectReference {
                api_version: Some("apps/v1".into()),
                kind: "Deployment".into(),
                name: g.name.clone(),
            },
            min_replicas: Some(replicas(p)),
            max_replicas: a.max_replicas.max(replicas(p)),
            metrics: Some(vec![MetricSpec {
                type_: "Resource".into(),
                resource: Some(ResourceMetricSource {
                    name: "cpu".into(),
                    target: MetricTarget {
                        type_: "Utilization".into(),
                        average_utilization: Some(a.target_cpu.unwrap_or(70)),
                        ..MetricTarget::default()
                    },
                }),
                ..MetricSpec::default()
            }]),
            behavior: None,
        }),
        status: None,
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
