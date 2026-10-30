//! RFC 0025: the WAF agent as a sidecar. It binds a Unix socket in an
//! `emptyDir` the proxy shares; both run as the images' user, the socket's
//! owner.

use k8s_openapi::api::core::v1::{
    ConfigMapVolumeSource, Container, EmptyDirVolumeSource, ResourceRequirements, SecurityContext,
    Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

use super::quantities;
use crate::crd::Waf;

/// What the proxy dials; the agent's config binds `unix:///run/waf/waf.sock`.
pub const ENDPOINT: &str = "unix:/run/waf/waf.sock";
/// The agent's ConfigMap in the proxy, for `waf.rules_files`.
pub const RULES: &str = "/etc/dvarapala-waf";
const SOCKET: &str = "/run/waf";
const CONFIG: &str = "/etc/coraza-spoa";
/// The user of both images (`USER 10001` in ours).
const UID: i64 = 10001;

fn mount(name: &str, path: &str, read_only: bool) -> VolumeMount {
    VolumeMount {
        name: name.into(),
        mount_path: path.into(),
        read_only: read_only.then_some(true),
        ..VolumeMount::default()
    }
}

fn empty_dir(name: &str, memory: bool, size: &str) -> Volume {
    Volume {
        name: name.into(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: memory.then(|| "Memory".into()),
            size_limit: Some(Quantity(size.into())),
        }),
        ..Volume::default()
    }
}

/// The `waf` container, locked down as `locked` plus the images' user.
pub fn container(w: &Waf, locked: &SecurityContext) -> Container {
    Container {
        name: "waf".into(),
        image: Some(w.image.clone()),
        // the image has no entrypoint
        command: Some(vec![
            "/coraza-spoa".into(),
            "-config".into(),
            format!("{CONFIG}/config.yaml"),
            "-autoreload".into(),
        ]),
        // ponytail: unmeasured defaults (RFC 0025), from examples/waf/
        resources: Some(w.resources.clone().unwrap_or(ResourceRequirements {
            requests: quantities(&[("cpu", "100m"), ("memory", "96Mi")]),
            limits: quantities(&[("memory", "256Mi")]),
            ..ResourceRequirements::default()
        })),
        security_context: Some(SecurityContext {
            run_as_user: Some(UID),
            run_as_group: Some(UID),
            ..locked.clone()
        }),
        volume_mounts: Some(vec![
            mount("waf-config", CONFIG, true),
            mount("waf-socket", SOCKET, false),
            // request bodies over the in-memory limit spill here
            mount("waf-tmp", "/tmp", false),
        ]),
        ..Container::default()
    }
}

/// The proxy's mounts: the socket, and the agent's config for the console.
pub fn proxy_mounts() -> Vec<VolumeMount> {
    vec![
        mount("waf-socket", SOCKET, false),
        mount("waf-config", RULES, true),
    ]
}

pub fn volumes(w: &Waf) -> Vec<Volume> {
    vec![
        Volume {
            name: "waf-config".into(),
            config_map: Some(ConfigMapVolumeSource {
                name: w.config_map.clone(),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        },
        empty_dir("waf-socket", true, "1Mi"),
        empty_dir("waf-tmp", false, "64Mi"),
    ]
}
