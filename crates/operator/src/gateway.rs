//! A gateway: the Deployment, Service, PodDisruptionBudget and HPA that
//! put dvarapala in front of one backend Service port for one policy.
#![allow(unused_variables, unused_imports, dead_code)]

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
    todo!("rfc 0019")
}

/// The gateway for `port` (a number or a port name) of `backend`, or why
/// that backend is left as it is.
pub fn plan(backend: &Service, port: &str, policy: &str, grpc: bool) -> Result<Gateway, String> {
    todo!("rfc 0019")
}

fn labels(g: &Gateway) -> BTreeMap<String, String> {
    todo!("rfc 0019")
}

fn selector(g: &Gateway) -> BTreeMap<String, String> {
    todo!("rfc 0019")
}

fn meta(g: &Gateway) -> ObjectMeta {
    todo!("rfc 0019")
}

/// The Service routes point at: first the backend's pods (`protecting`
/// false), then the gateway's.
pub fn service(g: &Gateway, backend: &Service, protecting: bool) -> Service {
    todo!("rfc 0019")
}

fn env(name: &str, value: String) -> EnvVar {
    todo!("rfc 0019")
}

fn quantities(pairs: &[(&str, &str)]) -> Option<BTreeMap<String, Quantity>> {
    todo!("rfc 0019")
}

pub fn deployment(g: &Gateway, p: &PolicySpec, image: &str, restart_hash: &str) -> Deployment {
    todo!("rfc 0019")
}

fn replicas(p: &PolicySpec) -> i32 {
    todo!("rfc 0019")
}

pub fn pdb(g: &Gateway) -> PodDisruptionBudget {
    todo!("rfc 0019")
}

pub fn hpa(g: &Gateway, p: &PolicySpec, a: &Autoscaling) -> HorizontalPodAutoscaler {
    todo!("rfc 0019")
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
