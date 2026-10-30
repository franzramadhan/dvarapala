//! RFC 0025: the WAF agent as a sidecar. It binds a Unix socket in an
//! `emptyDir` the proxy shares; both run as the images' user, the socket's
//! owner.
#![allow(unused_variables, unused_imports, dead_code)]

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
    todo!("rfc 0025")
}

fn empty_dir(name: &str, memory: bool, size: &str) -> Volume {
    todo!("rfc 0025")
}

/// The `waf` container, locked down as `locked` plus the images' user.
pub fn container(w: &Waf, locked: &SecurityContext) -> Container {
    todo!("rfc 0025")
}

/// The proxy's mounts: the socket, and the agent's config for the console.
pub fn proxy_mounts() -> Vec<VolumeMount> {
    todo!("rfc 0025")
}

pub fn volumes(w: &Waf) -> Vec<Volume> {
    todo!("rfc 0025")
}
