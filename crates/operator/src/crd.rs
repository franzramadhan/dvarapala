//! The `DvarapalaPolicy` custom resource.

use k8s_openapi::api::core::v1::ResourceRequirements;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The protection config, as TOML with the keys of `CONFIG.md`, and the
/// shape of the gateways that run it.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[kube(
    group = "dvarapala.franzramadhan.dev",
    version = "v1alpha1",
    kind = "DvarapalaPolicy",
    namespaced,
    status = "PolicyStatus",
    shortname = "dvp",
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Gateways","type":"integer","jsonPath":".status.gatewayCount"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct PolicySpec {
    /// dvarapala config as TOML. The operator owns `mode`, `listen`,
    /// `upstream`, `upstream_protocol`, `[pool]`, `config_watch`,
    /// `metrics.listen`, `[admin]`, `[xdp]`, `[quic]` and `[tls]`.
    #[serde(default)]
    pub config: String,
    /// A Secret whose keys become the gateway's environment, for example
    /// `DVARAPALA__STORE__URL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<SecretRef>,
    #[serde(default)]
    pub gateway: GatewaySpec,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub struct SecretRef {
    pub name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// Replicas per gateway, 2 when unset; the minimum with `autoscaling`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<Autoscaling>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
}

/// An HPA on CPU per gateway.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Autoscaling {
    pub max_replicas: i32,
    /// Average CPU utilization in percent of the request, 70 when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cpu: Option<i32>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyStatus {
    pub ready: bool,
    /// Why the policy is not ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(default)]
    pub gateway_count: i32,
    #[serde(default)]
    pub gateways: Vec<GatewayStatus>,
    /// Routes that use this policy.
    #[serde(default)]
    pub routes: i32,
    /// Backends left as they are, with the reason.
    #[serde(default)]
    pub skipped_backends: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayStatus {
    /// The gateway's Service, the name routes point at.
    pub service: String,
    /// The backend Service it protects.
    pub backend: String,
    pub port: i32,
    /// `Passthrough` until the first gateway pod is ready, then `Protecting`.
    pub phase: String,
    pub ready_replicas: i32,
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt;

    use super::*;

    #[test]
    fn deploy_manifest_has_this_crd() {
        let manifest = include_str!("../../../deploy/operator.yaml");
        let doc = manifest
            .split("\n---\n")
            .find(|d| d.starts_with('{'))
            .expect("the CRD document, as JSON");
        let on_disk: serde_json::Value = serde_json::from_str(doc).unwrap();
        let built = serde_json::to_value(DvarapalaPolicy::crd()).unwrap();
        assert_eq!(
            on_disk, built,
            "regenerate it with `dvarapala-operator crd`"
        );
    }
}
