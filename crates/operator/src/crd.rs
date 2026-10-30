//! The `DvarapalaPolicy` custom resource.

use std::collections::BTreeMap;

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
    /// `metrics.listen`, `admin.listen`, `[xdp]`, `[quic]` and `[tls]`,
    /// and `waf.endpoint` with `gateway.waf`.
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
    /// RFC 0025: the admin listener and console, one Service per gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<Admin>,
    /// RFC 0025: `coraza-spoa` as a sidecar over a Unix socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waf: Option<Waf>,
    /// RFC 0025: ConfigMaps and Secrets of this namespace, read-only at
    /// `/etc/dvarapala-mounts/<name>/`. At most 16.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,
    /// Added to the gateway pods; the operator's own keys are refused.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_annotations: BTreeMap<String, String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
pub struct Admin {
    /// `admin.listen` on port 9091; needs a `secretRef` with the token.
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Waf {
    /// Must start with a prefix of the operator's `--waf-images`; pin it
    /// by digest.
    pub image: String,
    /// The agent's config under the key `config.yaml`; it binds
    /// `unix:///run/waf/waf.sock`.
    pub config_map: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
}

/// One of `configMap` or `secret`.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Mount {
    /// A DNS label, unique in the list: the directory name.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
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
    /// Accepted but probably not meant: an idle WAF sidecar, an image
    /// without a digest, a `rules` entry a route does not have.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
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
    /// The admin Service with `gateway.admin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_service: Option<String>,
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
