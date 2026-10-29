//! The mutating webhook: a labeled route's backends point at their
//! gateways, or back at the originals when the label is gone. A gateway
//! Service that does not exist yet is created here in passthrough, so the
//! rewrite is part of the user's own request and their field manager keeps
//! owning the backends (a later server-side apply of their manifest does
//! not conflict). Nothing is created on a dry run.

use std::collections::HashSet;

use k8s_openapi::api::core::v1::{Namespace, Service};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::core::DynamicObject;
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview};
use kube::{Client, ResourceExt};

use crate::controller::MANAGER;
use crate::crd::DvarapalaPolicy;
use crate::gateway::{self, MANAGED_BY};
use crate::routes::{self, Kind, LABEL};

/// The `AdmissionReview` answer to `body`. Refuses when a lookup fails,
/// so a labeled route is never stored without its rewrite.
pub async fn review(client: &Client, body: &[u8]) -> Vec<u8> {
    let resp = match serde_json::from_slice::<AdmissionReview<DynamicObject>>(body)
        .map_err(|e| e.to_string())
        .and_then(|r| TryInto::<AdmissionRequest<_>>::try_into(r).map_err(|e| e.to_string()))
    {
        Err(e) => AdmissionResponse::invalid(e),
        Ok(req) => {
            let base = AdmissionResponse::from(&req);
            let result = match mutate(client, &req).await {
                Ok(Some(patch)) => base.with_patch(patch).map_err(|e| e.to_string()),
                Ok(None) => Ok(base),
                Err(e) => Err(e),
            };
            let kind = req.kind.kind.clone();
            match result {
                Ok(r) => {
                    let outcome = if r.patch.is_some() {
                        "rewritten"
                    } else {
                        "unchanged"
                    };
                    ::metrics::counter!("dvarapala_operator_admissions_total", "kind" => kind, "result" => outcome).increment(1);
                    r
                }
                Err(e) => {
                    tracing::warn!(msg = "admission refused", error = %e);
                    ::metrics::counter!("dvarapala_operator_admissions_total", "kind" => kind, "result" => "refused").increment(1);
                    AdmissionResponse::from(&req).deny(e)
                }
            }
        }
    };
    serde_json::to_vec(&resp.into_review()).unwrap_or_default()
}

async fn mutate(
    client: &Client,
    req: &AdmissionRequest<DynamicObject>,
) -> Result<Option<json_patch::Patch>, String> {
    let (Some(obj), Some(kind)) = (&req.object, Kind::from_kind(&req.kind.kind)) else {
        return Ok(None);
    };
    let ns = req.namespace.clone().unwrap_or_default();
    let labels = Api::<Namespace>::all(client.clone())
        .get(&ns)
        .await
        .map_err(|e| format!("namespace {ns}: {e}"))?
        .labels()
        .clone();
    let policy = routes::policy(
        obj.labels().get(LABEL).map(String::as_str),
        labels.get(LABEL).map(String::as_str),
    );
    let services = Api::<Service>::namespaced(client.clone(), &ns);
    let lp = ListParams::default().labels(&format!("{}={}", MANAGED_BY.0, MANAGED_BY.1));
    let mut gateways: HashSet<String> = services
        .list(&lp)
        .await
        .map_err(|e| format!("gateway services in {ns}: {e}"))?
        .items
        .iter()
        .map(ResourceExt::name_any)
        .collect();
    let route = serde_json::to_value(obj).map_err(|e| e.to_string())?;
    if let Some(p) = policy {
        let policies = Api::<DvarapalaPolicy>::namespaced(client.clone(), &ns);
        if policies
            .get_opt(p)
            .await
            .map_err(|e| format!("policy {ns}/{p}: {e}"))?
            .is_some()
        {
            for b in routes::backends(kind, &route, &ns) {
                let name = gateway::name(&b.service, &b.port, p);
                if gateways.contains(&name) {
                    continue;
                }
                let Some(backend) = services
                    .get_opt(&b.service)
                    .await
                    .map_err(|e| e.to_string())?
                else {
                    continue;
                };
                // the controller reports a backend it cannot protect
                let Ok(g) = gateway::plan(&backend, &b.port, p, kind == Kind::GrpcRoute) else {
                    continue;
                };
                if !req.dry_run {
                    let svc = gateway::service(&g, &backend, false);
                    services
                        .patch(
                            &name,
                            &PatchParams::apply(MANAGER).force(),
                            &Patch::Apply(&svc),
                        )
                        .await
                        .map_err(|e| format!("gateway service {ns}/{name}: {e}"))?;
                }
                gateways.insert(name);
            }
        }
    }
    let out = routes::rewrite(kind, &route, &ns, policy, &|g| gateways.contains(g));
    let patch = json_patch::diff(&route, &out);
    Ok((!patch.0.is_empty()).then_some(patch))
}
