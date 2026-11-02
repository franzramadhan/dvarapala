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
            // RFC 0025: a route that opts in some rules only
            let some_rules = req
                .object
                .as_ref()
                .is_some_and(|o| o.annotations().contains_key(routes::RULES));
            match result {
                Ok(r) => {
                    let outcome = match (r.patch.is_some(), some_rules) {
                        (false, _) => "unchanged",
                        (true, false) => "rewritten",
                        (true, true) => "partial",
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

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::fake::Fake;

    const NS: &str = "/api/v1/namespaces/shop";
    const POLICY: &str =
        "/apis/dvarapala.franzramadhan.dev/v1alpha1/namespaces/shop/dvarapalapolicies/default";

    fn cluster() -> Fake {
        let fake = Fake::default();
        fake.put(
            NS,
            json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "shop"}}),
        );
        fake.put(
            &format!("{NS}/services/web"),
            json!({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "web", "namespace": "shop"},
                "spec": {"selector": {"app": "web"}, "ports": [{"name": "http", "port": 80}]}}),
        );
        fake.put(
            POLICY,
            json!({"apiVersion": "dvarapala.franzramadhan.dev/v1alpha1",
                "kind": "DvarapalaPolicy",
                "metadata": {"name": "default", "namespace": "shop"}, "spec": {}}),
        );
        fake
    }

    fn ingress(label: Option<&str>, backend: &str) -> Value {
        let mut labels = serde_json::Map::new();
        if let Some(l) = label {
            labels.insert(LABEL.into(), l.into());
        }
        json!({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "shop", "namespace": "shop", "labels": labels},
            "spec": {"rules": [{"http": {"paths": [{"path": "/", "pathType": "Prefix",
                "backend": {"service": {"name": backend, "port": {"number": 80}}}}]}}]}})
    }

    fn body(kind: &str, object: &Value, dry_run: bool) -> Vec<u8> {
        json!({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
            "request": {"uid": "u1",
                "kind": {"group": "networking.k8s.io", "version": "v1", "kind": kind},
                "resource": {"group": "networking.k8s.io", "version": "v1", "resource": "ingresses"},
                "name": "shop", "namespace": "shop", "operation": "CREATE",
                "userInfo": {}, "object": object, "dryRun": dry_run}})
        .to_string()
        .into_bytes()
    }

    async fn answer(fake: &Fake, body: &[u8]) -> Value {
        let out = review(&fake.client(), body).await;
        serde_json::from_slice::<Value>(&out).unwrap()["response"].clone()
    }

    fn gateway_path() -> String {
        format!("{NS}/services/{}", gateway::name("web", "80", "default"))
    }

    #[tokio::test]
    async fn labeled_route_gets_its_gateway() {
        let fake = cluster();
        let route = ingress(Some("default"), "web");
        let r = answer(&fake, &body("Ingress", &route, false)).await;
        assert_eq!(r["uid"], "u1");
        assert_eq!(r["allowed"], true);
        assert_eq!(r["patchType"], "JSONPatch");
        assert!(fake.get(&gateway_path()).is_some());
        assert_eq!(fake.writes(), [format!("PATCH {}", gateway_path())]);
        // the gateway is there now: rewritten again, nothing created
        let r = answer(&fake, &body("Ingress", &route, false)).await;
        assert_eq!(r["patchType"], "JSONPatch");
        assert_eq!(fake.writes().len(), 1);
    }

    #[tokio::test]
    async fn dry_run_creates_nothing() {
        let fake = cluster();
        let r = answer(
            &fake,
            &body("Ingress", &ingress(Some("default"), "web"), true),
        )
        .await;
        assert_eq!(r["allowed"], true);
        assert_eq!(r["patchType"], "JSONPatch");
        assert!(fake.writes().is_empty());
    }

    #[tokio::test]
    async fn routes_left_alone() {
        // no label, a missing policy, a missing backend, a kind not handled
        let fake = cluster();
        for b in [
            body("Ingress", &ingress(None, "web"), false),
            body("Ingress", &ingress(Some("other"), "web"), false),
            body("Ingress", &ingress(Some("default"), "gone"), false),
            body("Service", &ingress(Some("default"), "web"), false),
        ] {
            let r = answer(&fake, &b).await;
            assert_eq!(r["allowed"], true, "{r}");
            assert!(r.get("patch").is_none(), "{r}");
        }
        assert!(fake.writes().is_empty());
    }

    #[tokio::test]
    async fn refuses_when_a_lookup_fails() {
        let route = ingress(Some("default"), "web");
        let services = format!("{NS}/services");
        let gw = gateway_path();
        for (method, path) in [
            (http::Method::GET, NS),
            (http::Method::GET, services.as_str()),
            (http::Method::GET, POLICY),
            (http::Method::PATCH, gw.as_str()),
        ] {
            let fake = cluster();
            fake.fail(method, path, 500);
            let r = answer(&fake, &body("Ingress", &route, false)).await;
            assert_eq!(r["allowed"], false, "{path}");
            assert!(
                r["status"]["message"]
                    .as_str()
                    .is_some_and(|m| !m.is_empty())
            );
        }
    }

    #[tokio::test]
    async fn malformed_review_is_refused() {
        let fake = cluster();
        let r = answer(&fake, b"{").await;
        assert_eq!(r["allowed"], false);
        let no_request = br#"{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview"}"#;
        let r = answer(&fake, no_request).await;
        assert_eq!(r["allowed"], false);
    }
}
