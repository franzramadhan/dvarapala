use http::Method;
use serde_json::{Value, json};

use super::*;
use crate::fake::Fake;

const CORE: &str = "/api/v1/namespaces/shop";
const APPS: &str = "/apis/apps/v1/namespaces/shop/deployments";
const PDBS: &str = "/apis/policy/v1/namespaces/shop/poddisruptionbudgets";
const HPAS: &str = "/apis/autoscaling/v2/namespaces/shop/horizontalpodautoscalers";
const INGRESSES: &str = "/apis/networking.k8s.io/v1/namespaces/shop/ingresses";
const POLICIES: &str =
    "/apis/dvarapala.franzramadhan.dev/v1alpha1/namespaces/shop/dvarapalapolicies";

fn ctx(fake: &Fake) -> Arc<Ctx> {
    Arc::new(Ctx {
        client: fake.client(),
        image: "dvarapala:test".into(),
        kinds: vec![(Kind::Ingress, ApiResource::erase::<Ingress>(&()))],
        waf_images: vec!["ghcr.io/corazawaf/coraza-spoa".into()],
        mount_images: Vec::new(),
    })
}

fn namespace(label: Option<&str>) -> Arc<Namespace> {
    let mut labels = BTreeMap::new();
    if let Some(l) = label {
        labels.insert(LABEL.to_owned(), l.to_owned());
    }
    Arc::new(Namespace {
        metadata: ObjectMeta {
            name: Some("shop".into()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    })
}

fn put_policy(fake: &Fake, name: &str, spec: Value) {
    fake.put(
        &format!("{POLICIES}/{name}"),
        json!({"apiVersion": "dvarapala.franzramadhan.dev/v1alpha1", "kind": "DvarapalaPolicy",
            "metadata": {"name": name, "namespace": "shop"}, "spec": spec}),
    );
}

fn put_ingress(fake: &Fake, labels: Value, annotations: Value, backend: &str) {
    fake.put(
        &format!("{INGRESSES}/shop"),
        json!({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": "shop", "namespace": "shop",
                "labels": labels, "annotations": annotations},
            "spec": {"rules": [{"http": {"paths": [{"path": "/", "pathType": "Prefix",
                "backend": {"service": {"name": backend, "port": {"number": 80}}}}]}}]}}),
    );
}

/// A namespace with policy `default`, Service `web` and an Ingress to it
/// labeled with the policy.
fn shop(spec: Value) -> Fake {
    let fake = Fake::default();
    put_policy(&fake, "default", spec);
    fake.put(
        &format!("{CORE}/services/web"),
        json!({"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "web", "namespace": "shop"},
            "spec": {"selector": {"app": "web"}, "ports": [{"name": "http", "port": 80}]}}),
    );
    put_ingress(&fake, json!({LABEL: "default"}), json!({}), "web");
    fake
}

fn gw() -> String {
    gateway::name("web", "80", "default")
}

fn policy_status(fake: &Fake) -> Value {
    fake.get(&format!("{POLICIES}/default")).unwrap()["status"].clone()
}

#[tokio::test]
async fn nothing_to_do_without_policies_or_gateways() {
    let fake = Fake::default();
    let a = reconcile(namespace(None), ctx(&fake)).await.unwrap();
    assert_eq!(a, Action::await_change());
    assert!(fake.writes().is_empty());
}

#[tokio::test]
async fn labeled_route_gets_a_gateway_in_passthrough() {
    let fake = shop(json!({"config": "[rate_limit]\nrate = 10\n"}));
    let a = reconcile(namespace(None), ctx(&fake)).await.unwrap();
    // passthrough: look again soon for ready pods
    assert_eq!(a, Action::requeue(Duration::from_secs(3)));
    let g = gw();
    let cm = fake
        .get(&format!(
            "{CORE}/configmaps/{}",
            policy::config_map_name("default")
        ))
        .unwrap();
    assert!(
        cm["data"][policy::FILE]
            .as_str()
            .unwrap()
            .contains("rate = 10")
    );
    assert!(fake.get(&format!("{APPS}/{g}")).is_some());
    assert!(fake.get(&format!("{PDBS}/{g}")).is_some());
    let svc = fake.get(&format!("{CORE}/services/{g}")).unwrap();
    assert_eq!(svc["metadata"]["annotations"][PHASE], "passthrough");
    let route = fake.get(&format!("{INGRESSES}/shop")).unwrap();
    assert_eq!(
        route["spec"]["rules"][0]["http"]["paths"][0]["backend"]["service"]["name"],
        g.as_str()
    );
    let s = policy_status(&fake);
    assert_eq!(s["ready"], true);
    assert_eq!(s["routes"], 1);
    assert_eq!(s["gatewayCount"], 1);
    assert_eq!(s["gateways"][0]["phase"], "Passthrough");

    // a second pass changes nothing it already wrote: no route patch, no status
    let before = fake.writes().len();
    reconcile(namespace(None), ctx(&fake)).await.unwrap();
    let again: Vec<String> = fake.writes()[before..].to_vec();
    assert!(!again.iter().any(|w| w.ends_with("/status")), "{again:?}");
    assert!(
        !again.iter().any(|w| w.contains("/ingresses/")),
        "{again:?}"
    );
}

#[tokio::test]
async fn ready_pods_switch_the_gateway_to_protecting() {
    let fake = shop(json!({}));
    let g = gw();
    fake.put(
        &format!("{APPS}/{g}"),
        json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": g, "namespace": "shop"}, "status": {"readyReplicas": 2}}),
    );
    let a = reconcile(namespace(None), ctx(&fake)).await.unwrap();
    assert_eq!(a, Action::requeue(Duration::from_secs(300)));
    let svc = fake.get(&format!("{CORE}/services/{g}")).unwrap();
    assert_eq!(svc["metadata"]["annotations"][PHASE], "protecting");
    let s = policy_status(&fake);
    assert_eq!(s["gateways"][0]["phase"], "Protecting");
    assert_eq!(s["gateways"][0]["readyReplicas"], 2);
}

#[tokio::test]
async fn admin_and_autoscaling_add_their_objects() {
    let fake = shop(json!({"secretRef": {"name": "tokens"},
        "gateway": {"admin": {"enabled": true}, "autoscaling": {"maxReplicas": 5}}}));
    reconcile(namespace(None), ctx(&fake)).await.unwrap();
    let g = gw();
    assert!(fake.get(&format!("{HPAS}/{g}")).is_some());
    let s = policy_status(&fake);
    let admin = s["gateways"][0]["adminService"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(fake.get(&format!("{CORE}/services/{admin}")).is_some());
}

#[tokio::test]
async fn namespace_label_covers_unlabeled_routes() {
    let fake = shop(json!({}));
    put_ingress(
        &fake,
        json!({}),
        json!({(routes::RULES): "/, /nope"}),
        "web",
    );
    reconcile(namespace(Some("default")), ctx(&fake))
        .await
        .unwrap();
    let s = policy_status(&fake);
    assert_eq!(s["routes"], 1);
    assert_eq!(s["warnings"], json!(["Ingress shop: no rule /nope"]));
}

#[tokio::test]
async fn invalid_policy_and_missing_backend_are_reported() {
    let fake = shop(json!({"config": "listen = \"0.0.0.0:1\"\n"}));
    reconcile(namespace(None), ctx(&fake)).await.unwrap();
    let s = policy_status(&fake);
    assert_eq!(s["ready"], false);
    assert!(s["message"].as_str().unwrap().contains("listen"));
    assert!(fake.get(&format!("{APPS}/{}", gw())).is_none());

    let fake = shop(json!({}));
    put_ingress(&fake, json!({LABEL: "default"}), json!({}), "gone");
    reconcile(namespace(None), ctx(&fake)).await.unwrap();
    let s = policy_status(&fake);
    assert_eq!(s["skippedBackends"], json!(["gone:80: no such Service"]));
    assert_eq!(s["gatewayCount"], 0);
}

#[tokio::test]
async fn unused_gateways_and_config_maps_are_removed() {
    let fake = Fake::default();
    let managed = json!({(MANAGED_BY.0): MANAGED_BY.1});
    let old = "2020-01-01T00:00:00Z";
    for (name, extra) in [
        ("stale-dvp-1", json!({})),
        ("stale-dvp-1-admin", json!({ADMIN_OF: "stale-dvp-1"})),
    ] {
        let mut labels = managed.clone();
        json_patch::merge(&mut labels, &extra);
        fake.put(
            &format!("{CORE}/services/{name}"),
            json!({"apiVersion": "v1", "kind": "Service",
                "metadata": {"name": name, "labels": labels, "creationTimestamp": old}}),
        );
    }
    // the webhook just created this one: its route is not stored yet
    fake.put(
        &format!("{CORE}/services/young-dvp-2"),
        json!({"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": "young-dvp-2", "labels": managed}}),
    );
    fake.put(
        &format!("{APPS}/stale-dvp-1"),
        json!({"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "stale-dvp-1", "labels": managed}}),
    );
    let mut cm_labels = managed.clone();
    json_patch::merge(&mut cm_labels, &json!({POLICY: "removed"}));
    fake.put(
        &format!("{CORE}/configmaps/dvarapala-removed"),
        json!({"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "dvarapala-removed", "labels": cm_labels}}),
    );
    reconcile(namespace(None), ctx(&fake)).await.unwrap();
    assert!(fake.get(&format!("{CORE}/services/stale-dvp-1")).is_none());
    assert!(
        fake.get(&format!("{CORE}/services/stale-dvp-1-admin"))
            .is_none()
    );
    assert!(fake.get(&format!("{APPS}/stale-dvp-1")).is_none());
    assert!(fake.get(&format!("{CORE}/services/young-dvp-2")).is_some());
    assert!(
        fake.get(&format!("{CORE}/configmaps/dvarapala-removed"))
            .is_none()
    );
}

#[tokio::test]
async fn api_errors_fail_the_reconcile() {
    let g = gw();
    let deployments = format!("{APPS}/{g}");
    let hpa = format!("{HPAS}/{g}");
    let status = format!("{POLICIES}/default/status");
    for (method, path) in [
        (Method::GET, POLICIES),
        (Method::GET, INGRESSES),
        (Method::PATCH, deployments.as_str()),
        (Method::DELETE, hpa.as_str()),
        (Method::PATCH, status.as_str()),
    ] {
        let fake = shop(json!({}));
        fake.fail(method.clone(), path, 500);
        let e = reconcile(namespace(None), ctx(&fake)).await.unwrap_err();
        assert!(!e.to_string().is_empty(), "{method} {path}");
    }
}
