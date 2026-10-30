use serde_json::json;

use super::*;

fn http_route() -> Value {
    json!({
        "metadata": {"name": "shop", "namespace": "shop", "labels": {LABEL: "default"}},
        "spec": {"rules": [{
            "filters": [{"type": "RequestHeaderModifier"}],
            "backendRefs": [
                {"name": "web", "port": 80, "weight": 90},
                {"name": "web-canary", "port": 80, "weight": 10},
                {"name": "other-ns", "namespace": "elsewhere", "port": 80},
                {"group": "example.com", "kind": "Bucket", "name": "b"}
            ]
        }]}
    })
}

fn all(_: &str) -> bool {
    true
}

fn names(route: &Value) -> Vec<String> {
    route
        .pointer("/spec/rules/0/backendRefs")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_owned())
        .collect()
}

// case 1
#[test]
fn weighted_backends_each_get_their_gateway() {
    let out = rewrite(
        Kind::HttpRoute,
        &http_route(),
        "shop",
        Some("default"),
        &all,
    );
    let web = gateway::name("web", "80", "default");
    let canary = gateway::name("web-canary", "80", "default");
    assert_eq!(
        names(&out),
        [web.as_str(), canary.as_str(), "other-ns", "b"]
    );
    let refs = out.pointer("/spec/rules/0/backendRefs").unwrap();
    assert_eq!(
        (refs[0]["weight"].clone(), refs[0]["port"].clone()),
        (json!(90), json!(80))
    );
    assert_eq!(
        out.pointer("/spec/rules/0/filters"),
        http_route().pointer("/spec/rules/0/filters")
    );
    let recorded: Value =
        serde_json::from_str(out["metadata"]["annotations"][BACKENDS].as_str().unwrap()).unwrap();
    assert_eq!(recorded, json!({web: "web", canary: "web-canary"}));
    assert_eq!(
        backends(Kind::HttpRoute, &out, "shop"),
        [
            Backend {
                service: "web".into(),
                port: "80".into()
            },
            Backend {
                service: "web-canary".into(),
                port: "80".into()
            }
        ]
    );
}

// case 2
#[test]
fn ingress_service_backends_rewritten_resource_kept() {
    let ing = json!({
        "metadata": {"name": "i"},
        "spec": {
            "defaultBackend": {"service": {"name": "web", "port": {"name": "http"}}},
            "rules": [{"http": {"paths": [
                {"path": "/", "backend": {"service": {"name": "api", "port": {"number": 8080}}}},
                {"path": "/s", "backend": {"resource": {"kind": "Bucket", "name": "s"}}}
            ]}}]
        }
    });
    let out = rewrite(Kind::Ingress, &ing, "shop", Some("p"), &all);
    assert_eq!(
        out.pointer("/spec/defaultBackend/service/name").unwrap(),
        &json!(gateway::name("web", "http", "p"))
    );
    assert_eq!(
        out.pointer("/spec/rules/0/http/paths/0/backend/service/name")
            .unwrap(),
        &json!(gateway::name("api", "8080", "p"))
    );
    assert_eq!(
        out.pointer("/spec/rules/0/http/paths/1"),
        ing.pointer("/spec/rules/0/http/paths/1")
    );
}

// case 3
#[test]
fn label_removed_restores_the_originals() {
    let original = http_route();
    let out = rewrite(Kind::HttpRoute, &original, "shop", Some("default"), &all);
    let back = rewrite(Kind::HttpRoute, &out, "shop", None, &all);
    let mut expected = original.clone();
    expected["metadata"]["labels"] = json!({LABEL: "default"});
    assert_eq!(back, expected);
}

// case 4
#[test]
fn rewriting_twice_changes_nothing() {
    let once = rewrite(
        Kind::HttpRoute,
        &http_route(),
        "shop",
        Some("default"),
        &all,
    );
    assert_eq!(
        rewrite(Kind::HttpRoute, &once, "shop", Some("default"), &all),
        once
    );
    // another policy moves the backends from one gateway to the other
    let other = rewrite(Kind::HttpRoute, &once, "shop", Some("strict"), &all);
    assert_eq!(names(&other)[0], gateway::name("web", "80", "strict"));
}

// case 5
#[test]
fn none_opts_a_route_out() {
    assert_eq!(policy(Some("none"), Some("default")), None);
    assert_eq!(policy(None, Some("default")), Some("default"));
    assert_eq!(policy(Some("strict"), Some("default")), Some("strict"));
    assert_eq!(policy(None, None), None);
}

#[test]
fn a_gateway_not_there_yet_keeps_the_original() {
    let web = gateway::name("web", "80", "default");
    let out = rewrite(
        Kind::HttpRoute,
        &http_route(),
        "shop",
        Some("default"),
        &|g| g == web,
    );
    assert_eq!(names(&out)[1], "web-canary");
    assert_eq!(names(&out)[0], web);
}

#[test]
fn odd_shapes_do_not_panic() {
    for v in [
        json!(null),
        json!([]),
        json!({"spec": 1}),
        json!({"spec": {"rules": [1, {"backendRefs": 2}]}}),
        json!({"metadata": 1, "spec": {"rules": [{"backendRefs": [{"name": 1, "port": "x"}]}]}}),
    ] {
        for k in [Kind::Ingress, Kind::HttpRoute] {
            let _ = rewrite(k, &v, "ns", Some("p"), &all);
            let _ = backends(k, &v, "ns");
        }
    }
}

fn split_route(rules: Option<&str>) -> Value {
    let mut r = json!({
        "metadata": {"name": "shop", "labels": {LABEL: "default"}},
        "spec": {"rules": [
            {"name": "api", "backendRefs": [{"name": "api", "port": 80}]},
            {"name": "assets", "backendRefs": [{"name": "assets", "port": 80}]}
        ]}
    });
    if let Some(v) = rules {
        r["metadata"]["annotations"] = json!({RULES: v});
    }
    r
}

fn rule_backend(route: &Value, i: usize) -> &str {
    route["spec"]["rules"][i]["backendRefs"][0]["name"]
        .as_str()
        .unwrap()
}

// RFC 0025 cases 11 and 12
#[test]
fn rules_annotation_picks_rules() {
    let api = gateway::name("api", "80", "default");
    let assets = gateway::name("assets", "80", "default");
    let partial = rewrite(
        Kind::HttpRoute,
        &split_route(Some("api")),
        "shop",
        Some("default"),
        &all,
    );
    assert_eq!(
        (rule_backend(&partial, 0), rule_backend(&partial, 1)),
        (api.as_str(), "assets")
    );
    assert_eq!(
        backends(Kind::HttpRoute, &partial, "shop"),
        [Backend {
            service: "api".into(),
            port: "80".into()
        }]
    );
    // annotation removed: the whole route opts in
    let mut whole = partial.clone();
    whole["metadata"]["annotations"]
        .as_object_mut()
        .unwrap()
        .remove(RULES);
    let whole = rewrite(Kind::HttpRoute, &whole, "shop", Some("default"), &all);
    assert_eq!(
        (rule_backend(&whole, 0), rule_backend(&whole, 1)),
        (api.as_str(), assets.as_str())
    );
    // listed again: the unlisted rule is restored
    let mut again = whole.clone();
    again["metadata"]["annotations"][RULES] = json!("api");
    let again = rewrite(Kind::HttpRoute, &again, "shop", Some("default"), &all);
    assert_eq!(rule_backend(&again, 1), "assets");
}

// RFC 0025 case 13
#[test]
fn rules_annotation_picks_ingress_paths() {
    let ing = json!({
        "metadata": {"name": "i", "annotations": {RULES: "/api/"}},
        "spec": {
            "defaultBackend": {"service": {"name": "web", "port": {"number": 80}}},
            "rules": [{"http": {"paths": [
                {"path": "/api/", "backend": {"service": {"name": "api", "port": {"number": 80}}}},
                {"path": "/", "backend": {"service": {"name": "web", "port": {"number": 80}}}}
            ]}}]
        }
    });
    let out = rewrite(Kind::Ingress, &ing, "shop", Some("p"), &all);
    let paths = out.pointer("/spec/rules/0/http/paths").unwrap();
    assert_eq!(
        paths[0]["backend"]["service"]["name"],
        json!(gateway::name("api", "80", "p"))
    );
    assert_eq!(paths[1]["backend"]["service"]["name"], json!("web"));
    assert_eq!(
        out.pointer("/spec/defaultBackend/service/name").unwrap(),
        &json!("web")
    );
}

// RFC 0025 case 14
#[test]
fn unknown_rules_change_nothing_and_are_named() {
    let r = split_route(Some("missing, api"));
    assert_eq!(unknown_rules(Kind::HttpRoute, &r), ["missing"]);
    let only = split_route(Some("missing"));
    let out = rewrite(Kind::HttpRoute, &only, "shop", Some("default"), &all);
    assert_eq!(
        (rule_backend(&out, 0), rule_backend(&out, 1)),
        ("api", "assets")
    );
    assert!(unknown_rules(Kind::HttpRoute, &split_route(None)).is_empty());
    // capped: at most 64 entries of at most 253 bytes
    let long = vec!["x"; 100].join(",") + "," + &"y".repeat(300);
    assert_eq!(
        unknown_rules(Kind::HttpRoute, &split_route(Some(&long))).len(),
        64
    );
}
