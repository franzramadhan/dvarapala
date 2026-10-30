use super::*;

fn web(app_protocol: Option<&str>) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some("web".into()),
            namespace: Some("shop".into()),
            ..ObjectMeta::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(BTreeMap::from([("app".into(), "web".into())])),
            ports: Some(vec![ServicePort {
                name: Some("http".into()),
                port: 80,
                target_port: Some(IntOrString::String("web".into())),
                app_protocol: app_protocol.map(Into::into),
                ..ServicePort::default()
            }]),
            ..ServiceSpec::default()
        }),
        status: None,
    }
}

fn env_of(d: &Deployment, k: &str) -> String {
    let c = &d
        .spec
        .as_ref()
        .unwrap()
        .template
        .spec
        .as_ref()
        .unwrap()
        .containers[0];
    c.env
        .iter()
        .flatten()
        .find(|e| e.name == k)
        .unwrap()
        .value
        .clone()
        .unwrap()
}

#[test]
fn names_are_stable_short_and_distinct() {
    assert_eq!(name("web", "80", "default"), name("web", "80", "default"));
    assert_ne!(name("web", "80", "default"), name("web", "80", "strict"));
    let long = "a".repeat(49) + "-" + &"b".repeat(13);
    let n = name(&long, "80", "default");
    assert!(n.len() <= 63, "{n}");
    assert!(!n.contains("--"), "{n}");
    assert_ne!(
        n,
        name(&("a".repeat(49) + "-" + &"c".repeat(13)), "80", "default")
    );
}

// case 7
#[test]
fn h2c_backend_gets_an_http2_gateway() {
    let g = plan(&web(Some("kubernetes.io/h2c")), "80", "default", false).unwrap();
    assert_eq!(g.port, 80);
    let d = deployment(&g, &PolicySpec::default(), "img:1", "abc");
    assert_eq!(env_of(&d, "DVARAPALA__UPSTREAM"), "http://web.shop.svc:80");
    assert_eq!(env_of(&d, "DVARAPALA__UPSTREAM_PROTOCOL"), "http2");
    let spec = d.spec.unwrap();
    assert_eq!(spec.replicas, Some(2));
    let pod = spec.template.spec.unwrap();
    let sc = pod.containers[0].security_context.clone().unwrap();
    assert_eq!(sc.run_as_non_root, Some(true));
    assert_eq!(sc.read_only_root_filesystem, Some(true));
    assert_eq!(sc.allow_privilege_escalation, Some(false));
    assert_eq!(sc.capabilities.unwrap().drop, Some(vec!["ALL".into()]));
    let by_name = plan(&web(None), "http", "default", true).unwrap();
    assert!(by_name.http2, "a GRPCRoute backend speaks h2c");
    assert_eq!(
        pdb(&g).spec.unwrap().max_unavailable,
        Some(IntOrString::Int(1))
    );
}

// case 8
#[test]
fn passthrough_then_protecting() {
    let b = web(None);
    let g = plan(&b, "80", "default", false).unwrap();
    let pass = service(&g, &b, false).spec.unwrap();
    assert_eq!(pass.selector, b.spec.clone().unwrap().selector);
    let port = &pass.ports.unwrap()[0];
    assert_eq!(
        (port.port, port.target_port.clone()),
        (80, Some(IntOrString::String("web".into())))
    );
    assert_eq!(port.name.as_deref(), Some("http"));
    let prot = service(&g, &b, true).spec.unwrap();
    assert_eq!(
        prot.selector,
        Some(BTreeMap::from([(GATEWAY.into(), g.name.clone())]))
    );
    assert_eq!(
        prot.ports.unwrap()[0].target_port,
        Some(IntOrString::Int(8080))
    );
}

// case 6
#[test]
fn unsupported_backends_have_a_reason() {
    let mut ext = web(None);
    ext.spec.as_mut().unwrap().type_ = Some("ExternalName".into());
    assert!(
        plan(&ext, "80", "p", false)
            .unwrap_err()
            .contains("ExternalName")
    );
    let mut bare = web(None);
    bare.spec.as_mut().unwrap().selector = None;
    assert!(
        plan(&bare, "80", "p", false)
            .unwrap_err()
            .contains("selector")
    );
    assert!(
        plan(&web(None), "81", "p", false)
            .unwrap_err()
            .contains("no such port")
    );
    assert!(
        plan(&web(Some("https")), "80", "p", false)
            .unwrap_err()
            .contains("https")
    );
}

#[test]
fn autoscaling_leaves_replicas_to_the_hpa() {
    let g = plan(&web(None), "80", "p", false).unwrap();
    let mut p = PolicySpec::default();
    let a = Autoscaling {
        max_replicas: 10,
        target_cpu: None,
    };
    p.gateway.autoscaling = Some(a.clone());
    p.gateway.replicas = Some(3);
    assert_eq!(deployment(&g, &p, "i", "h").spec.unwrap().replicas, None);
    let h = hpa(&g, &p, &a).spec.unwrap();
    assert_eq!((h.min_replicas, h.max_replicas), (Some(3), 10));
}

// RFC 0025 case 1: `GOLDEN=1` rewrites the file
#[test]
fn without_the_new_fields_nothing_changes() {
    let b = web(None);
    let g = plan(&b, "80", "default", false).unwrap();
    let p = PolicySpec {
        secret_ref: Some(crate::crd::SecretRef { name: "s".into() }),
        ..PolicySpec::default()
    };
    let got = serde_json::json!({
        "deployment": deployment(&g, &p, "img:1", "abc"),
        "service": service(&g, &b, true),
    });
    if std::env::var_os("GOLDEN").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/gateway_golden.json");
        std::fs::write(path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let want: serde_json::Value =
        serde_json::from_str(include_str!("gateway_golden.json")).unwrap();
    assert_eq!(got, want);
}

fn pod(d: &Deployment) -> PodSpec {
    d.spec.clone().unwrap().template.spec.unwrap()
}

fn mount_paths(c: &Container) -> Vec<(String, String, bool)> {
    c.volume_mounts
        .iter()
        .flatten()
        .map(|m| {
            (
                m.name.clone(),
                m.mount_path.clone(),
                m.read_only == Some(true),
            )
        })
        .collect()
}

// RFC 0025 case 2
#[test]
fn admin_listener_port_and_service() {
    let g = plan(&web(None), "80", "default", false).unwrap();
    let mut p = PolicySpec::default();
    p.gateway.admin = Some(crate::crd::Admin { enabled: true });
    let d = deployment(&g, &p, "img:1", "abc");
    assert_eq!(env_of(&d, "DVARAPALA__ADMIN__LISTEN"), "0.0.0.0:9091");
    let ports = pod(&d).containers[0].ports.clone().unwrap();
    assert!(
        ports
            .iter()
            .any(|p| p.name.as_deref() == Some("admin") && p.container_port == 9091)
    );
    let s = admin::service(&g);
    assert_eq!(s.metadata.name.as_deref(), Some("web-dvp-admin-80"));
    let spec = s.spec.unwrap();
    assert_eq!(spec.session_affinity.as_deref(), Some("ClientIP"));
    assert_eq!(spec.selector, Some(selector(&g)));
    assert_eq!(spec.ports.unwrap()[0].port, 9091);
    // never taken for a gateway Service
    assert!(!s.metadata.labels.unwrap().contains_key(APP.0));
}

// RFC 0025 case 5
#[test]
fn waf_sidecar_shares_the_socket() {
    let g = plan(&web(None), "80", "default", false).unwrap();
    let mut p = PolicySpec::default();
    p.gateway.waf = Some(crate::crd::Waf {
        image: "ghcr.io/corazawaf/coraza-spoa:0.9.1".into(),
        config_map: "coraza".into(),
        resources: None,
    });
    let d = deployment(&g, &p, "img:1", "abc");
    assert_eq!(
        env_of(&d, "DVARAPALA__WAF__ENDPOINT"),
        "unix:/run/waf/waf.sock"
    );
    let pod = pod(&d);
    assert_eq!(pod.containers.len(), 2);
    let (proxy, agent) = (&pod.containers[0], &pod.containers[1]);
    assert_eq!(agent.name, "waf");
    let socket = ("waf-socket".to_owned(), "/run/waf".to_owned(), false);
    assert!(mount_paths(proxy).contains(&socket));
    assert!(mount_paths(agent).contains(&socket));
    assert!(mount_paths(proxy).contains(&("waf-config".into(), "/etc/dvarapala-waf".into(), true)));
    for c in [proxy, agent] {
        let sc = c.security_context.clone().unwrap();
        assert_eq!(sc.run_as_non_root, Some(true), "{}", c.name);
        assert_eq!(sc.read_only_root_filesystem, Some(true), "{}", c.name);
        assert_eq!(sc.allow_privilege_escalation, Some(false), "{}", c.name);
        assert_eq!(sc.capabilities.unwrap().drop, Some(vec!["ALL".into()]));
    }
    assert_eq!(
        agent.security_context.clone().unwrap().run_as_user,
        Some(10001)
    );
    let volumes: Vec<String> = pod.volumes.unwrap().into_iter().map(|v| v.name).collect();
    assert!(volumes.contains(&"waf-socket".into()) && volumes.contains(&"waf-config".into()));
}

// RFC 0025 case 8
#[test]
fn mounts_are_read_only_in_the_proxy_only() {
    let g = plan(&web(None), "80", "default", false).unwrap();
    let mut p = PolicySpec::default();
    p.gateway.mounts = vec![
        crate::crd::Mount {
            name: "pg-ca".into(),
            config_map: Some("lab-root-ca".into()),
            secret: None,
        },
        crate::crd::Mount {
            name: "llm-key".into(),
            config_map: None,
            secret: Some("shop-llm".into()),
        },
    ];
    p.gateway.pod_labels = [("team".into(), "shop".into())].into();
    let d = deployment(&g, &p, "img:1", "abc");
    let pod_meta = d.spec.clone().unwrap().template.metadata.unwrap();
    assert_eq!(pod_meta.labels.unwrap()["team"], "shop");
    let pod = pod(&d);
    assert_eq!(pod.containers.len(), 1);
    let m = mount_paths(&pod.containers[0]);
    assert!(m.contains(&(
        "mount-pg-ca".into(),
        "/etc/dvarapala-mounts/pg-ca".into(),
        true
    )));
    assert!(m.contains(&(
        "mount-llm-key".into(),
        "/etc/dvarapala-mounts/llm-key".into(),
        true
    )));
    let v = pod.volumes.unwrap();
    let ca = v.iter().find(|v| v.name == "mount-pg-ca").unwrap();
    assert_eq!(ca.config_map.as_ref().unwrap().name, "lab-root-ca");
    let key = v.iter().find(|v| v.name == "mount-llm-key").unwrap();
    assert_eq!(
        key.secret.as_ref().unwrap().secret_name.as_deref(),
        Some("shop-llm")
    );
}
