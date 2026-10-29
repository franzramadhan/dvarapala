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
