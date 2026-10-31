//! RFC 0028 cases 1 to 5, 19 and 20: routes through `dv_check_request`.

mod common;

use std::sync::Arc;
use std::thread;

use common::{Req, guard, req};
use dvarapala::*;

const LOGIN: &str =
    r#"[{"name": "login", "path": "=/login", "methods": ["POST"], "rate": 1, "burst": 2}]"#;

/// RFC 0028 case 1
#[test]
fn a_route_bucket_on_top_of_the_global_one() {
    let g = guard(&[("routes", LOGIN)]).unwrap();
    let post = || g.request(req("192.0.2.1", "POST", "/login")).unwrap();
    let route = Some("login".to_owned());
    assert_eq!(post(), (DV_ALLOW, 0, route.clone()));
    assert_eq!(post(), (DV_ALLOW, 0, route.clone()));
    let (kind, retry, name) = post();
    assert_eq!((kind, name), (DV_THROTTLE, route));
    assert!((1..=1000).contains(&retry), "{retry}");
    assert_eq!(
        g.request(req("192.0.2.1", "GET", "/login")).unwrap(),
        (DV_ALLOW, 0, None)
    );
}

/// RFC 0028 case 2
#[test]
fn a_denied_route_drops_before_any_bucket() {
    let routes = r#"[{"name": "probes", "path": "/wp-admin", "deny": true}]"#;
    let g = guard(&[
        ("routes", routes),
        ("rate_limit.rate", "1"),
        ("rate_limit.burst", "1"),
    ])
    .unwrap();
    for _ in 0..3 {
        let v = g.request(req("192.0.2.1", "GET", "/wp-admin/x")).unwrap();
        assert_eq!(v, (DV_DROP, 0, Some("probes".into())));
    }
    // the client's one token is still there
    assert_eq!(g.check("192.0.2.1").kind, DV_ALLOW);
}

const API: &str =
    r#"[{"name": "api", "path": "/", "key": "header:X-Api-Key", "rate": 1, "burst": 1}]"#;

/// RFC 0028 cases 3 and 4
#[test]
fn a_bucket_per_header_value() {
    let g = guard(&[("routes", API)]).unwrap();
    let with = |key: &str| {
        let h = format!("x-api-key: {key}\n");
        let r = Req {
            headers: Some(&h),
            ..req("192.0.2.1", "GET", "/v1")
        };
        g.request(r).unwrap().0
    };
    assert_eq!(
        [with("a"), with("a"), with("b")],
        [DV_ALLOW, DV_THROTTLE, DV_ALLOW]
    );
    assert_eq!(g.route_headers(), "x-api-key");
    assert_eq!(guard(&[("routes", LOGIN)]).unwrap().route_headers(), "");
    assert_eq!(guard(&[]).unwrap().route_headers(), "");
}

/// RFC 0028 case 5
#[test]
fn gateway_only_route_fields_are_refused() {
    for (field, route) in [
        ("key", r#"[{"name": "fp", "key": "ja4", "rate": 1}]"#),
        ("challenge", r#"[{"name": "fp", "challenge": false}]"#),
        ("waf", r#"[{"name": "fp", "waf": false}]"#),
    ] {
        let e = guard(&[("routes", route)]).err().unwrap();
        assert!(e.contains("\"fp\"") && e.contains(field), "{field}: {e}");
    }
}

/// RFC 0028 case 19
#[test]
fn bad_request_input_fails_closed() {
    let g = guard(&[("routes", API)]).unwrap();
    let long = format!("/{}", "a".repeat(8 * 1024));
    let bad = [
        Req {
            headers: Some("x-api-key: a\nb\n"),
            ..req("192.0.2.1", "GET", "/")
        },
        Req {
            headers: Some("x-api-key: a\r\n"),
            ..req("192.0.2.1", "GET", "/")
        },
        req("192.0.2.1", "GET", &long),
        Req {
            method: None,
            ..req("192.0.2.1", "GET", "/")
        },
        Req {
            path: None,
            ..req("192.0.2.1", "GET", "/")
        },
        req("192.0.2.1", "", "/"),
    ];
    for r in bad {
        assert_eq!(g.request(r), Err(DV_E_INVALID));
    }
    let host = Req {
        host: Some("api.example.com:8443"),
        ..req("192.0.2.1", "GET", "/")
    };
    assert!(g.request(host).is_ok());
}

/// RFC 0028 case 20
#[test]
fn reload_with_checks_in_flight() {
    let g = Arc::new(guard(&[("routes", LOGIN), ("rate_limit.rate", "1")]).unwrap());
    let workers: Vec<_> = (1..=8)
        .map(|n| {
            let g = g.clone();
            thread::spawn(move || {
                let ip = format!("192.0.2.{n}");
                for _ in 0..2000 {
                    let (kind, _, _) = g.request(req(&ip, "POST", "/login")).unwrap();
                    assert!([DV_ALLOW, DV_THROTTLE].contains(&kind), "{kind}");
                }
            })
        })
        .collect();
    for i in 0..100 {
        let rate = if i % 2 == 0 { "100" } else { "1" };
        g.reload(&[("routes", LOGIN), ("rate_limit.rate", rate)])
            .unwrap();
    }
    for w in workers {
        w.join().unwrap();
    }
}
