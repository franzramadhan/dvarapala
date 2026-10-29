//! RFC 0017 case 12: the WAF layer against a real `coraza-spoa` with its
//! built-in CRS at paranoia 1, at `DVARAPALA_TEST_CORAZA` (`host:port`).
//! Fails in CI when unset, skips locally.
#![cfg(feature = "waf")]

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::TrustedProxies;
use dvarapala_l7::{Endpoint, PeerAddr, WafBody, WafConfig, WafLayer};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, ServiceExt, service_fn};

fn agent() -> Option<String> {
    const VAR: &str = "DVARAPALA_TEST_CORAZA";
    match std::env::var(VAR) {
        Ok(a) => Some(a),
        Err(_) if std::env::var_os("CI").is_some() => panic!("{VAR} is not set in CI"),
        Err(_) => {
            eprintln!("skipped: {VAR} is not set");
            None
        }
    }
}

fn layer(agent: String) -> WafLayer {
    WafLayer::new(Some(WafConfig {
        enforce: true,
        endpoint: Endpoint::Tcp(agent),
        app: "default".into(),
        // the first request on a cold agent compiles the CRS
        timeout: Duration::from_secs(5),
        fail_open: false,
        max_body: 16 * 1024,
        reject_over_limit: true,
        max_concurrent: 4,
        trusted: TrustedProxies::default(),
        listen: "192.0.2.1:443".parse().unwrap(),
    }))
}

/// A browser-like request, so only the sample itself can raise the score.
fn request(method: &str, target: &str, body: &'static str) -> Request<Full<Bytes>> {
    let mut r = Request::builder()
        .method(method)
        .uri(target)
        .header("host", "app.example")
        .header(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        )
        .header("accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
        .header("accept-language", "en-US,en;q=0.5");
    if !body.is_empty() {
        r = r
            .header("content-type", "application/x-www-form-urlencoded")
            .header("content-length", body.len());
    }
    let mut r = r
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap();
    r.extensions_mut()
        .insert(PeerAddr("198.51.100.7:50000".parse().unwrap()));
    r
}

async fn status(l: &WafLayer, req: Request<Full<Bytes>>) -> StatusCode {
    let svc = l.layer(service_fn(|_: Request<WafBody<Full<Bytes>>>| async {
        Ok::<_, Infallible>(Response::new(Full::<Bytes>::default()))
    }));
    svc.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn crs_blocks_attacks_and_passes_ordinary_requests() {
    let Some(agent) = agent() else { return };
    let l = layer(agent);
    let attacks = [
        ("sqli", "GET", "/items?id=1%27%20OR%20%271%27%3D%271", ""),
        (
            "xss",
            "GET",
            "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "",
        ),
        (
            "traversal",
            "GET",
            "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "",
        ),
        (
            "rce",
            "GET",
            "/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd",
            "",
        ),
        (
            "sqli in a form",
            "POST",
            "/login",
            "user=admin&pass=x%27%20UNION%20SELECT%20password%20FROM%20users--",
        ),
    ];
    for (name, method, target, body) in attacks {
        let s = status(&l, request(method, target, body)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{name}");
    }
    for i in 0..100 {
        let target = format!("/products/{i}?page={}&sort=price", i % 7);
        let req = match i % 4 {
            0 => request("POST", &target, "item=42&qty=2&note=gift+wrap"),
            _ => request("GET", &target, ""),
        };
        let s = status(&l, req).await;
        assert_eq!(s, StatusCode::OK, "ordinary request {i}");
    }
}
