//! RFC 0007: forward proxy routing, the client and destination allow
//! lists, and provider pauses.

mod egress;

use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_proxy::ForwardConfig;
use egress::{Behave, config, connect, counter, dest, get, proxy, record, send, upstream};
use http::{Request, StatusCode};
use http_body_util::Empty;

fn egress(destination: &str, result: &str) -> u64 {
    counter(&format!(
        "dvarapala_egress_requests_total{{destination={destination},result={result}}}"
    ))
}

/// RFC 0007 case 7
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0007"]
async fn absolute_form_goes_out_in_origin_form() {
    record();
    let (up, seen) = upstream(Behave::default()).await;
    let (p, _stop) = proxy(config(vec![dest("c7", &format!("http://{up}"), 100.0, 10)])).await;
    let req = Request::get(format!("http://{up}/v1/x?q=1"))
        .header("x-custom", "v")
        .header("proxy-authorization", "Basic <token>")
        .header("connection", "x-secret-hop")
        .header("x-secret-hop", "1")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let (status, _, body) = send(p, req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with("GET /v1/x?q=1\n"), "{body}");
    assert!(body.contains("x-custom=v\n"), "{body}");
    assert!(body.contains(&format!("host={up}\n")), "{body}");
    for gone in ["proxy-authorization", "x-secret-hop", "x-forwarded-for"] {
        assert!(!body.contains(gone), "{gone} reached the upstream: {body}");
    }
    assert_eq!(seen.hits(), 1);
    assert_eq!(egress("c7", "sent"), 1);
}

/// RFC 0007 case 9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0007"]
async fn unlisted_origin_is_denied() {
    record();
    let (up, seen) = upstream(Behave::default()).await;
    let (p, _stop) = proxy(config(vec![dest("c9", &format!("http://{up}"), 100.0, 10)])).await;
    for url in [
        "http://192.0.2.1:9/".to_owned(),
        // same host, other port; https:// to an http:// origin; userinfo
        format!("http://127.0.0.1:{}/", up.port().wrapping_add(1)),
        format!("https://{up}/"),
        format!("http://user@{up}/"),
    ] {
        assert_eq!(get(p, &url).await.0, StatusCode::FORBIDDEN, "{url}");
    }
    assert_eq!(
        connect(p, "192.0.2.1:443").await.unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(seen.hits(), 0);
    assert_eq!(egress("none", "denied"), 5);
}

/// RFC 0007 case 9, `forward.connect = false`
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0007"]
async fn connect_off_is_denied() {
    let (up, _) = upstream(Behave::default()).await;
    let (p, _stop) = proxy(ForwardConfig {
        connect: false,
        ..config(vec![dest("c9-off", &format!("http://{up}"), 100.0, 10)])
    })
    .await;
    assert_eq!(
        connect(p, &up.to_string()).await.unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(get(p, &format!("http://{up}/")).await.0, StatusCode::OK);
}

/// RFC 0007 case 10
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0007"]
async fn client_outside_the_list_is_denied() {
    record();
    let (up, seen) = upstream(Behave::default()).await;
    let (p, _stop) = proxy(ForwardConfig {
        clients: vec!["192.0.2.0/24".parse().unwrap()],
        ..config(vec![dest("c10", &format!("http://{up}"), 100.0, 10)])
    })
    .await;
    assert_eq!(
        get(p, &format!("http://{up}/")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        connect(p, &up.to_string()).await.unwrap_err(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(seen.hits(), 0);
    assert_eq!(egress("c10", "denied"), 2);
}

/// RFC 0007 case 13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0007"]
async fn provider_retry_after_pauses_the_destination() {
    record();
    let (up, seen) = upstream(Behave {
        first: Some((StatusCode::TOO_MANY_REQUESTS, "1")),
        ..Behave::default()
    })
    .await;
    let (p, _stop) = proxy(config(vec![dest(
        "c13",
        &format!("http://{up}"),
        100.0,
        10,
    )]))
    .await;
    let url = format!("http://{up}/");
    // the provider's own 429 passes through
    assert_eq!(get(p, &url).await.0, StatusCode::TOO_MANY_REQUESTS);
    let start = Instant::now();
    assert_eq!(get(p, &url).await.0, StatusCode::OK);
    assert!(
        start.elapsed() >= Duration::from_millis(900),
        "{:?}",
        start.elapsed()
    );
    let t = seen.times.lock().unwrap().clone();
    assert!(
        t[1] - t[0] >= Duration::from_millis(900),
        "{:?}",
        t[1] - t[0]
    );
    assert_eq!(
        counter("dvarapala_egress_provider_pauses_total{destination=c13}"),
        1
    );
    assert_eq!(egress("c13", "delayed"), 1);
}
