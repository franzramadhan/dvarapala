use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use bytes::Bytes;
use dvarapala_engine::{Cidr, Limit, TrustedProxies};
use dvarapala_l7::{PeerAddr, RateLimitConfig, RateLimitLayer};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

fn layer(rate: u32, burst: u32, trusted: &[&str]) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(rate, burst).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(trusted.iter().map(|c| c.parse::<Cidr>().unwrap()).collect()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
    })
    .unwrap()
}

/// Inner service that counts calls and answers 200.
fn counting() -> (
    Arc<AtomicUsize>,
    impl Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let svc = service_fn(move |_req: Request<Body>| {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, Infallible>(Response::new(Body::default())) }
    });
    (calls, svc)
}

fn req(peer: &str, xff: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri("/");
    if let Some(x) = xff {
        b = b.header("x-forwarded-for", x);
    }
    let mut r = b.body(Body::default()).unwrap();
    r.extensions_mut()
        .insert(PeerAddr(peer.parse::<SocketAddr>().unwrap()));
    r
}

#[tokio::test]
async fn second_request_gets_429_with_retry_after() {
    let (_, inner) = counting();
    let mut svc = layer(1, 1, &[]).layer(inner);
    let ok = svc
        .ready()
        .await
        .unwrap()
        .call(req("192.0.2.10:1000", None))
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    let limited = svc
        .ready()
        .await
        .unwrap()
        .call(req("192.0.2.10:1001", None))
        .await
        .unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()["retry-after"], "1");
}

#[tokio::test]
async fn throttled_request_never_reaches_inner() {
    let (calls, inner) = counting();
    let mut svc = layer(1, 1, &[]).layer(inner);
    for port in 0..5 {
        let peer = format!("192.0.2.10:{}", 2000 + port);
        svc.ready()
            .await
            .unwrap()
            .call(req(&peer, None))
            .await
            .unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn clients_have_separate_buckets() {
    let (_, inner) = counting();
    let l = layer(1, 1, &[]);
    let mut svc = l.clone().layer(inner);
    for peer in ["192.0.2.10:1", "192.0.2.11:1", "[2001:db8::1]:1"] {
        let r = svc
            .ready()
            .await
            .unwrap()
            .call(req(peer, None))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{peer}");
    }
    assert_eq!(l.clients(), 3);
}

#[tokio::test]
async fn trusted_proxy_keys_on_forwarded_client() {
    let (_, inner) = counting();
    let mut svc = layer(1, 1, &["192.0.2.0/24"]).layer(inner);
    let a = svc
        .ready()
        .await
        .unwrap()
        .call(req("192.0.2.1:1", Some("198.51.100.7")))
        .await
        .unwrap();
    let b = svc
        .ready()
        .await
        .unwrap()
        .call(req("192.0.2.1:1", Some("198.51.100.8")))
        .await
        .unwrap();
    let c = svc
        .ready()
        .await
        .unwrap()
        .call(req("192.0.2.1:1", Some("198.51.100.7")))
        .await
        .unwrap();
    assert_eq!(a.status(), StatusCode::OK);
    assert_eq!(b.status(), StatusCode::OK);
    assert_eq!(c.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn missing_peer_fails_closed() {
    let (calls, inner) = counting();
    let mut svc = layer(1, 1, &[]).layer(inner);
    let r = svc
        .ready()
        .await
        .unwrap()
        .call(Request::builder().uri("/").body(Body::default()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
