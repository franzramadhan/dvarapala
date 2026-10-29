//! RFC 0004 cases 11, 12 and 14: local answers to gRPC and plain clients.

use std::cell::Cell;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{DetectConfig, Limit, TrustedProxies};
use dvarapala_l7::{Detection, PeerAddr, RateLimitConfig, RateLimitLayer};
use http::{Request, Response, StatusCode, Version};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

thread_local! {
    static MS: Cell<u64> = const { Cell::new(0) };
}

/// Fake clock, moved by `at`.
fn now() -> Instant {
    *BASE + Duration::from_millis(MS.get())
}

fn at(ms: u64) {
    MS.set(ms);
}

fn layer(detection: Option<Detection>) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(1, 1).unwrap(),
        max_clients: NonZeroUsize::new(4096).unwrap(),
        trusted: TrustedProxies::default(),
        detection,
        scoring: None,
        now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: Vec::new(),
        max_blocks: 0,
    })
    .unwrap()
}

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

fn req(peer: &str, grpc: bool) -> Request<Body> {
    let mut b = Request::post("/pkg.Svc/Method").version(Version::HTTP_2);
    if grpc {
        b = b.header("content-type", "application/grpc+proto");
    }
    let mut r = b.body(Body::default()).unwrap();
    r.extensions_mut()
        .insert(PeerAddr(peer.parse::<SocketAddr>().unwrap()));
    r
}

async fn call<S>(svc: &mut S, r: Request<Body>) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    svc.ready().await.unwrap().call(r).await.unwrap()
}

/// RFC 0004 case 11
#[tokio::test]
async fn throttled_grpc_gets_resource_exhausted() {
    let (calls, inner) = counting();
    let mut svc = layer(None).layer(inner);
    assert_eq!(
        call(&mut svc, req("192.0.2.10:1", true)).await.status(),
        StatusCode::OK
    );
    let r = call(&mut svc, req("192.0.2.10:2", true)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-type"], "application/grpc");
    assert_eq!(r.headers()["grpc-status"], "8");
    assert!(r.headers().contains_key("grpc-message"));
    assert_eq!(r.headers()["retry-after"], "1");
    let ms: u64 = r.headers()["grpc-retry-pushback-ms"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=1000).contains(&ms), "{ms}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// RFC 0004 case 12
#[tokio::test]
async fn dropped_grpc_gets_permission_denied() {
    let detection = Detection {
        detect: DetectConfig {
            warmup_windows: 1,
            trigger_windows: 1,
            ..DetectConfig::default()
        },
        enforce: true,
        attack_rate_factor: 0.25,
    };
    let (_, inner) = counting();
    let mut svc = layer(Some(detection)).layer(inner);
    // window 0: ten clients; window 1: one source floods; the first
    // request of window 2 closes it and the flooder is a heavy hitter
    at(0);
    for i in 0..10 {
        call(&mut svc, req(&format!("198.51.100.{i}:1"), true)).await;
    }
    at(1000);
    for _ in 0..1000 {
        call(&mut svc, req("192.0.2.10:1", true)).await;
    }
    at(2000);
    let r = call(&mut svc, req("192.0.2.10:1", true)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["grpc-status"], "7");
}

/// RFC 0004 case 14
#[tokio::test]
async fn throttled_plain_request_still_gets_429() {
    let (_, inner) = counting();
    let mut svc = layer(None).layer(inner);
    call(&mut svc, req("192.0.2.10:1", false)).await;
    let r = call(&mut svc, req("192.0.2.10:2", false)).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.headers()["retry-after"], "1");
    assert!(r.headers().get("grpc-status").is_none());
}
