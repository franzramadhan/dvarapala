//! RFC 0013 cases 5 to 9: routes through the rate limit layer.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{ChallengeMode, Limit, TrustedProxies};
use dvarapala_l7::{
    ChallengeConfig, Matcher, PathMatch, PeerAddr, RateLimitConfig, RateLimitLayer, RouteConfig,
    RouteKey, unix_now,
};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

fn route(path: &str) -> RouteConfig {
    RouteConfig {
        name: "r".into(),
        matcher: Matcher {
            path: Some(PathMatch::parse(path).unwrap()),
            ..Matcher::default()
        },
        deny: false,
        limit: None,
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::new(100).unwrap(),
    }
}

fn layer(global: Limit, routes: Vec<RouteConfig>, challenge: bool) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: global,
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: challenge.then(|| ChallengeConfig {
            mode: ChallengeMode::Always,
            difficulty: 8,
            timeout: Duration::from_secs(60),
            pass_ttl: Duration::from_secs(3600),
            secret: vec![5; 32],
            cookie_secure: false,
            unix: unix_now,
        }),
        fingerprints: Default::default(),
        routes,
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

fn req(uri: &str, peer: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut r = b.body(Body::default()).unwrap();
    r.extensions_mut().insert(PeerAddr(
        format!("{peer}:4000").parse::<SocketAddr>().unwrap(),
    ));
    r
}

async fn send<S>(svc: &mut S, r: Request<Body>) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    svc.ready().await.unwrap().call(r).await.unwrap()
}

const PEER: &str = "192.0.2.10";

// case 5
#[tokio::test]
async fn deny_closes_before_any_bucket() {
    let (calls, inner) = counting();
    let deny = RouteConfig {
        deny: true,
        ..route("/wp-admin")
    };
    // global burst 1: a token taken by the denied request would throttle
    // the next one
    let mut svc = layer(Limit::new(1, 1).unwrap(), vec![deny], false).layer(inner);
    let res = send(&mut svc, req("/wp-admin/x", PEER, &[])).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(res.headers()["connection"], "close");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let res = send(&mut svc, req("/", PEER, &[])).await;
    assert_eq!(res.status(), StatusCode::OK);
}

// case 6
#[tokio::test]
async fn route_bucket_throttles_under_the_global_rate() {
    let login = RouteConfig {
        limit: Some(Limit::new(1, 1).unwrap()),
        ..route("=/login")
    };
    let (_, inner) = counting();
    let mut svc = layer(Limit::new(100, 100).unwrap(), vec![login], false).layer(inner);
    assert_eq!(
        send(&mut svc, req("/login", PEER, &[])).await.status(),
        StatusCode::OK
    );
    let res = send(&mut svc, req("/login", PEER, &[])).await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(res.headers().contains_key("retry-after"));
    // other paths keep the global limit
    assert_eq!(
        send(&mut svc, req("/a", PEER, &[])).await.status(),
        StatusCode::OK
    );
}

// case 7
#[tokio::test]
async fn header_key_buckets() {
    let api = RouteConfig {
        limit: Some(Limit::new(1, 1).unwrap()),
        key: RouteKey::parse("header:x-api-key").unwrap(),
        ..route("/api/")
    };
    let (_, inner) = counting();
    let mut svc = layer(Limit::new(100, 100).unwrap(), vec![api], false).layer(inner);
    let status = async |svc: &mut _, peer, key: Option<&str>| {
        let h: Vec<_> = key.map(|k| ("x-api-key", k)).into_iter().collect();
        send(svc, req("/api/x", peer, &h)).await.status()
    };
    // two keys from one client: one bucket each
    assert_eq!(status(&mut svc, PEER, Some("a")).await, StatusCode::OK);
    assert_eq!(status(&mut svc, PEER, Some("b")).await, StatusCode::OK);
    // one key from another client: shared with the first
    assert_eq!(
        status(&mut svc, "198.51.100.1", Some("a")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // no header: the client's own bucket
    assert_eq!(status(&mut svc, "198.51.100.1", None).await, StatusCode::OK);
    assert_eq!(
        status(&mut svc, "198.51.100.1", None).await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// case 8
#[tokio::test]
async fn global_bucket_still_applies() {
    let loose = RouteConfig {
        limit: Some(Limit::new(100, 100).unwrap()),
        ..route("/")
    };
    let (_, inner) = counting();
    let mut svc = layer(Limit::new(1, 1).unwrap(), vec![loose], false).layer(inner);
    assert_eq!(
        send(&mut svc, req("/", PEER, &[])).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&mut svc, req("/", PEER, &[])).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

// case 9
#[tokio::test]
async fn exempt_route_skips_the_challenge() {
    let api = RouteConfig {
        challenge: false,
        ..route("/api/")
    };
    let (calls, inner) = counting();
    let mut svc = layer(Limit::new(100, 100).unwrap(), vec![api], true).layer(inner);
    let html = [("accept", "text/html")];
    let res = send(&mut svc, req("/api/x", PEER, &html)).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let res = send(&mut svc, req("/x", PEER, &html)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
