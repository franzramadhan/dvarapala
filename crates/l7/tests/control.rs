//! RFC 0014 cases 4 to 6: manual blocks and reloads through the layer.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Limit, TrustedProxies};
use dvarapala_l7::{
    Matcher, PathMatch, PeerAddr, RateLimitConfig, RateLimitLayer, Reload, RouteConfig, RouteKey,
};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

fn layer(limit: Limit) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit,
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: Vec::new(),
        max_blocks: 4,
    })
    .unwrap()
}

fn reload(limit: Limit, routes: Option<Vec<RouteConfig>>) -> Reload {
    Reload {
        limit,
        trusted: TrustedProxies::new(Vec::new()),
        enforce: false,
        attack_rate_factor: 1.0,
        challenge: None,
        fingerprints: Default::default(),
        routes,
    }
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

async fn send<S>(svc: &mut S, uri: &str, peer: &str) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let mut r = Request::builder().uri(uri).body(Body::default()).unwrap();
    r.extensions_mut().insert(PeerAddr(
        format!("{peer}:4000").parse::<SocketAddr>().unwrap(),
    ));
    svc.ready().await.unwrap().call(r).await.unwrap()
}

// case 4
#[tokio::test]
async fn manual_block_closes_before_any_bucket() {
    let l = layer(Limit::new(100, 100).unwrap());
    let (calls, inner) = counting();
    let mut svc = l.layer(inner);
    l.block("192.0.2.0/24".parse().unwrap(), Duration::from_secs(600))
        .unwrap();
    let res = send(&mut svc, "/", "192.0.2.7").await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(res.headers()["connection"], "close");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let res = send(&mut svc, "/", "198.51.100.7").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let b = l.blocks();
    assert_eq!(b.len(), 1);
    assert!(b[0].remaining <= Duration::from_secs(600));
    assert!(l.unblock("192.0.2.0/24".parse().unwrap()));
    let res = send(&mut svc, "/", "192.0.2.7").await;
    assert_eq!(res.status(), StatusCode::OK);
}

// case 5
#[tokio::test]
async fn reload_applies_the_rate_and_keeps_clients() {
    let l = layer(Limit::new(100, 100).unwrap());
    let (_, inner) = counting();
    let mut svc = l.layer(inner);
    assert_eq!(
        send(&mut svc, "/", "192.0.2.10").await.status(),
        StatusCode::OK
    );
    assert_eq!(l.clients(), 1);
    l.reload(reload(Limit::new(1, 1).unwrap(), None)).unwrap();
    assert_eq!(l.clients(), 1);
    // a new client gets the new burst of 1
    assert_eq!(
        send(&mut svc, "/", "198.51.100.1").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&mut svc, "/", "198.51.100.1").await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

// case 6
#[tokio::test]
async fn reload_adds_a_deny_route() {
    let l = layer(Limit::new(100, 100).unwrap());
    let (_, inner) = counting();
    let mut svc = l.layer(inner);
    assert_eq!(
        send(&mut svc, "/wp-admin", "192.0.2.10").await.status(),
        StatusCode::OK
    );
    let deny = RouteConfig {
        name: "wp".into(),
        matcher: Matcher {
            path: Some(PathMatch::parse("/wp-admin").unwrap()),
            ..Matcher::default()
        },
        deny: true,
        limit: None,
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::new(16).unwrap(),
        waf: true,
    };
    l.reload(reload(Limit::new(100, 100).unwrap(), Some(vec![deny])))
        .unwrap();
    assert_eq!(
        send(&mut svc, "/wp-admin", "192.0.2.10").await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&mut svc, "/", "192.0.2.10").await.status(),
        StatusCode::OK
    );
}
