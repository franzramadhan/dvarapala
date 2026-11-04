//! Issue 329: a request through the rate limit layer with a limited route,
//! which counts the verdict and sets the keys gauge on every request.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Instant;

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{Limit, TrustedProxies};
use dvarapala_l7::{
    Matcher, PathMatch, PeerAddr, RateLimitConfig, RateLimitLayer, RouteConfig, RouteKey,
};
use http::{Request, Response};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

fn layer() -> RateLimitLayer {
    let route = RouteConfig {
        name: "api".into(),
        matcher: Matcher {
            path: Some(PathMatch::parse("/api/").unwrap()),
            ..Matcher::default()
        },
        deny: false,
        limit: Some(Limit::new(1_000_000_000, 1_000_000_000).unwrap()),
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::new(100).unwrap(),
        waf: true,
        concurrency: 1,
    };
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(1_000_000_000, 1_000_000_000).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: vec![route],
        max_blocks: 0,
        priority: None,
    })
    .unwrap()
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut svc = layer().layer(service_fn(|_: Request<Body>| async {
        Ok::<_, Infallible>(Response::new(Body::default()))
    }));
    let peer = PeerAddr("192.0.2.7:4000".parse::<SocketAddr>().unwrap());
    c.bench_function("route_layer_allow", |b| {
        b.iter(|| {
            let mut req = Request::get("/api/items").body(Body::default()).unwrap();
            req.extensions_mut().insert(peer);
            rt.block_on(async { svc.ready().await.unwrap().call(req).await.unwrap() })
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
