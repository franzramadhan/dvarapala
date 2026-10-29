//! RFC 0013 case 14: 32 routes, a request that matches only the last.

use std::hint::black_box;
use std::net::IpAddr;
use std::num::NonZeroUsize;

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::ClientKey;
use dvarapala_l7::{Host, Matcher, PathMatch, RouteConfig, RouteKey, Routes};
use http::{Method, Request};

fn routes() -> Routes {
    let route = |i: usize| RouteConfig {
        name: format!("r{i}"),
        matcher: Matcher {
            host: Some(Host::parse("*.example.com").unwrap()),
            path: Some(PathMatch::parse(&format!("/api/v{i}/")).unwrap()),
            methods: vec![Method::GET, Method::POST],
            clients: vec!["192.0.2.0/24".parse().unwrap()],
        },
        deny: false,
        limit: None,
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::new(100).unwrap(),
        waf: true,
    };
    Routes::new((0..32).map(route).collect())
}

fn bench(c: &mut Criterion) {
    let routes = routes();
    let req = Request::post("/api/v31/items?page=2")
        .header("host", "shop.example.com:443")
        .body(())
        .unwrap();
    let client = ClientKey::from(IpAddr::from([192, 0, 2, 7]));
    assert_eq!(routes.matching(&req, client), Some("r31"));
    c.bench_function("route_match_last_of_32", |b| {
        b.iter(|| routes.matching(black_box(&req), black_box(client)))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
