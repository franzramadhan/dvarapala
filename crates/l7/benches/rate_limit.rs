//! Issue 330: requests through `RateLimitLayer` over a no-op service from
//! 10k clients in 198.18.0.0/15, alone and on 8 threads, so the locks on the
//! request path (client table, detector, cluster) show up in a profile.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{
    Cluster, ClusterConfig, DetectConfig, Features, Limit, Scorer, TrustedProxies,
};
use dvarapala_l7::{
    Detection, Matcher, PathMatch, PeerAddr, RateLimitConfig, RateLimitLayer, RouteConfig,
    RouteKey, Scoring,
};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

const CLIENTS: u32 = 10_000;
const BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);

/// Scores every request 0 and counts the calls, so the bench can tell that
/// scoring (and with it the `StatusRecorder` relock) ran.
struct Flat(AtomicUsize);

impl Scorer for Flat {
    fn score(&self, _: &Features) -> f64 {
        self.0.fetch_add(1, Ordering::Relaxed);
        0.0
    }
}

fn huge() -> Limit {
    Limit::new(1_000_000_000, 1_000_000_000).unwrap()
}

fn config() -> RateLimitConfig {
    RateLimitConfig {
        limit: huge(),
        max_clients: NonZeroUsize::new(16_384).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: Vec::new(),
        max_blocks: 0,
        priority: None,
    }
}

fn detection(mut c: RateLimitConfig, scorer: Arc<Flat>) -> RateLimitConfig {
    c.detection = Some(Detection {
        detect: DetectConfig::default(),
        enforce: false,
        attack_rate_factor: 0.25,
    });
    c.scoring = Some(Scoring {
        scorer,
        threshold: 0.9,
    });
    c
}

fn route(mut c: RateLimitConfig, limit: Limit) -> RateLimitConfig {
    c.routes = vec![RouteConfig {
        name: "api".into(),
        matcher: Matcher {
            path: Some(PathMatch::parse("/api/").unwrap()),
            ..Matcher::default()
        },
        deny: false,
        limit: Some(limit),
        key: RouteKey::Client,
        challenge: false,
        max_keys: NonZeroUsize::new(16_384).unwrap(),
        waf: false,
        concurrency: 1,
    }];
    c
}

fn cluster(mut c: RateLimitConfig, shared: Arc<Mutex<Cluster>>) -> RateLimitConfig {
    c.cluster = Some(shared);
    c
}

fn new_cluster() -> Arc<Mutex<Cluster>> {
    Arc::new(Mutex::new(Cluster::new(ClusterConfig {
        limit: Some(huge()),
        window: Duration::from_secs(10),
        max_keys: 16_384,
        max_clients: 16_384,
    })))
}

/// One request from `192.0.2.1` through a fresh service of `layer`.
fn once(layer: &RateLimitLayer, path: &str) -> StatusCode {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut svc = layer.layer(service_fn(|_: Request<Body>| async {
        Ok::<_, Infallible>(Response::new(Body::default()))
    }));
    let mut req = Request::get(path).body(Body::default()).unwrap();
    req.extensions_mut()
        .insert(PeerAddr(SocketAddr::from(([192, 0, 2, 1], 4000))));
    rt.block_on(async { svc.ready().await.unwrap().call(req).await.unwrap() })
        .status()
}

/// `n` threads, each with its own runtime, walk the clients from its own
/// offset. Returns the time per request as the average thread sees it.
fn run(layer: &RateLimitLayer, path: &'static str, n: usize, iters: u64) -> Duration {
    let start = Arc::new(Barrier::new(n));
    let threads: Vec<_> = (0..n)
        .map(|t| {
            let (layer, start) = (layer.clone(), start.clone());
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                let mut svc = layer.layer(service_fn(|_: Request<Body>| async {
                    Ok::<_, Infallible>(Response::new(Body::default()))
                }));
                let peers: Vec<PeerAddr> = (0..CLIENTS)
                    .map(|i| {
                        let ip = Ipv4Addr::from(BASE + (i + t as u32 * 1_000) % CLIENTS);
                        PeerAddr(SocketAddr::from((ip, 4000)))
                    })
                    .collect();
                start.wait();
                let began = Instant::now();
                for i in 0..iters as usize {
                    let mut req = Request::get(path).body(Body::default()).unwrap();
                    req.extensions_mut().insert(peers[i % peers.len()]);
                    rt.block_on(async { svc.ready().await.unwrap().call(req).await.unwrap() });
                }
                began.elapsed()
            })
        })
        .collect();
    let total: Duration = threads.into_iter().map(|t| t.join().unwrap()).sum();
    total / n as u32
}

/// Outside the timed loop: every case must allow its requests (a rejection
/// would time the early `Rejected` path) and reach the path it is named for.
fn verify(name: &str, layer: &RateLimitLayer, path: &str, scorer: &Flat, shared: &Mutex<Cluster>) {
    assert_eq!(
        once(layer, path),
        StatusCode::OK,
        "{name}: request rejected"
    );
    match name {
        // scoring ran, so the client is tracked and `StatusRecorder` relocks
        "detection_scoring" => {
            assert!(scorer.0.load(Ordering::Relaxed) > 0, "{name}: no scoring");
            assert_eq!(layer.clients(), 1, "{name}: client not tracked");
        }
        // the allowed request was recorded for the next sync
        "cluster" => {
            let batch = shared.lock().unwrap().take().into_batch(0);
            assert_eq!(batch.counts.len(), 1, "{name}: not recorded");
        }
        _ => {}
    }
}

/// The route bucket is its own: with a global limit that never trips, a
/// route limited to one request rejects the client's second request.
fn verify_route_bucket() {
    let tight = Limit::new(1, 1).unwrap();
    let layer = RateLimitLayer::new(route(config(), tight)).unwrap();
    assert_eq!(once(&layer, "/api/items"), StatusCode::OK);
    let second = layer.clone();
    assert_eq!(
        once(&second, "/api/items"),
        StatusCode::TOO_MANY_REQUESTS,
        "route: no own bucket"
    );
}

fn bench(c: &mut Criterion) {
    verify_route_bucket();
    let scorer = Arc::new(Flat(AtomicUsize::new(0)));
    let shared = new_cluster();
    let cases: [(&str, RateLimitConfig, &'static str); 4] = [
        ("default", config(), "/"),
        (
            "detection_scoring",
            detection(config(), scorer.clone()),
            "/",
        ),
        ("route", route(config(), huge()), "/api/items"),
        ("cluster", cluster(config(), shared.clone()), "/"),
    ];
    for (name, config, path) in cases {
        let layer = RateLimitLayer::new(config).unwrap();
        verify(name, &layer, path, &scorer, &shared);
        for n in [1, 8] {
            c.bench_function(&format!("rate_limit_call_{name}_{n}_threads"), |b| {
                b.iter_custom(|iters| run(&layer, path, n, iters))
            });
        }
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
