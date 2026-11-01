//! RFC 0029 cases 1 to 3, 8 and 10: a reload swaps the scorer and its
//! threshold, and client features survive the swap. The clock stands
//! still, so every request lands in one window.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use bytes::Bytes;
use dvarapala_engine::{Features, Limit, Scorer, TrustedProxies};
use dvarapala_l7::{PeerAddr, RateLimitConfig, RateLimitLayer, Reload, Scoring};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now() -> Instant {
    *BASE
}

fn limit() -> Limit {
    Limit::new(10_000, 10_000).unwrap()
}

fn layer(scoring: Option<Scoring>) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: limit(),
        max_clients: NonZeroUsize::new(4096).unwrap(),
        trusted: TrustedProxies::default(),
        detection: None,
        scoring,
        now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: Vec::new(),
        max_blocks: 4,
    })
    .unwrap()
}

fn reload(scoring: Option<Option<Scoring>>) -> Reload {
    Reload {
        limit: limit(),
        trusted: TrustedProxies::default(),
        enforce: false,
        attack_rate_factor: 1.0,
        challenge: None,
        fingerprints: Default::default(),
        routes: None,
        scoring,
    }
}

fn scoring(scorer: impl Scorer + 'static, threshold: f64) -> Scoring {
    Scoring {
        scorer: Arc::new(scorer),
        threshold,
    }
}

struct Fixed(f64);

impl Scorer for Fixed {
    fn score(&self, _: &Features) -> f64 {
        self.0
    }
}

/// 1 once the client sent 20 requests in the window, else 0.
struct Busy;

impl Scorer for Busy {
    fn score(&self, f: &Features) -> f64 {
        if f[0] >= 20.0 { 1.0 } else { 0.0 }
    }
}

fn inner()
-> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send> + Clone
{
    service_fn(|_req: Request<Body>| async { Ok::<_, Infallible>(Response::new(Body::default())) })
}

async fn send<S>(svc: &mut S, peer: &str) -> StatusCode
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let mut r = Request::get("/").body(Body::default()).unwrap();
    r.extensions_mut().insert(PeerAddr(
        format!("{peer}:4000").parse::<SocketAddr>().unwrap(),
    ));
    svc.ready().await.unwrap().call(r).await.unwrap().status()
}

// RFC 0029 case 1
#[tokio::test]
async fn a_new_threshold_applies_to_the_next_request() {
    let l = layer(Some(scoring(Fixed(0.2), 0.9)));
    let mut svc = l.layer(inner());
    assert_eq!(send(&mut svc, "192.0.2.1").await, StatusCode::OK);
    l.reload(reload(Some(Some(scoring(Fixed(0.2), 0.1)))))
        .unwrap();
    assert_eq!(
        send(&mut svc, "192.0.2.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// RFC 0029 cases 2 and 8: a new scorer, then `None` keeps it, then off
#[tokio::test]
async fn a_new_scorer_applies_none_keeps_it_some_none_turns_it_off() {
    let l = layer(Some(scoring(Fixed(0.2), 0.9)));
    let mut svc = l.layer(inner());
    assert_eq!(send(&mut svc, "192.0.2.1").await, StatusCode::OK);
    l.reload(reload(Some(Some(scoring(Fixed(0.99), 0.9)))))
        .unwrap();
    let throttled = StatusCode::TOO_MANY_REQUESTS;
    assert_eq!(send(&mut svc, "192.0.2.1").await, throttled);
    l.reload(reload(None)).unwrap();
    assert_eq!(send(&mut svc, "192.0.2.1").await, throttled);
    l.reload(reload(Some(None))).unwrap();
    assert_eq!(send(&mut svc, "192.0.2.1").await, StatusCode::OK);
}

// RFC 0029 case 3
#[tokio::test]
async fn features_survive_the_swap() {
    let l = layer(Some(scoring(Fixed(0.0), 0.5)));
    let mut svc = l.layer(inner());
    for _ in 0..20 {
        assert_eq!(send(&mut svc, "192.0.2.1").await, StatusCode::OK);
    }
    l.reload(reload(Some(Some(scoring(Busy, 0.5))))).unwrap();
    // the 21st request scores on the 20 before it, a new client on none
    assert_eq!(
        send(&mut svc, "192.0.2.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(send(&mut svc, "192.0.2.2").await, StatusCode::OK);
}

// RFC 0029 case 7 at the layer: scoring off at start, on after a reload
#[tokio::test]
async fn scoring_turned_on_by_a_reload_starts_the_features() {
    let l = layer(None);
    let mut svc = l.layer(inner());
    for _ in 0..30 {
        send(&mut svc, "192.0.2.1").await;
    }
    l.reload(reload(Some(Some(scoring(Busy, 0.5))))).unwrap();
    for _ in 0..19 {
        assert_eq!(send(&mut svc, "192.0.2.1").await, StatusCode::OK);
    }
    assert_eq!(
        send(&mut svc, "192.0.2.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

// RFC 0029 case 10
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn swaps_under_load_give_one_models_verdict() {
    let l = layer(Some(scoring(Fixed(0.0), 0.5)));
    let svc = l.layer(inner());
    let tasks: Vec<_> = (0..8)
        .map(|t| {
            let mut svc = svc.clone();
            tokio::spawn(async move {
                for i in 0..200 {
                    let s = send(&mut svc, &format!("198.51.{t}.{}", i % 250)).await;
                    assert!(
                        s == StatusCode::OK || s == StatusCode::TOO_MANY_REQUESTS,
                        "{s}"
                    );
                }
            })
        })
        .collect();
    for i in 0..100 {
        let score = if i % 2 == 0 { 1.0 } else { 0.0 };
        l.reload(reload(Some(Some(scoring(Fixed(score), 0.5)))))
            .unwrap();
        tokio::task::yield_now().await;
    }
    for t in tasks {
        t.await.unwrap();
    }
}
