//! RFC 0002 cases 19 to 21, 26, 29 and 30: detection and scoring in the
//! rate limit layer. A per-thread fake clock drives the windows.

use std::cell::Cell;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{DetectConfig, Features, Limit, Scorer, TrustedProxies};
use dvarapala_l7::{Detection, PeerAddr, RateLimitConfig, RateLimitLayer, Scoring};
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Empty<Bytes>;

static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

thread_local! {
    static MS: Cell<u64> = const { Cell::new(0) };
}

fn now() -> Instant {
    *BASE + Duration::from_millis(MS.get())
}

fn at(ms: u64) {
    MS.set(ms);
}

fn inner() -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone {
    service_fn(|_req: Request<Body>| async { Ok::<_, Infallible>(Response::new(Body::new())) })
}

/// rate 4/s, burst 1. Detection alarms after one window of warmup and
/// enters `Attack` on the first anomalous window.
fn layer(enforce: bool, prefix_v4: u8, scoring: Option<Scoring>) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(4, 1).unwrap(),
        max_clients: NonZeroUsize::new(4096).unwrap(),
        trusted: TrustedProxies::default(),
        detection: Some(Detection {
            detect: DetectConfig {
                prefix_v4,
                warmup_windows: 1,
                trigger_windows: 1,
                ..DetectConfig::default()
            },
            enforce,
            attack_rate_factor: 0.25,
        }),
        scoring,
        now,
    })
    .unwrap()
}

async fn send<S>(svc: &mut S, peer: &str) -> StatusCode
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let mut r = Request::get("/").body(Body::new()).unwrap();
    r.extensions_mut().insert(PeerAddr(
        format!("{peer}:4000").parse::<SocketAddr>().unwrap(),
    ));
    svc.ready().await.unwrap().call(r).await.unwrap().status()
}

/// Window 0: 10 normal clients. Window 1: 1000 requests from 192.0.2.10.
/// Leaves the clock at the start of window 2; the next request closes
/// window 1 and the detector is in `Attack` with 192.0.2.10 as heavy hitter.
async fn flood<S>(svc: &mut S)
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    at(0);
    for i in 0..10 {
        send(svc, &format!("198.51.100.{i}")).await;
    }
    at(1000);
    for _ in 0..1000 {
        send(svc, "192.0.2.10").await;
    }
    at(2000);
}

#[tokio::test]
async fn observe_mode_changes_no_verdict() {
    let mut svc = layer(false, 32, None).layer(inner());
    flood(&mut svc).await;
    assert_eq!(send(&mut svc, "192.0.2.10").await, StatusCode::OK);
}

#[tokio::test]
async fn enforce_drops_heavy_hitter() {
    let mut svc = layer(true, 32, None).layer(inner());
    flood(&mut svc).await;
    assert_eq!(send(&mut svc, "192.0.2.10").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn enforce_slows_every_other_client() {
    for (enforce, second) in [
        (false, StatusCode::OK),
        (true, StatusCode::TOO_MANY_REQUESTS),
    ] {
        let mut svc = layer(enforce, 32, None).layer(inner());
        flood(&mut svc).await;
        assert_eq!(send(&mut svc, "198.51.100.50").await, StatusCode::OK);
        // 500 ms refills 2 tokens at 4/s, half a token at 1/s
        at(2500);
        assert_eq!(
            send(&mut svc, "198.51.100.50").await,
            second,
            "enforce={enforce}"
        );
    }
}

#[tokio::test]
async fn default_grouping_spares_the_neighbor() {
    let mut svc = layer(true, 32, None).layer(inner());
    flood(&mut svc).await;
    assert_eq!(send(&mut svc, "192.0.2.11").await, StatusCode::OK);
}

#[tokio::test]
async fn slash_24_grouping_drops_the_neighbor() {
    let mut svc = layer(true, 24, None).layer(inner());
    flood(&mut svc).await;
    assert_eq!(send(&mut svc, "192.0.2.11").await, StatusCode::FORBIDDEN);
}

struct Fixed(f64);

impl Scorer for Fixed {
    fn score(&self, _: &Features) -> f64 {
        self.0
    }
}

#[tokio::test]
async fn score_over_threshold_throttles() {
    for (score, want) in [(0.95, StatusCode::TOO_MANY_REQUESTS), (0.5, StatusCode::OK)] {
        let scoring = Scoring {
            scorer: Arc::new(Fixed(score)),
            threshold: 0.9,
        };
        let mut svc = layer(true, 32, Some(scoring)).layer(inner());
        at(0);
        assert_eq!(send(&mut svc, "198.51.100.1").await, want, "score {score}");
    }
}

/// Scores the client's 4xx share.
struct ErrorShare;

impl Scorer for ErrorShare {
    fn score(&self, f: &Features) -> f64 {
        f[7]
    }
}

#[tokio::test]
async fn response_status_feeds_the_features() {
    let scoring = Scoring {
        scorer: Arc::new(ErrorShare),
        threshold: 0.5,
    };
    let not_found = service_fn(|_req: Request<Body>| async {
        let mut r = Response::new(Body::new());
        *r.status_mut() = StatusCode::NOT_FOUND;
        Ok::<_, Infallible>(r)
    });
    let mut svc = layer(true, 32, Some(scoring)).layer(not_found);
    at(0);
    assert_eq!(send(&mut svc, "198.51.100.1").await, StatusCode::NOT_FOUND);
    at(1000);
    assert_eq!(
        send(&mut svc, "198.51.100.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}
