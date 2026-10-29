//! RFC 0002 cases 19 to 21, 26, 29 and 30: detection and scoring in the
//! rate limit layer. A per-thread fake clock drives the windows.

use std::cell::Cell;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{
    BlockSink, Cluster, ClusterConfig, DetectConfig, Features, Limit, Reply, Scorer, TrustedProxies,
};
use dvarapala_l7::{Detection, PeerAddr, RateLimitConfig, RateLimitLayer, Scoring};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

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
    service_fn(|_req: Request<Body>| async { Ok::<_, Infallible>(Response::new(Body::default())) })
}

/// rate 4/s, burst 1. Detection alarms after one window of warmup and
/// enters `Attack` on the first anomalous window.
fn layer(enforce: bool, prefix_v4: u8, scoring: Option<Scoring>) -> RateLimitLayer {
    layer_in(enforce, prefix_v4, scoring, None, None)
}

fn layer_in(
    enforce: bool,
    prefix_v4: u8,
    scoring: Option<Scoring>,
    cluster: Option<Arc<Mutex<Cluster>>>,
    block: Option<BlockSink>,
) -> RateLimitLayer {
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
        cluster,
        block,
        challenge: None,
        fingerprints: Default::default(),
    })
    .unwrap()
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
        let mut r = Response::new(Body::default());
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

fn cluster() -> Arc<Mutex<Cluster>> {
    Arc::new(Mutex::new(Cluster::new(ClusterConfig {
        limit: Some(Limit::new(4, 1).unwrap()),
        window: Duration::from_secs(10),
        max_keys: 100,
        max_clients: 100,
    })))
}

// RFC 0010: the cluster's verdict comes before the local bucket, allowed
// requests are counted for the next sync
#[tokio::test]
async fn cluster_verdicts_come_first() {
    let c = cluster();
    let mut svc = layer_in(false, 32, None, Some(c.clone()), None).layer(inner());
    at(0);
    assert_eq!(send(&mut svc, "192.0.2.20").await, StatusCode::OK);
    let batch = c.lock().unwrap().drain(0);
    assert_eq!(batch.counts.len(), 1);
    assert_eq!(batch.counts[0].1, 1);
    let key = batch.counts[0].0;
    c.lock().unwrap().apply(
        Reply {
            replicas: 2,
            totals: vec![(key, 1_000)],
            heavy: vec![("198.51.100.0/24".parse().unwrap(), Duration::from_secs(30))],
            ..Reply::default()
        },
        now(),
        0,
    );
    at(5000);
    assert_eq!(
        send(&mut svc, "192.0.2.20").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(send(&mut svc, "198.51.100.1").await, StatusCode::FORBIDDEN);
    assert_eq!(send(&mut svc, "203.0.113.1").await, StatusCode::OK);
}

// RFC 0010 case 8: heavy hitters are published in enforce mode only
#[tokio::test]
async fn heavy_hitters_are_published_while_enforcing() {
    for enforce in [false, true] {
        let c = cluster();
        let mut svc = layer_in(enforce, 32, None, Some(c.clone()), None).layer(inner());
        flood(&mut svc).await;
        send(&mut svc, "203.0.113.1").await;
        let heavy = c.lock().unwrap().drain(0).heavy;
        let listed = heavy.iter().any(|(n, _)| n.to_string() == "192.0.2.10/32");
        assert_eq!(listed, enforce, "enforce = {enforce}");
    }
}

// RFC 0011: heavy hitters reach the XDP block sink in enforce mode only
#[tokio::test]
async fn heavy_hitters_reach_the_block_sink_while_enforcing() {
    for enforce in [false, true] {
        let seen: Arc<Mutex<Vec<String>>> = Arc::default();
        let s = seen.clone();
        let sink = BlockSink::new(move |c| s.lock().unwrap().push(c.to_string()));
        let mut svc = layer_in(enforce, 32, None, None, Some(sink)).layer(inner());
        flood(&mut svc).await;
        send(&mut svc, "203.0.113.1").await;
        let listed = seen.lock().unwrap().iter().any(|n| n == "192.0.2.10/32");
        assert_eq!(listed, enforce, "enforce = {enforce}");
    }
}
