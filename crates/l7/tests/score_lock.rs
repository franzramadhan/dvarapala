//! Issue 306: the scorer runs outside the rate limiter's lock, so a model
//! walk does not stall every other request in the process.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Features, Limit, Scorer, TrustedProxies};
use dvarapala_l7::{PeerAddr, RateLimitConfig, RateLimitLayer, Scoring};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now() -> Instant {
    *BASE
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

fn inner()
-> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send> + Clone
{
    service_fn(|_req: Request<Body>| async { Ok::<_, Infallible>(Response::new(Body::default())) })
}

/// On its first call, sends a request for another client from a second
/// thread and records whether that request finished while it still runs.
struct Probe {
    layer: OnceLock<RateLimitLayer>,
    probing: AtomicBool,
    free: Mutex<Option<bool>>,
}

impl Scorer for Probe {
    fn score(&self, _: &Features) -> f64 {
        if self.probing.swap(true, Ordering::SeqCst) {
            return 0.0;
        }
        let layer = self.layer.get().unwrap().clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let mut svc = layer.layer(inner());
            rt.block_on(send(&mut svc, "192.0.2.2"));
            let _ = tx.send(());
        });
        let done = rx.recv_timeout(Duration::from_secs(2)).is_ok();
        *self.free.lock().unwrap() = Some(done);
        0.0
    }
}

#[tokio::test]
async fn the_scorer_runs_without_the_limiter_lock() {
    let probe = Arc::new(Probe {
        layer: OnceLock::new(),
        probing: AtomicBool::new(false),
        free: Mutex::new(None),
    });
    let l = RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(10_000, 10_000).unwrap(),
        max_clients: NonZeroUsize::new(4096).unwrap(),
        trusted: TrustedProxies::default(),
        detection: None,
        scoring: Some(Scoring {
            scorer: probe.clone(),
            threshold: 0.9,
        }),
        now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: Vec::new(),
        max_blocks: 4,
        priority: None,
    })
    .unwrap();
    probe.layer.set(l.clone()).ok();
    let mut svc = l.layer(inner());
    assert_eq!(send(&mut svc, "192.0.2.1").await, StatusCode::OK);
    assert_eq!(*probe.free.lock().unwrap(), Some(true));
}
