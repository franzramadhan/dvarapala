use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dvarapala_engine::Cluster;
use tokio::task::JoinHandle;

use crate::{Round, Store};

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub cluster: String,
    /// Unique per running replica.
    pub replica: String,
    pub interval: Duration,
    /// A round slower than this fails.
    pub timeout: Duration,
    /// Listed heavy hitters and pauses read back at most.
    pub max_list: usize,
}

/// What the sync task last saw, for tests and health checks.
#[derive(Debug, Default)]
pub struct Status {
    up: AtomicBool,
    rounds: AtomicU64,
    failures: AtomicU64,
    /// `store unavailable` and `store recovered` lines logged
    logged: AtomicU64,
}

impl Status {
    pub fn up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
    /// Good rounds.
    pub fn rounds(&self) -> u64 {
        self.rounds.load(Ordering::Acquire)
    }
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Acquire)
    }
    /// Lines logged for the store going away and coming back.
    pub fn logged(&self) -> u64 {
        self.logged.load(Ordering::Acquire)
    }
}

/// Starts the sync task on the current runtime: the first round right
/// away, then one every `interval`, backing off up to `interval x 10`
/// while the store fails. Fails open: on error the cluster keeps its last
/// view, which expires, and local limits go on.
pub fn spawn<S: Store>(
    store: S,
    cluster: Arc<Mutex<Cluster>>,
    cfg: SyncConfig,
) -> (JoinHandle<()>, Arc<Status>) {
    let status = Arc::new(Status::default());
    let task = tokio::spawn(run(store, cluster, cfg, status.clone()));
    (task, status)
}

async fn run<S: Store>(
    mut store: S,
    cluster: Arc<Mutex<Cluster>>,
    cfg: SyncConfig,
    status: Arc<Status>,
) {
    let lock = || cluster.lock().unwrap_or_else(PoisonError::into_inner);
    let window = lock().window();
    let mut delay = Duration::ZERO;
    let mut down_logged = false;
    loop {
        tokio::time::sleep(delay).await;
        let batch = lock().drain(unix_ms());
        if batch.dropped > 0 {
            metrics::counter!("dvarapala_store_keys_dropped_total").increment(batch.dropped);
        }
        let round = Round {
            cluster: &cfg.cluster,
            replica: &cfg.replica,
            heartbeat: cfg.interval * 3,
            window,
            max_list: cfg.max_list,
            batch: &batch,
        };
        let start = Instant::now();
        let result = match tokio::time::timeout(cfg.timeout, store.round(&round)).await {
            Ok(r) => r.map_err(|e| e.0),
            Err(_) => Err(format!("round over {:?}", cfg.timeout)),
        };
        metrics::histogram!("dvarapala_store_sync_seconds").record(start.elapsed().as_secs_f64());
        match result {
            Ok(reply) => {
                let replicas = reply.replicas;
                lock().apply(reply, Instant::now(), unix_ms());
                metrics::gauge!("dvarapala_store_replicas").set(f64::from(replicas));
                // looked up per round: the recorder may come after spawn
                metrics::gauge!("dvarapala_store_up").set(1.0);
                status.up.store(true, Ordering::Release);
                status.rounds.fetch_add(1, Ordering::AcqRel);
                if down_logged {
                    down_logged = false;
                    status.logged.fetch_add(1, Ordering::AcqRel);
                    tracing::info!(msg = "store recovered");
                }
                delay = cfg.interval;
            }
            Err(error) => {
                metrics::counter!("dvarapala_store_sync_errors_total").increment(1);
                metrics::gauge!("dvarapala_store_up").set(0.0);
                status.up.store(false, Ordering::Release);
                status.failures.fetch_add(1, Ordering::AcqRel);
                if !down_logged {
                    down_logged = true;
                    status.logged.fetch_add(1, Ordering::AcqRel);
                    tracing::warn!(msg = "store unavailable", %error, "local limits only");
                }
                delay = (delay * 2).clamp(cfg.interval, cfg.interval * 10);
            }
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
