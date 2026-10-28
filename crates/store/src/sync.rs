#![allow(unused_variables, unused_imports, unused_mut, dead_code)]
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
        todo!("rfc 0010")
    }
    /// Good rounds.
    pub fn rounds(&self) -> u64 {
        todo!("rfc 0010")
    }
    pub fn failures(&self) -> u64 {
        todo!("rfc 0010")
    }
    /// Lines logged for the store going away and coming back.
    pub fn logged(&self) -> u64 {
        todo!("rfc 0010")
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
    todo!("rfc 0010")
}

async fn run<S: Store>(
    mut store: S,
    cluster: Arc<Mutex<Cluster>>,
    cfg: SyncConfig,
    status: Arc<Status>,
) {
    todo!("rfc 0010")
}

fn unix_ms() -> u64 {
    todo!("rfc 0010")
}
