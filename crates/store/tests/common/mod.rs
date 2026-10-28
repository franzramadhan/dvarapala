#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{Cluster, ClusterConfig};
use dvarapala_store::{Status, Store, SyncConfig, spawn};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub const INTERVAL: Duration = Duration::from_millis(100);
pub const TIMEOUT: Duration = Duration::from_millis(500);

/// A test service URL from `var`. Unset skips the test locally and fails
/// it in CI, where the services run.
pub fn url(var: &str) -> Option<String> {
    match std::env::var(var) {
        Ok(u) => Some(u),
        Err(_) if std::env::var_os("CI").is_some() => panic!("{var} is not set in CI"),
        Err(_) => {
            eprintln!("skipped: {var} is not set");
            None
        }
    }
}

/// A name no other test uses.
pub fn unique(prefix: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{prefix}{}x{}",
        t % 1_000_000_000_000,
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// A TCP forwarder in front of a service that can be shut, as if the
/// service went away, and opened again.
pub struct Gate {
    pub addr: SocketAddr,
    open: Arc<AtomicBool>,
    conns: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Gate {
    pub async fn new(target: SocketAddr) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let open = Arc::new(AtomicBool::new(true));
        let conns: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let (o, c) = (open.clone(), conns.clone());
        tokio::spawn(async move {
            while let Ok((mut down, _)) = l.accept().await {
                // under the lock set_open takes: a connection is either
                // refused or registered before a close drains the list
                let mut conns = c.lock().unwrap();
                if !o.load(Ordering::Acquire) {
                    continue;
                }
                conns.push(tokio::spawn(async move {
                    if let Ok(mut up) = TcpStream::connect(target).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                }));
            }
        });
        Self { addr, open, conns }
    }

    pub fn set_open(&self, open: bool) {
        let mut conns = self.conns.lock().unwrap();
        self.open.store(open, Ordering::Release);
        if !open {
            for c in conns.drain(..) {
                c.abort();
            }
        }
    }
}

fn hostport(url: &str) -> &str {
    let rest = url.split("://").nth(1).unwrap();
    rest.rsplit('@')
        .next()
        .unwrap()
        .split(['/', '?'])
        .next()
        .unwrap()
}

/// The host and port of a `scheme://user:pass@host:port/...` URL.
pub fn target(url: &str) -> SocketAddr {
    std::net::ToSocketAddrs::to_socket_addrs(hostport(url))
        .unwrap()
        .next()
        .unwrap()
}

/// `url` with its host and port replaced by `addr`.
pub fn through(url: &str, addr: SocketAddr) -> String {
    url.replacen(hostport(url), &addr.to_string(), 1)
}

/// One simulated replica: its cluster view and its sync task.
pub struct Replica {
    pub cluster: Arc<Mutex<Cluster>>,
    pub status: Arc<Status>,
    task: JoinHandle<()>,
}

impl Drop for Replica {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn replica<S: Store>(store: S, cluster: &str, cfg: ClusterConfig) -> Replica {
    let c = Arc::new(Mutex::new(Cluster::new(cfg)));
    let (task, status) = spawn(
        store,
        c.clone(),
        SyncConfig {
            cluster: cluster.to_owned(),
            replica: unique("r"),
            interval: INTERVAL,
            timeout: TIMEOUT,
            max_list: 10_000,
        },
    );
    Replica {
        cluster: c,
        status,
        task,
    }
}

/// Waits until `f` holds, checking every 10 ms, at most `max`.
pub async fn until(max: Duration, f: impl Fn() -> bool) -> bool {
    let end = tokio::time::Instant::now() + max;
    while tokio::time::Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
