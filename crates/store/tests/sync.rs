//! The sync task's own bounds (RFC 0010).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use dvarapala_engine::{Cluster, ClusterConfig, Reply};
use dvarapala_store::{Error, Memory, Round, Store, SyncConfig, spawn};

/// A store whose first connect is slower than one round timeout, like a
/// PostgreSQL replica waiting for another one's migration.
struct SlowConnect {
    inner: Memory,
    connected: bool,
}

impl Store for SlowConnect {
    async fn connect(&mut self) -> Result<(), Error> {
        if !self.connected {
            tokio::time::sleep(Duration::from_millis(300)).await;
            self.connected = true;
        }
        Ok(())
    }

    // like the PostgreSQL backend: a round connects when it has to
    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        self.connect().await?;
        self.inner.round(r).await
    }
}

#[tokio::test]
async fn a_slow_first_connect_is_not_a_failed_round() {
    let cluster = Arc::new(Mutex::new(Cluster::new(ClusterConfig {
        limit: None,
        window: Duration::from_secs(1),
        max_keys: 10,
        max_clients: 10,
    })));
    let store = SlowConnect {
        inner: Memory::default(),
        connected: false,
    };
    let (_task, status) = spawn(
        store,
        cluster,
        SyncConfig {
            cluster: "c".into(),
            replica: "r".into(),
            interval: Duration::from_millis(50),
            timeout: Duration::from_millis(100),
            max_list: 10,
        },
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(status.up());
    assert!(status.rounds() > 0);
    assert_eq!(status.failures(), 0);
    assert_eq!(status.logged(), 0, "no store unavailable line");
}

/// A store that never answers: in `connect`, or in `round`.
struct Hangs {
    in_connect: bool,
}

impl Store for Hangs {
    async fn connect(&mut self) -> Result<(), Error> {
        if self.in_connect {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn round(&mut self, _: &Round<'_>) -> Result<Reply, Error> {
        std::future::pending().await
    }
}

fn cluster(max_keys: usize) -> Arc<Mutex<Cluster>> {
    Arc::new(Mutex::new(Cluster::new(ClusterConfig {
        limit: None,
        window: Duration::from_secs(1),
        max_keys,
        max_clients: 10,
    })))
}

fn config() -> SyncConfig {
    SyncConfig {
        cluster: "c".into(),
        replica: "r".into(),
        interval: Duration::from_millis(10),
        timeout: Duration::from_millis(10),
        max_list: 10,
    }
}

#[tokio::test]
async fn a_store_that_hangs_fails_open_once_logged() {
    for in_connect in [true, false] {
        let (task, status) = spawn(Hangs { in_connect }, cluster(10), config());
        tokio::time::sleep(Duration::from_millis(400)).await;
        task.abort();
        assert!(!status.up(), "in_connect {in_connect}");
        assert!(status.failures() > 0, "in_connect {in_connect}");
        assert_eq!(status.rounds(), 0);
        assert_eq!(status.logged(), 1, "one store unavailable line");
    }
}

#[tokio::test]
async fn a_round_over_max_keys_still_syncs() {
    let c = cluster(1);
    for i in 1..=3u8 {
        let k: dvarapala_engine::ClientKey =
            std::net::IpAddr::from([192, 0, 2, i]).into();
        c.lock().unwrap().record(k);
    }
    let (task, status) = spawn(Memory::default(), c, config());
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    assert!(status.up());
    assert!(status.rounds() > 0);
}
