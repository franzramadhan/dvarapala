//! RFC 0010 cases 5 to 11, once per backend. Redis and PostgreSQL run
//! when `DVARAPALA_TEST_REDIS`, `DVARAPALA_TEST_POSTGRES` and
//! `DVARAPALA_TEST_PGBOUNCER` hold their URLs (CI services).

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use common::{INTERVAL, Replica, replica, unique, unix_ms, until};
use dvarapala_engine::{
    Cidr, ClientKey, Cluster, ClusterConfig, Guard, GuardConfig, Limit, Schedule, ScheduleConfig,
    Slot, Verdict, overshoot, split,
};
use dvarapala_store::{Memory, Store};

struct Backend<S> {
    make: Box<dyn Fn() -> S + Send + Sync>,
    down: Box<dyn Fn(bool) + Send + Sync>,
}

fn memory() -> Backend<Memory> {
    let m = Memory::default();
    let d = m.clone();
    Backend {
        make: Box::new(move || m.clone()),
        down: Box::new(move |down| d.set_down(down)),
    }
}

#[cfg(feature = "redis")]
async fn redis() -> Option<Backend<dvarapala_store::Redis>> {
    let url = common::url("DVARAPALA_TEST_REDIS")?;
    let gate = common::Gate::new(common::target(&url)).await;
    let url = common::through(&url, gate.addr);
    Some(Backend {
        make: Box::new(move || dvarapala_store::Redis::new(&url, None).unwrap()),
        down: Box::new(move |down| gate.set_open(!down)),
    })
}

#[cfg(feature = "postgres")]
async fn postgres(var: &str) -> Option<Backend<dvarapala_store::Postgres>> {
    let url = common::url(var)?;
    let gate = common::Gate::new(common::target(&url)).await;
    let url = common::through(&url, gate.addr);
    Some(Backend {
        make: Box::new(move || {
            dvarapala_store::Postgres::new(&url, None, true, Duration::from_millis(500)).unwrap()
        }),
        down: Box::new(move |down| gate.set_open(!down)),
    })
}

fn key() -> ClientKey {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)).into()
}

fn config(limit: Option<Limit>, window: Duration) -> ClusterConfig {
    ClusterConfig {
        limit,
        window,
        max_keys: 10_000,
        max_clients: 100_000,
    }
}

fn lock(r: &Replica) -> std::sync::MutexGuard<'_, Cluster> {
    r.cluster.lock().unwrap()
}

/// Two replicas on one store under one fresh cluster name, both seeing
/// each other.
async fn pair<S: Store>(b: &Backend<S>, cfg: ClusterConfig) -> (Replica, Replica) {
    let name = unique("c");
    let a = replica((b.make)(), &name, cfg.clone());
    let c = replica((b.make)(), &name, cfg);
    let both = until(Duration::from_secs(5), || {
        lock(&a).replicas() == 2 && lock(&c).replicas() == 2
    })
    .await;
    assert!(both, "replicas never saw each other");
    (a, c)
}

// case 5
async fn round_robin_client_is_held_to_one_limit<S: Store>(b: Backend<S>) {
    let window = Duration::from_secs(2);
    let limit = Limit::new(10, 10).unwrap();
    let (a, c) = pair(&b, config(Some(limit), window)).await;
    let guard = || {
        Guard::<()>::new(GuardConfig {
            limit,
            max_clients: NonZeroUsize::new(10).unwrap(),
            detection: None,
        })
        .unwrap()
    };
    let mut local = [guard(), guard()];
    // start at a window boundary so the run counts in one window
    while unix_ms() % 2000 > 50 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let end = unix_ms() - unix_ms() % 2000 + 1950;
    let mut passed = 0;
    let mut i = 0;
    while unix_ms() < end {
        i += 1;
        let r = if i % 2 == 0 { &a } else { &c };
        let now = Instant::now();
        let cluster = lock(r).check(key(), now);
        if cluster.is_none() && local[i % 2].check(key(), now).verdict == Verdict::Allow {
            lock(r).record(key());
            passed += 1;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // without the store each replica lets about 10 + 19 through
    let bound = limit.allowance(window) + overshoot(10.0, 2, INTERVAL * 2);
    assert!(f64::from(passed) <= bound, "{passed} passed, bound {bound}");
}

// case 6
async fn forward_budget_holds_across_replicas<S: Store>(b: Backend<S>) {
    let (a, c) = pair(&b, config(None, Duration::from_secs(1))).await;
    let base = ScheduleConfig {
        rate: 10.0,
        burst: 2,
        max_queue: 0,
        ..ScheduleConfig::default()
    };
    let mut schedules = [&a, &c].map(|r| {
        let (share, _) = split(&base, 0, lock(r).replicas());
        Schedule::new(share).unwrap()
    });
    let start = Instant::now();
    let mut sent = 0;
    // both callers at 100 rps for 1 s
    for i in 0..200 {
        let at = start + Duration::from_millis(i / 2 * 10);
        if schedules[(i % 2) as usize].reserve(at, 0) == Slot::Now {
            sent += 1;
        }
    }
    assert!(sent <= 10 + 2, "{sent} sent");
}

// case 7
async fn provider_pause_reaches_the_other_replica<S: Store>(b: Backend<S>) {
    let (a, c) = pair(&b, config(None, Duration::from_secs(1))).await;
    lock(&a).publish_pause("api", Duration::from_secs(2));
    let paused = until(Duration::from_secs(2), || {
        lock(&c).pause("api", Instant::now()).is_some()
    })
    .await;
    assert!(paused);
    assert!(lock(&c).pause("api", Instant::now()).unwrap() <= Duration::from_secs(2));
}

// case 8
async fn heavy_hitter_is_dropped_everywhere<S: Store>(b: Backend<S>) {
    let (a, c) = pair(&b, config(None, Duration::from_secs(1))).await;
    let net: Cidr = "192.0.2.0/24".parse().unwrap();
    lock(&a).publish_heavy([net], Duration::from_secs(30));
    let dropped = until(Duration::from_secs(2), || {
        lock(&c).check(key(), Instant::now()) == Some(Verdict::Drop)
    })
    .await;
    assert!(dropped);
}

// cases 9 and 10
async fn lost_store_fails_open_and_recovers<S: Store>(b: Backend<S>) {
    let (a, _c) = pair(&b, config(None, Duration::from_secs(1))).await;
    assert!(a.status.up());
    (b.down)(true);
    assert!(until(Duration::from_secs(3), || !a.status.up()).await);
    // the request path never waits: a check is a map lookup
    let t = Instant::now();
    assert_eq!(lock(&a).check(key(), t), None);
    assert!(t.elapsed() < Duration::from_millis(5));
    let failures = a.status.failures();
    assert!(
        until(Duration::from_secs(3), || a.status.failures()
            > failures + 1)
        .await
    );
    assert_eq!(a.status.logged(), 1, "one store unavailable line");
    assert_eq!(lock(&a).replicas(), 2, "last replica count kept");
    (b.down)(false);
    assert!(until(Duration::from_secs(5), || a.status.up()).await);
    assert_eq!(a.status.logged(), 2, "one store recovered line");
}

// case 11
async fn max_keys_bounds_a_round<S: Store>(b: Backend<S>) {
    let mut cluster = Cluster::new(config(
        Some(Limit::new(10, 10).unwrap()),
        Duration::from_secs(1),
    ));
    for i in 0..50_000u32 {
        let k: ClientKey = IpAddr::V4(Ipv4Addr::from(0xc000_0000 + i)).into();
        for _ in 0..=(i % 3) {
            cluster.record(k);
        }
    }
    let batch = cluster.drain(unix_ms());
    assert_eq!((batch.counts.len(), batch.dropped), (10_000, 40_000));
    assert!(batch.counts.iter().all(|(_, n)| *n == 3), "busiest first");
    let mut store = (b.make)();
    let round = dvarapala_store::Round {
        cluster: &unique("c"),
        replica: "r",
        heartbeat: Duration::from_secs(1),
        window: Duration::from_secs(1),
        max_list: 10,
        batch: &batch,
    };
    // the first round of a PostgreSQL backend also connects and migrates
    let _ = store
        .round(&dvarapala_store::Round {
            batch: &Default::default(),
            ..round
        })
        .await
        .unwrap();
    let t = Instant::now();
    let reply = store.round(&round).await.unwrap();
    assert!(
        t.elapsed() < Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(reply.totals.len(), 10_000);
}

macro_rules! cases {
    ($backend:ident, $make:expr, $($case:ident),*) => {
        mod $backend {
            #[allow(unused_imports)]
            use super::*;
            $(
                #[tokio::test(flavor = "multi_thread")]
                #[ignore = "rfc 0010"]
                async fn $case() {
                    #[allow(clippy::redundant_closure_call)]
                    let Some(b) = ($make)().await else { return };
                    super::$case(b).await
                }
            )*
        }
    };
}

macro_rules! all_cases {
    ($backend:ident, $make:expr) => {
        cases!(
            $backend,
            $make,
            round_robin_client_is_held_to_one_limit,
            forward_budget_holds_across_replicas,
            provider_pause_reaches_the_other_replica,
            heavy_hitter_is_dropped_everywhere,
            lost_store_fails_open_and_recovers,
            max_keys_bounds_a_round
        );
    };
}

all_cases!(memory, || async { Some(super::memory()) });
#[cfg(feature = "redis")]
all_cases!(redis, super::redis);
#[cfg(feature = "postgres")]
all_cases!(postgres, || super::postgres("DVARAPALA_TEST_POSTGRES"));
// case 23: through PgBouncer in transaction mode
#[cfg(feature = "postgres")]
cases!(
    pgbouncer,
    || super::postgres("DVARAPALA_TEST_PGBOUNCER"),
    round_robin_client_is_held_to_one_limit,
    lost_store_fails_open_and_recovers
);
