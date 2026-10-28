//! RFC 0010 case 15: one sync round for 10 000 clients. The memory backend
//! always; Redis and PostgreSQL on loopback when `DVARAPALA_TEST_REDIS` or
//! `DVARAPALA_TEST_POSTGRES` is set. Target: under 5 ms.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{Cluster, ClusterConfig, Limit};
use dvarapala_store::{Memory, Round, Store};

fn cluster() -> Cluster {
    let mut c = Cluster::new(ClusterConfig {
        limit: Some(Limit::new(20, 40).unwrap()),
        window: Duration::from_secs(10),
        max_keys: 10_000,
        max_clients: 10_000,
    });
    for i in 0..10_000u32 {
        c.record(IpAddr::V4(Ipv4Addr::from(0xc000_0200 + i)).into());
    }
    c
}

fn bench_store<S: Store>(c: &mut Criterion, name: &str, mut store: S) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut cl = cluster();
    let batch = cl.drain(0);
    c.bench_function(&format!("sync round 10k keys ({name})"), |b| {
        b.iter(|| {
            let reply = rt
                .block_on(store.round(&Round {
                    cluster: "bench",
                    replica: "r",
                    heartbeat: Duration::from_secs(3),
                    window: Duration::from_secs(10),
                    max_list: 1_000,
                    batch: &batch,
                }))
                .unwrap();
            cl.apply(black_box(reply), Instant::now(), 0);
        })
    });
}

fn benches(c: &mut Criterion) {
    c.bench_function("drain 10k keys", |b| {
        b.iter_batched(
            cluster,
            |mut cl| black_box(cl.drain(0)),
            criterion::BatchSize::LargeInput,
        )
    });
    bench_store(c, "memory", Memory::default());
    #[cfg(feature = "redis")]
    if let Ok(url) = std::env::var("DVARAPALA_TEST_REDIS") {
        bench_store(c, "redis", dvarapala_store::Redis::new(&url, None).unwrap());
    }
    #[cfg(feature = "postgres")]
    if let Ok(url) = std::env::var("DVARAPALA_TEST_POSTGRES") {
        let pg = dvarapala_store::Postgres::new(&url, None, true, Duration::from_secs(5)).unwrap();
        bench_store(c, "postgres", pg);
    }
}

criterion_group!(group, benches);
criterion_main!(group);
