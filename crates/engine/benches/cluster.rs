//! Issue 308: `Cluster::check` over 10 000 listed heavy hitters.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{Cidr, Cluster, ClusterConfig, Limit, Reply};

fn check(c: &mut Criterion) {
    let now = Instant::now();
    let mut cl = Cluster::new(ClusterConfig {
        limit: Some(Limit::new(10, 5).unwrap()),
        window: Duration::from_secs(10),
        max_keys: 10_000,
        max_clients: 10_000,
    });
    let heavy = (0..10_000u32)
        .map(|i| {
            let net = Cidr::of(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i)), 32);
            (net, Duration::from_secs(30))
        })
        .collect();
    cl.apply(
        Reply {
            heavy,
            ..Reply::default()
        },
        now,
        0,
    );
    // a miss: no prefix length matches
    let key = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)).into();
    c.bench_function("cluster_check_10000", |b| {
        b.iter(|| black_box(cl.check(black_box(key), now)))
    });
}

criterion_group!(benches, check);
criterion_main!(benches);
