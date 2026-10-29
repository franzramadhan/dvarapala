//! RFC 0015 case 11: one least requests pick over 16 endpoints, budget
//! 100 ns.

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_proxy::{Balance, Pool, PoolConfig};

fn bench(c: &mut Criterion) {
    let mut config = PoolConfig::single("http://192.0.2.1");
    config.upstreams = (1..=16).map(|i| format!("http://192.0.2.{i}")).collect();
    config.balance = Balance::LeastRequests;
    let pool = Pool::new(config).unwrap();
    c.bench_function("pool_pick_least_requests_16", |b| {
        b.iter(|| pool.pick(std::hint::black_box(None)))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
