//! RFC 0014 case 14: `Blocks::contains` over 4096 networks under 2 us.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{Blocks, Cidr};

fn contains(c: &mut Criterion) {
    let now = Instant::now();
    let mut b = Blocks::new(4096);
    for i in 0..4096u32 {
        let net = Cidr::of(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | (i << 8))), 24);
        b.add(net, now + Duration::from_secs(600), now).unwrap();
    }
    // a miss scans every entry: the worst case
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    c.bench_function("blocks_contains_4096", |bn| {
        bn.iter(|| black_box(b.contains(black_box(ip), now)))
    });
}

criterion_group!(benches, contains);
criterion_main!(benches);
