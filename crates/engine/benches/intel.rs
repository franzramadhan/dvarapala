//! RFC 0031 case 2: `PrefixSet::contains` over 100 000 prefixes under 200 ns.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{Cidr, PrefixSet};

fn contains(c: &mut Criterion) {
    // every other network, so none merge
    let v4 = (0..90_000u32).map(|i| Cidr::of(Ipv4Addr::from(0x0a00_0000 + (i << 9)).into(), 24));
    let v6 = (0..10_000u128).map(|i| {
        Cidr::of(
            Ipv6Addr::from((0x2001_0db8u128 << 96) | (i << 81)).into(),
            48,
        )
    });
    let set = PrefixSet::new(v4.chain(v6));
    let hit = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
    let miss = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1));
    c.bench_function("intel_contains_100k_hit", |b| {
        b.iter(|| black_box(set.contains(black_box(hit))))
    });
    c.bench_function("intel_contains_100k_miss", |b| {
        b.iter(|| black_box(set.contains(black_box(miss))))
    });
}

criterion_group!(benches, contains);
criterion_main!(benches);
