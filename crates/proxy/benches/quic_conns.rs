//! RFC 0036 case 13: opening and closing QUIC connections with 10000
//! clients in the per-client table; the cost per connection is the RFC 0009
//! one.

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::ConnsConfig;
use dvarapala_proxy::quic::ClientLimits;

const CLIENTS: u32 = 10_000;

fn ip(i: u32) -> IpAddr {
    // distinct /32s in 198.18.0.0/15, the benchmarking range (RFC 2544)
    IpAddr::V4(Ipv4Addr::from(0xc612_0000 + i))
}

fn open_close(c: &mut Criterion) {
    let limits = ClientLimits::new(&ConnsConfig {
        max_clients: NonZeroUsize::new(CLIENTS as usize).unwrap(),
        ..ConnsConfig::default()
    })
    .unwrap();
    let _held: Vec<_> = (0..CLIENTS).map(|i| limits.admit(ip(i)).unwrap()).collect();
    let mut i = 0;
    c.bench_function("quic_conns/open_close", |b| {
        b.iter(|| {
            i = (i + 1) % CLIENTS;
            drop(limits.admit(ip(i)).unwrap());
        });
    });
}

criterion_group!(benches, open_close);
criterion_main!(benches);
