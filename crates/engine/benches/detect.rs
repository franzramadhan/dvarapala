//! RFC 0002 case 27: `Detector::observe` under 200 ns per observation.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{DetectConfig, Detector};

fn observe(c: &mut Criterion) {
    let mut d = Detector::new(DetectConfig::default()).unwrap();
    let t0 = Instant::now();
    let mut i = 0u64;
    c.bench_function("detector_observe", |b| {
        b.iter(|| {
            i += 1;
            // 100k req/s: a new window every 100k observations
            let now = t0 + Duration::from_micros(i * 10);
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | (i as u32 & 0xf_ffff)));
            black_box(d.observe(ip, now));
        })
    });
}

criterion_group!(benches, observe);
criterion_main!(benches);
