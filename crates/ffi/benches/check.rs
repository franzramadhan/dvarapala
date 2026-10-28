//! RFC 0008 case 14: `dv_check` through the ABI with the default config
//! under 1 µs per call.

use std::ffi::CString;
use std::hint::black_box;
use std::ptr;

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala::{DvVerdict, dv_check, dv_config_free, dv_config_new, dv_guard_free, dv_guard_new};

fn check(c: &mut Criterion) {
    // 10k clients from 198.18.0.0/15 (RFC 2544), as text the way a host has them
    let ips: Vec<CString> = (0..10_000u32)
        .map(|i| CString::new(format!("198.18.{}.{}", i / 256, i % 256)).unwrap())
        .collect();
    // SAFETY: pointers from the ABI itself, freed once below
    unsafe {
        let cfg = dv_config_new();
        let g = dv_guard_new(cfg);
        dv_config_free(cfg);
        let mut out = DvVerdict {
            kind: 0,
            retry_after_ms: 0,
        };
        let mut i = 0;
        c.bench_function("dv_check", |b| {
            b.iter(|| {
                i = (i + 1) % ips.len();
                black_box(dv_check(g, ips[i].as_ptr(), ptr::null(), &mut out));
            })
        });
        dv_guard_free(g);
    }
}

criterion_group!(benches, check);
criterion_main!(benches);
