//! RFC 0032 case 14: admit and release, alone and on 8 threads, next to
//! the floor of one shared counter on 8 threads.

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use dvarapala_engine::{Class, Concurrency, ConcurrencyConfig, LimitMode, Outcome, Priority};

fn admit_release(c: &mut Criterion) {
    for (name, mode, limit) in [
        ("", LimitMode::Gradient, 0),
        ("fixed_", LimitMode::Fixed, 1000),
    ] {
        pair(c, name, mode, limit);
    }
    floor(c);
}

fn pair(c: &mut Criterion, name: &str, mode: LimitMode, limit: u32) {
    let config = ConcurrencyConfig {
        mode,
        limit,
        min: 1000,
        max: 1000,
        window: Duration::from_secs(1),
        reserve: 0.2,
    };
    let limiter = Arc::new(Concurrency::new(config, Instant::now()).unwrap());
    let p = Priority {
        class: Class::Normal,
        weight: 1,
    };
    let latency = Outcome::Answered(Duration::from_millis(5));
    for n in [1, 8] {
        c.bench_function(
            &format!("concurrency_{name}admit_release_{n}_threads"),
            |b| {
                b.iter_custom(|iters| {
                    // each thread times its own loop, after a barrier, so thread
                    // spawns stay out of the measurement
                    let start = Arc::new(Barrier::new(n));
                    let threads: Vec<_> = (0..n)
                        .map(|_| {
                            let (l, start) = (limiter.clone(), start.clone());
                            std::thread::spawn(move || {
                                start.wait();
                                let t = Instant::now();
                                for _ in 0..iters {
                                    if let Some(w) = l.admit(black_box(p)) {
                                        l.release(w, latency, Instant::now());
                                    }
                                }
                                t.elapsed()
                            })
                        })
                        .collect();
                    // time per pair, as the average thread sees it
                    let total: Duration = threads.into_iter().map(|t| t.join().unwrap()).sum();
                    total / n as u32
                })
            },
        );
    }
}

fn floor(c: &mut Criterion) {
    // the floor: one shared counter taken and given back, no limit
    let counter = Arc::new(std::sync::atomic::AtomicU32::new(0));
    c.bench_function("shared_counter_8_threads", |b| {
        b.iter_custom(|iters| {
            let start = Arc::new(Barrier::new(8));
            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let (c, start) = (counter.clone(), start.clone());
                    std::thread::spawn(move || {
                        use std::sync::atomic::Ordering::Relaxed;
                        start.wait();
                        let t = Instant::now();
                        for _ in 0..iters {
                            black_box(c.fetch_add(1, Relaxed));
                            c.fetch_sub(1, Relaxed);
                        }
                        t.elapsed()
                    })
                })
                .collect();
            // time per pair, as the average thread sees it
            let total: Duration = threads.into_iter().map(|t| t.join().unwrap()).sum();
            total / 8
        })
    });
}

criterion_group!(benches, admit_release);
criterion_main!(benches);
