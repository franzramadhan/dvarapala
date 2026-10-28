//! RFC 0009 case 14: memory of the per-client table. Opens one connection
//! for each of `DVARAPALA_CLIENTS` (default 100000) distinct addresses and
//! reports the heap the table took per client, counted by the allocator.
//!
//! `cargo bench -p dvarapala-l4 --bench conns_table`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use dvarapala_engine::{Conns, ConnsConfig};

/// RFC 0009 implementation notes: measured about 106 bytes, budget 160.
const BUDGET_PER_CLIENT: usize = 160;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator, only counting sizes
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size(), Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn main() {
    let n: usize = std::env::var("DVARAPALA_CLIENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000)
        .min(1 << 17);
    let before = LIVE.load(Ordering::Relaxed);
    let mut conns = Conns::new(ConnsConfig {
        max_clients: NonZeroUsize::new(n).unwrap(),
        ..ConnsConfig::default()
    })
    .unwrap();
    let now = Instant::now();
    for i in 0..n as u32 {
        // distinct /32s in 198.18.0.0/15, the benchmarking range (RFC 2544)
        let ip = IpAddr::V4(Ipv4Addr::from(0xc612_0000 + i));
        conns.open(ip, now).unwrap();
    }
    assert_eq!(conns.clients(), n);
    let per = (LIVE.load(Ordering::Relaxed) - before) / n;
    println!("{n} clients: {per} bytes per client (budget {BUDGET_PER_CLIENT})");
    assert!(per <= BUDGET_PER_CLIENT, "over budget");
}
