//! RFC 0002 cases 4 and 28: detector memory is fixed at creation and stays
//! under 256 KB with the defaults. One test per binary: the allocator
//! counter is global.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dvarapala_engine::{DetectConfig, Detector};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);

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
static A: Counting = Counting;

#[test]
#[ignore = "rfc 0002 cases 4 and 28"]
fn detector_memory_is_fixed_and_small() {
    let before = LIVE.load(Ordering::Relaxed);
    let mut d = Detector::new(DetectConfig::default()).unwrap();
    let after_new = LIVE.load(Ordering::Relaxed) - before;
    assert!(after_new < 256 * 1024, "{after_new} bytes");

    let t0 = Instant::now();
    for i in 0..1_000_000u32 {
        // ten windows of 100k distinct sources each
        let now = t0 + Duration::from_secs(u64::from(i / 100_000));
        d.observe(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i)), now);
    }
    let after_flood = LIVE.load(Ordering::Relaxed) - before;
    assert_eq!(after_flood, after_new, "memory grew with distinct sources");
}
