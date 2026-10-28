//! The RFC 0011 XDP program. Per packet to a protected port: the allow
//! trie passes, the block trie drops, then the per-source rates. Every
//! other packet passes untouched.
//!
//! Build (nightly from `rust-toolchain.toml`, `bpf-linker` 0.12 on PATH):
//! `cargo build --locked --release` here, then copy
//! `target/bpfel-unknown-none/release/dvarapala-xdp` to
//! `crates/xdp/dvarapala-xdp.o`. CI rebuilds it and fails on a difference.

#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::maps::{Array, LpmTrie, LruHashMap, PerCpuArray};
use aya_ebpf::programs::XdpContext;
use dvarapala_xdp_common::{Action, Bytes, COUNTERS, Config, Proto, Reason, counter, parse};

#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

/// Addresses (IPv4 mapped into IPv6) never dropped.
#[map]
static ALLOW: LpmTrie<[u8; 16], u8> = LpmTrie::with_max_entries(4096, 0);

/// Value: expiry in `bpf_ktime_get_ns` time, 0 for a static entry. The
/// loader sets the size from `xdp.max_blocks`.
#[map]
static BLOCK: LpmTrie<[u8; 16], u64> = LpmTrie::with_max_entries(65536, 0);

/// Per source prefix: the GCRA arrival times of `pps`, `syn_pps` and
/// `udp_pps`. Sized from `xdp.max_sources`.
#[map]
static SOURCES: LruHashMap<[u8; 16], [u64; 3]> = LruHashMap::with_max_entries(1 << 20, 0);

#[map]
static COUNTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNTERS, 0);

struct Packet<'a>(&'a XdpContext);

impl Bytes for Packet<'_> {
    #[inline(always)]
    fn get<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let start = self.0.data() + off;
        if start + N > self.0.data_end() {
            return None;
        }
        // SAFETY: checked against the packet end above
        Some(unsafe { (start as *const [u8; N]).read_unaligned() })
    }
}

#[xdp]
pub fn dvarapala_xdp(ctx: XdpContext) -> u32 {
    let Some(cfg) = CONFIG.get(0) else {
        return XDP_PASS;
    };
    match parse(&Packet(&ctx)) {
        Some(p) if cfg.protects(&p) => check(cfg, &p),
        _ => count(Action::Pass, Reason::Other, XDP_PASS),
    }
}

#[inline(always)]
fn check(cfg: &Config, p: &dvarapala_xdp_common::Packet) -> u32 {
    let key = Key::new(128, p.src);
    if ALLOW.get(&key).is_some() {
        return count(Action::Pass, Reason::Allow, XDP_PASS);
    }
    // SAFETY: a helper without arguments
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(&until) = BLOCK.get(&key) {
        if until == 0 || until > now {
            return refuse(cfg, Reason::Block);
        }
    }
    let src = cfg.source(p);
    let tats = match SOURCES.get_ptr_mut(&src) {
        Some(t) => t,
        None => {
            if SOURCES.insert(&src, &[0; 3], 0).is_err() {
                return count(Action::Pass, Reason::Other, XDP_PASS);
            }
            match SOURCES.get_ptr_mut(&src) {
                Some(t) => t,
                None => return count(Action::Pass, Reason::Other, XDP_PASS),
            }
        }
    };
    // SAFETY: a map value pointer, valid for this run. Concurrent CPUs
    // may race on one source: a few packets more or less, never unsafe.
    let tats = unsafe { &mut *tats };
    if !cfg.pps.admit(&mut tats[0], now) {
        return refuse(cfg, Reason::Pps);
    }
    match p.proto {
        Proto::Tcp { syn: true } if !cfg.syn.admit(&mut tats[1], now) => refuse(cfg, Reason::Syn),
        Proto::Udp if !cfg.udp.admit(&mut tats[2], now) => refuse(cfg, Reason::Udp),
        _ => count(Action::Pass, Reason::Other, XDP_PASS),
    }
}

#[inline(always)]
fn refuse(cfg: &Config, r: Reason) -> u32 {
    if cfg.enforce == 1 {
        count(Action::Drop, r, XDP_DROP)
    } else {
        count(Action::WouldDrop, r, XDP_PASS)
    }
}

#[inline(always)]
fn count(a: Action, r: Reason, verdict: u32) -> u32 {
    if let Some(n) = COUNTS.get_ptr_mut(counter(a, r)) {
        // SAFETY: this CPU's slot
        unsafe { *n += 1 };
    }
    verdict
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
