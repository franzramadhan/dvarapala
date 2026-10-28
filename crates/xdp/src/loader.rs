#![allow(unused_variables, unused_imports, dead_code)]
use std::ffi::CString;
use std::fmt;
use std::sync::{Mutex, PoisonError};

use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, MapData, PerCpuArray};
use aya::programs::{TestRun, TestRunOptions, Xdp as XdpProgram, XdpMode};
use aya::{Ebpf, EbpfLoader};
use dvarapala_engine::Cidr;
use dvarapala_xdp_common::{ACTIONS, COUNTERS, Config, REASONS, Rate, counter};

use crate::maps::{Add, Blocks, key};
use crate::{Attach, XdpConfig, XdpError};

/// Built from `crates/xdp-ebpf` (see its `rust-toolchain.toml`); CI
/// rebuilds it and fails when it differs.
static OBJECT: &[u8] = &[];
const PROGRAM: &str = "dvarapala_xdp";

/// The loaded program and its maps. Dropping it detaches the program: the
/// link is a file descriptor of this process, so a kill detaches it too.
pub struct Xdp {
    ebpf: Ebpf,
    state: Mutex<State>,
    ttl: u64,
    /// `"native"` or `"generic"` once attached
    mode: Option<&'static str>,
}

struct State {
    block: LpmTrie<MapData, [u8; 16], u64>,
    counts: PerCpuArray<MapData, u64>,
    blocks: Blocks,
}

impl Xdp {
    /// Loads the program with `cfg`, not attached yet. Needs `CAP_BPF`.
    pub fn load(cfg: &XdpConfig) -> Result<Self, XdpError> {
        todo!("rfc 0011")
    }

    /// Attaches to `interface`; the mode it got, `"native"` or
    /// `"generic"`. Needs `CAP_NET_ADMIN`.
    pub fn attach(&mut self, interface: &str, attach: Attach) -> Result<&'static str, XdpError> {
        todo!("rfc 0011")
    }

    /// Blocks `net` for `xdp.block_ttl`: a heavy hitter or a client over
    /// the accept rate. A no-op while it is already listed.
    pub fn block(&self, net: Cidr) {
        todo!("rfc 0011")
    }

    /// Removes expired blocks and exports the counters; once a second.
    pub fn tick(&self) {
        todo!("rfc 0011")
    }

    /// Entries in the block trie, static and dynamic.
    pub fn blocks(&self) -> usize {
        todo!("rfc 0011")
    }

    /// The counters summed over CPUs, indexed by [`counter`].
    pub fn counts(&self) -> [u64; COUNTERS as usize] {
        todo!("rfc 0011")
    }

    /// Runs the program once on `frame` (`BPF_PROG_TEST_RUN`): the XDP
    /// action. For tests.
    pub fn run(&self, frame: &[u8]) -> Result<u32, XdpError> {
        todo!("rfc 0011")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        todo!("rfc 0011")
    }
}

fn take<T: TryFrom<aya::maps::Map>>(ebpf: &mut Ebpf, name: &str) -> Result<T, XdpError>
where
    T::Error: fmt::Display,
{
    todo!("rfc 0011")
}

fn program_attach(p: &mut XdpProgram, name: &CString, mode: XdpMode) -> Result<(), String> {
    todo!("rfc 0011")
}

fn counts(m: &PerCpuArray<MapData, u64>) -> [u64; COUNTERS as usize] {
    todo!("rfc 0011")
}

/// `CLOCK_MONOTONIC` in ns, the clock of `bpf_ktime_get_ns`.
fn now() -> u64 {
    todo!("rfc 0011")
}
