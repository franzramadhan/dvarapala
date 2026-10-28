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
static OBJECT: &[u8] = include_bytes!("../dvarapala-xdp.o");
const PROGRAM: &str = "dvarapala_xdp";

fn err(what: &str) -> impl Fn(&dyn fmt::Display) -> XdpError + '_ {
    move |e| XdpError(format!("{what}: {e}"))
}

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
        let allow = u32::try_from(cfg.allow.len().max(1)).unwrap_or(u32::MAX);
        let mut ebpf = EbpfLoader::new()
            .map_max_entries("ALLOW", allow)
            .map_max_entries("BLOCK", cfg.max_blocks.max(1))
            .map_max_entries("SOURCES", cfg.max_sources.max(1))
            .load(OBJECT)
            .map_err(|e| err("load")(&e))?;
        let mut config: Array<MapData, Config> = take(&mut ebpf, "CONFIG")?;
        config
            .set(
                0,
                &Config {
                    pps: Rate::new(cfg.pps, cfg.burst),
                    syn: Rate::new(cfg.syn_pps, cfg.burst),
                    udp: Rate::new(cfg.udp_pps, cfg.burst),
                    tcp_port: cfg.tcp_port,
                    udp_port: cfg.udp_port,
                    enforce: u8::from(cfg.enforce),
                    prefix_v4: cfg.prefix_v4,
                    prefix_v6: cfg.prefix_v6,
                    _pad: 0,
                },
                0,
            )
            .map_err(|e| err("config")(&e))?;
        let mut allow: LpmTrie<MapData, [u8; 16], u8> = take(&mut ebpf, "ALLOW")?;
        for net in &cfg.allow {
            let (len, k) = key(*net);
            allow
                .insert(&Key::new(len, k), &1, 0)
                .map_err(|e| err("xdp.allow")(&e))?;
        }
        let mut block: LpmTrie<MapData, [u8; 16], u64> = take(&mut ebpf, "BLOCK")?;
        for net in &cfg.block {
            let (len, k) = key(*net);
            block
                .insert(&Key::new(len, k), &0, 0)
                .map_err(|e| err("xdp.block")(&e))?;
        }
        let counts = take(&mut ebpf, "COUNTS")?;
        let program: &mut XdpProgram = ebpf
            .program_mut(PROGRAM)
            .ok_or_else(|| XdpError(format!("no program {PROGRAM}")))?
            .try_into()
            .map_err(|e| err("program")(&e))?;
        program.load().map_err(|e| err("verifier")(&e))?;
        let blocks = Blocks::new(cfg.max_blocks as usize, cfg.block.iter().copied());
        Ok(Self {
            ebpf,
            state: Mutex::new(State {
                block,
                counts,
                blocks,
            }),
            ttl: cfg.block_ttl.as_nanos() as u64,
            mode: None,
        })
    }

    /// Attaches to `interface`; the mode it got, `"native"` or
    /// `"generic"`. Needs `CAP_NET_ADMIN`.
    pub fn attach(&mut self, interface: &str, attach: Attach) -> Result<&'static str, XdpError> {
        let name = CString::new(interface).map_err(|e| err("xdp.interface")(&e))?;
        let program: &mut XdpProgram = self
            .ebpf
            .program_mut(PROGRAM)
            .and_then(|p| p.try_into().ok())
            .ok_or_else(|| XdpError(format!("no program {PROGRAM}")))?;
        let mode = match attach {
            Attach::Native => program_attach(program, &name, XdpMode::Driver).map(|()| "native"),
            Attach::Generic => program_attach(program, &name, XdpMode::Skb).map(|()| "generic"),
            Attach::Auto => match program_attach(program, &name, XdpMode::Driver) {
                Ok(()) => Ok("native"),
                Err(e) => {
                    tracing::warn!(msg = "xdp generic mode", interface, error = %e, "the driver has no native XDP, slower");
                    program_attach(program, &name, XdpMode::Skb).map(|()| "generic")
                }
            },
        }
        .map_err(|e| XdpError(format!("xdp.interface {interface:?}: {e}")))?;
        self.mode = Some(mode);
        tracing::info!(msg = "xdp attached", interface, mode);
        Ok(mode)
    }

    /// Blocks `net` for `xdp.block_ttl`: a heavy hitter or a client over
    /// the accept rate. A no-op while it is already listed.
    pub fn block(&self, net: Cidr) {
        if self.ttl == 0 {
            return;
        }
        let mut s = self.lock();
        let now = now();
        let until = now + self.ttl;
        let Add::Write { evicted } = s.blocks.add(net, now, self.ttl) else {
            return;
        };
        if let Some(old) = evicted {
            let (len, k) = key(old);
            let _ = s.block.remove(&Key::new(len, k));
        }
        let (len, k) = key(net);
        if let Err(e) = s.block.insert(&Key::new(len, k), &until, 0) {
            tracing::warn!(%net, error = %e, "xdp block");
        }
    }

    /// Removes expired blocks and exports the counters; once a second.
    pub fn tick(&self) {
        // looked up per tick: the recorder may come after attach
        if let Some(mode) = self.mode {
            metrics::gauge!("dvarapala_xdp_attached", "mode" => mode).set(1.0);
        }
        let mut s = self.lock();
        for net in s.blocks.expire(now()) {
            let (len, k) = key(net);
            let _ = s.block.remove(&Key::new(len, k));
        }
        metrics::gauge!("dvarapala_xdp_blocks").set(s.blocks.len() as f64);
        let counts = counts(&s.counts);
        for (a, action) in ACTIONS {
            for (r, reason) in REASONS {
                let n = counts[counter(a, r) as usize];
                if n > 0 {
                    metrics::counter!("dvarapala_xdp_packets_total", "action" => action, "reason" => reason)
                        .absolute(n);
                }
            }
        }
    }

    /// Entries in the block trie, static and dynamic.
    pub fn blocks(&self) -> usize {
        self.lock().blocks.len()
    }

    /// The counters summed over CPUs, indexed by [`counter`].
    pub fn counts(&self) -> [u64; COUNTERS as usize] {
        counts(&self.lock().counts)
    }

    /// Runs the program once on `frame` (`BPF_PROG_TEST_RUN`): the XDP
    /// action. For tests.
    pub fn run(&self, frame: &[u8]) -> Result<u32, XdpError> {
        let program: &XdpProgram = self
            .ebpf
            .program(PROGRAM)
            .and_then(|p| p.try_into().ok())
            .ok_or_else(|| XdpError(format!("no program {PROGRAM}")))?;
        let r = program
            .test_run(TestRunOptions {
                data_in: Some(frame),
                ..TestRunOptions::default()
            })
            .map_err(|e| err("test run")(&e))?;
        Ok(r.return_value)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn take<T: TryFrom<aya::maps::Map>>(ebpf: &mut Ebpf, name: &str) -> Result<T, XdpError>
where
    T::Error: fmt::Display,
{
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| XdpError(format!("no map {name}")))?;
    T::try_from(map).map_err(|e| err(name)(&e))
}

fn program_attach(p: &mut XdpProgram, name: &CString, mode: XdpMode) -> Result<(), String> {
    p.attach(name.as_c_str(), mode)
        .map(drop)
        .map_err(|e| e.to_string())
}

fn counts(m: &PerCpuArray<MapData, u64>) -> [u64; COUNTERS as usize] {
    let mut out = [0; COUNTERS as usize];
    for (i, n) in out.iter_mut().enumerate() {
        if let Ok(per_cpu) = m.get(&(i as u32), 0) {
            *n = per_cpu.iter().sum();
        }
    }
    out
}

/// `CLOCK_MONOTONIC` in ns, the clock of `bpf_ktime_get_ns`.
fn now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid out pointer
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
