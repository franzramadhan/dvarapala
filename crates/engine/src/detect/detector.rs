use std::fmt;
use std::hash::{BuildHasher, RandomState};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::Cidr;
use crate::detect::baseline::Baseline;
use crate::detect::entropy::Entropy;
use crate::detect::heavy::TopK;
use crate::detect::sketch::Sketch;
use crate::detect::state::{Machine, State};

/// Detector settings. `Default` holds the RFC 0002 defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectConfig {
    pub window: Duration,
    pub prefix_v4: u8,
    pub prefix_v6: u8,
    pub sketch_width: usize,
    pub sketch_depth: usize,
    pub top_k: usize,
    pub ewma_alpha: f64,
    pub warmup_windows: u32,
    pub z_threshold: f64,
    pub entropy_buckets: usize,
    pub entropy_drop: f64,
    pub trigger_windows: u32,
    pub cooldown_windows: u32,
    /// Requests per window a top-k prefix must exceed to count as a heavy
    /// hitter. The rate limit layer sets it to one client's allowance.
    pub heavy_min: u32,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(1),
            prefix_v4: 32,
            prefix_v6: 64,
            sketch_width: 2048,
            sketch_depth: 4,
            top_k: 64,
            ewma_alpha: 0.05,
            warmup_windows: 300,
            z_threshold: 4.0,
            entropy_buckets: 1024,
            entropy_drop: 0.5,
            trigger_windows: 3,
            cooldown_windows: 30,
            heavy_min: 60,
        }
    }
}

/// Fewer requests than this in a window and entropy is too noisy to judge.
// ponytail: fixed floor; make it a key if small sites need it lower
const MIN_ENTROPY_SAMPLES: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectError(pub String);

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "detection: {}", self.0)
    }
}

impl std::error::Error for DetectError {}

/// What a closed window looked like. `from` and `to` differ on a transition.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowReport {
    pub from: State,
    pub to: State,
    pub requests: u64,
    pub zscore: f64,
    /// Normalized source entropy, `[0, 1]`.
    pub entropy: f64,
    /// Heavy hitters found in the window.
    pub heavy: usize,
}

/// Feeds every observation to the sketch, top-k and entropy of the current
/// window. When a window closes, the baselines judge it and the state
/// machine moves. All memory is allocated in [`Detector::new`].
///
/// Not thread-safe; callers wrap it in a lock.
pub struct Detector {
    cfg: DetectConfig,
    hasher: RandomState,
    sketch: Sketch,
    top: TopK,
    entropy: Entropy,
    rate: Baseline,
    spread: Baseline,
    machine: Machine,
    start: Option<Instant>,
    requests: u64,
    /// heavy hitters of the last closed window, highest first
    heavy: Vec<(Cidr, u32)>,
    zscore: f64,
    norm_entropy: f64,
}

impl Detector {
    pub fn new(cfg: DetectConfig) -> Result<Self, DetectError> {
        validate(&cfg)?;
        Ok(Self {
            hasher: RandomState::new(),
            sketch: Sketch::new(cfg.sketch_width, cfg.sketch_depth),
            top: TopK::new(cfg.top_k),
            entropy: Entropy::new(cfg.entropy_buckets),
            rate: Baseline::new(cfg.ewma_alpha, cfg.warmup_windows),
            spread: Baseline::new(cfg.ewma_alpha, cfg.warmup_windows),
            machine: Machine::new(cfg.trigger_windows, cfg.cooldown_windows),
            start: None,
            requests: 0,
            heavy: Vec::with_capacity(cfg.top_k),
            zscore: 0.0,
            norm_entropy: 0.0,
            cfg,
        })
    }

    /// Records one request from `ip` at `now`. Returns a report when `now`
    /// closed one or more windows.
    pub fn observe(&mut self, ip: IpAddr, now: Instant) -> Option<WindowReport> {
        let start = *self.start.get_or_insert(now);
        let elapsed = now.saturating_duration_since(start);
        let mut report = None;
        if elapsed >= self.cfg.window {
            let w = self.cfg.window.as_nanos();
            let windows = elapsed.as_nanos() / w;
            let from = self.state();
            let mut last = self.close();
            // an idle gap is a run of empty windows; enough of them to settle
            // the state machine, not one per window of a long silence
            let cap = u128::from(self.cfg.cooldown_windows + self.cfg.trigger_windows);
            for _ in 1..windows.min(cap + 1) {
                last = self.close();
            }
            last.from = from;
            report = Some(last);
            self.start = Some(now - Duration::from_nanos((elapsed.as_nanos() % w) as u64));
        }
        let p = self.prefix(ip);
        let h = self.hasher.hash_one(p);
        let estimate = self.sketch.add(h);
        self.top.offer(p, estimate);
        self.entropy.add(h);
        self.requests += 1;
        report
    }

    fn prefix(&self, ip: IpAddr) -> Cidr {
        let ip = ip.to_canonical();
        let len = if ip.is_ipv4() {
            self.cfg.prefix_v4
        } else {
            self.cfg.prefix_v6
        };
        Cidr::of(ip, len)
    }

    /// Judges the current window, moves the state machine, starts a new one.
    fn close(&mut self) -> WindowReport {
        let requests = self.requests;
        let z = self.rate.zscore(requests as f64);
        let judge_spread = self.entropy.total() >= MIN_ENTROPY_SAMPLES;
        let perplexity = self.entropy.perplexity();
        // relative drop in the effective number of sources; a rate far below
        // normal also shrinks it, so only judge it while the rate is in band
        let spread_drop = if judge_spread && self.spread.ready() && z > -self.cfg.z_threshold {
            1.0 - perplexity / self.spread.mean()
        } else {
            0.0
        };
        let anomalous =
            self.rate.ready() && (z > self.cfg.z_threshold || spread_drop >= self.cfg.entropy_drop);
        let from = self.machine.state();
        let to = self.machine.step(anomalous);
        // learn only from normal windows outside Attack, so a flood never
        // becomes the new normal
        if !anomalous && from != State::Attack {
            self.rate.learn(requests as f64);
            if judge_spread {
                self.spread.learn(perplexity);
            }
        }
        self.zscore = z;
        self.norm_entropy = self.entropy.normalized();
        self.top.ranked_into(self.cfg.heavy_min, &mut self.heavy);
        self.sketch.clear();
        self.top.clear();
        self.entropy.clear();
        self.requests = 0;
        WindowReport {
            from,
            to,
            requests,
            zscore: z,
            entropy: self.norm_entropy,
            heavy: self.heavy.len(),
        }
    }

    pub fn state(&self) -> State {
        self.machine.state()
    }

    /// Whether `ip`'s prefix was a heavy hitter in the last closed window.
    pub fn is_heavy(&self, ip: IpAddr) -> bool {
        let p = self.prefix(ip);
        self.heavy.iter().any(|(c, _)| *c == p)
    }

    /// Heavy hitters of the last closed window, highest first.
    pub fn heavy(&self) -> &[(Cidr, u32)] {
        &self.heavy
    }

    /// Rate z-score of the last closed window.
    pub fn zscore(&self) -> f64 {
        self.zscore
    }

    /// Normalized source entropy of the last closed window.
    pub fn entropy(&self) -> f64 {
        self.norm_entropy
    }
}

fn validate(c: &DetectConfig) -> Result<(), DetectError> {
    let checks = [
        (c.window.is_zero(), "window must be above zero"),
        (c.prefix_v4 > 32, "prefix_v4 must be at most 32"),
        // client keys keep only the /64 of an IPv6 address
        (c.prefix_v6 > 64, "prefix_v6 must be at most 64"),
        (c.sketch_width == 0, "sketch_width must be at least 1"),
        (c.sketch_depth == 0, "sketch_depth must be at least 1"),
        (c.top_k == 0, "top_k must be at least 1"),
        (
            !(c.ewma_alpha > 0.0 && c.ewma_alpha <= 1.0),
            "ewma_alpha must be in (0, 1]",
        ),
        (
            c.z_threshold.is_nan() || c.z_threshold <= 0.0,
            "z_threshold must be above zero",
        ),
        (c.entropy_buckets < 2, "entropy_buckets must be at least 2"),
        (
            !(c.entropy_drop > 0.0 && c.entropy_drop <= 1.0),
            "entropy_drop must be in (0, 1]",
        ),
        (c.trigger_windows == 0, "trigger_windows must be at least 1"),
        (
            c.cooldown_windows == 0,
            "cooldown_windows must be at least 1",
        ),
    ];
    match checks.iter().find(|(bad, _)| *bad) {
        Some((_, msg)) => Err(DetectError((*msg).into())),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i))
    }

    #[test]
    fn baseline_frozen_during_attack() {
        // 10 s windows: an hour of flood in 360 windows keeps the test fast
        let cfg = DetectConfig {
            window: Duration::from_secs(10),
            warmup_windows: 10,
            ..DetectConfig::default()
        };
        let mut d = Detector::new(cfg).unwrap();
        let t0 = Instant::now();
        let mut w = 0u32;
        let mut window = |d: &mut Detector, n: u32| {
            let t = t0 + Duration::from_secs(10 * u64::from(w));
            for i in 0..n {
                d.observe(ip(i), t);
            }
            w += 1;
        };
        for _ in 0..20 {
            window(&mut d, 300);
        }
        let mean = d.rate.mean();
        for _ in 0..360 {
            window(&mut d, 3000);
        }
        assert_eq!(d.state(), State::Attack);
        assert_eq!(d.rate.mean(), mean);
    }

    #[test]
    fn idle_gap_closes_empty_windows() {
        let cfg = DetectConfig {
            warmup_windows: 1,
            trigger_windows: 1,
            cooldown_windows: 2,
            ..DetectConfig::default()
        };
        let mut d = Detector::new(cfg).unwrap();
        let t0 = Instant::now();
        for i in 0..300 {
            d.observe(ip(i), t0);
        }
        for i in 0..30_000 {
            d.observe(ip(i), t0 + Duration::from_secs(1));
        }
        d.observe(ip(0), t0 + Duration::from_secs(2));
        assert_eq!(d.state(), State::Attack);
        // an hour of silence: the gap counts as normal windows
        let r = d.observe(ip(0), t0 + Duration::from_secs(3600)).unwrap();
        assert_eq!((r.from, r.to), (State::Attack, State::Normal));
    }

    #[test]
    fn rejects_bad_config() {
        let bad = [
            DetectConfig {
                window: Duration::ZERO,
                ..Default::default()
            },
            DetectConfig {
                prefix_v4: 33,
                ..Default::default()
            },
            DetectConfig {
                prefix_v6: 65,
                ..Default::default()
            },
            DetectConfig {
                sketch_width: 0,
                ..Default::default()
            },
            DetectConfig {
                sketch_depth: 0,
                ..Default::default()
            },
            DetectConfig {
                top_k: 0,
                ..Default::default()
            },
            DetectConfig {
                ewma_alpha: 0.0,
                ..Default::default()
            },
            DetectConfig {
                ewma_alpha: 1.5,
                ..Default::default()
            },
            DetectConfig {
                z_threshold: 0.0,
                ..Default::default()
            },
            DetectConfig {
                entropy_buckets: 1,
                ..Default::default()
            },
            DetectConfig {
                entropy_drop: 0.0,
                ..Default::default()
            },
            DetectConfig {
                trigger_windows: 0,
                ..Default::default()
            },
            DetectConfig {
                cooldown_windows: 0,
                ..Default::default()
            },
        ];
        for c in bad {
            assert!(Detector::new(c.clone()).is_err(), "{c:?}");
        }
        assert!(Detector::new(DetectConfig::default()).is_ok());
    }
}
