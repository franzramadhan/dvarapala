use std::fmt;
use std::hash::RandomState;
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
    pub fn new(_cfg: DetectConfig) -> Result<Self, DetectError> {
        todo!("rfc 0002")
    }

    /// Records one request from `ip` at `now`. Returns a report when `now`
    /// closed one or more windows.
    pub fn observe(&mut self, _ip: IpAddr, _now: Instant) -> Option<WindowReport> {
        todo!("rfc 0002")
    }

    pub fn state(&self) -> State {
        self.machine.state()
    }

    /// Whether `ip`'s prefix was a heavy hitter in the last closed window.
    pub fn is_heavy(&self, _ip: IpAddr) -> bool {
        todo!("rfc 0002")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(i: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0x0a00_0000 | i))
    }

    #[test]
    #[ignore = "rfc 0002 case 8"]
    fn baseline_frozen_during_attack() {
        let cfg = DetectConfig {
            warmup_windows: 10,
            ..DetectConfig::default()
        };
        let mut d = Detector::new(cfg).unwrap();
        let t0 = Instant::now();
        let mut w = 0u32;
        let mut window = |d: &mut Detector, n: u32| {
            let t = t0 + Duration::from_secs(u64::from(w));
            for i in 0..n {
                d.observe(ip(i), t);
            }
            w += 1;
        };
        for _ in 0..20 {
            window(&mut d, 300);
        }
        let mean = d.rate.mean();
        for _ in 0..3600 {
            window(&mut d, 3000);
        }
        assert_eq!(d.state(), State::Attack);
        assert_eq!(d.rate.mean(), mean);
    }

    #[test]
    #[ignore = "rfc 0002"]
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
    #[ignore = "rfc 0002"]
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
