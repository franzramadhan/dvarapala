use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use crate::{
    ClientKey, DetectConfig, DetectError, Detector, Limit, State, Table, Verdict, WindowReport,
};

/// Adaptive detection on top of the per-client limit (RFC 0002).
#[derive(Debug, Clone)]
pub struct GuardDetection {
    pub detect: DetectConfig,
    /// `false` (observe) reports only; `true` changes verdicts.
    pub enforce: bool,
    /// Bucket rate multiplier for every client while in `Attack`, `(0, 1]`.
    pub attack_rate_factor: f64,
}

#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub limit: Limit,
    pub max_clients: NonZeroUsize,
    /// `None` turns detection off.
    pub detection: Option<GuardDetection>,
}

/// The decision for one request and what the caller reports about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub verdict: Verdict,
    /// Observe mode: enforce mode would have dropped this request.
    pub would_drop: bool,
    /// A detection window closed on this request.
    pub report: Option<WindowReport>,
    /// Clients evicted from the table by this request.
    pub evicted: u64,
}

/// The per-request decision shared by the `tower` layer and the C ABI
/// (RFC 0008): a bounded per-client table of buckets, the detector and the
/// attack limit. `V` is extra per-client state the caller keeps in the
/// table (the scorer's stats in `l7`). Time is an input.
///
/// Not thread-safe; callers wrap it in a lock.
pub struct Guard<V = ()> {
    table: Table<ClientKey, V>,
    detector: Option<Detector>,
    limit: Limit,
    /// `limit` with the refill scaled by `attack_rate_factor`
    attack_limit: Limit,
    enforce: bool,
}

impl<V: Default> Guard<V> {
    /// Fails on a detection config the engine rejects.
    pub fn new(config: GuardConfig) -> Result<Self, DetectError> {
        let (detector, enforce, attack_limit) = match config.detection {
            Some(GuardDetection {
                mut detect,
                enforce,
                attack_rate_factor: f,
            }) => {
                if !(f > 0.0 && f <= 1.0) {
                    return Err(DetectError("attack_rate_factor must be in (0, 1]".into()));
                }
                // a heavy hitter sent more than one client may in a window
                detect.heavy_min = config.limit.allowance(detect.window).ceil() as u32;
                (
                    Some(Detector::new(detect)?),
                    enforce,
                    config.limit.scaled(f),
                )
            }
            None => (None, false, config.limit),
        };
        Ok(Self {
            table: Table::new(config.max_clients),
            detector,
            limit: config.limit,
            attack_limit,
            enforce,
        })
    }

    /// The verdict for one request from `key` at `now`.
    pub fn check(&mut self, key: ClientKey, now: Instant) -> Decision {
        let (report, attack, heavy) = match self.detector.as_mut() {
            Some(d) => {
                let report = d.observe(key.into(), now);
                let attack = d.state() == State::Attack;
                (report, attack, attack && d.is_heavy(key.into()))
            }
            None => (None, false, false),
        };
        let before = self.table.evictions();
        let verdict = if heavy && self.enforce {
            Verdict::Drop
        } else if attack && self.enforce {
            self.table.take(key, &self.attack_limit, now)
        } else {
            self.table.take(key, &self.limit, now)
        };
        Decision {
            verdict,
            would_drop: heavy && !self.enforce,
            report,
            evicted: self.table.evictions() - before,
        }
    }

    /// The caller's state for `key`, when it is in the table.
    pub fn get_mut(&mut self, key: &ClientKey) -> Option<&mut V> {
        self.table.get_mut(key)
    }

    /// Clients in the table.
    pub fn clients(&self) -> usize {
        self.table.len()
    }

    pub fn evictions(&self) -> u64 {
        self.table.evictions()
    }

    pub fn detector(&self) -> Option<&Detector> {
        self.detector.as_ref()
    }

    /// The detection window, 1 s without detection.
    pub fn window(&self) -> Duration {
        self.detector
            .as_ref()
            .map_or(Duration::from_secs(1), Detector::window)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn key(last: u8) -> ClientKey {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)).into()
    }

    fn guard(rate: u32, burst: u32) -> Guard {
        Guard::new(GuardConfig {
            limit: Limit::new(rate, burst).unwrap(),
            max_clients: NonZeroUsize::new(2).unwrap(),
            detection: None,
        })
        .unwrap()
    }

    #[test]
    fn limits_per_client() {
        let mut g = guard(1, 2);
        let t = Instant::now();
        let v: Vec<_> = (0..3).map(|_| g.check(key(1), t).verdict).collect();
        assert_eq!(v[..2], [Verdict::Allow; 2]);
        assert!(
            matches!(v[2], Verdict::Throttle { retry_after } if retry_after <= Duration::from_secs(1))
        );
        // another client has its own bucket
        assert_eq!(g.check(key(2), t).verdict, Verdict::Allow);
    }

    #[test]
    fn bounded_table_counts_evictions() {
        let mut g = guard(1, 1);
        let t = Instant::now();
        assert_eq!(g.check(key(1), t).evicted, 0);
        assert_eq!(g.check(key(2), t).evicted, 0);
        assert_eq!(g.check(key(3), t).evicted, 1);
        assert_eq!((g.clients(), g.evictions()), (2, 1));
    }

    #[test]
    fn rejects_bad_attack_factor() {
        for f in [0.0, 1.5, f64::NAN] {
            let r = Guard::<()>::new(GuardConfig {
                limit: Limit::new(1, 1).unwrap(),
                max_clients: NonZeroUsize::new(2).unwrap(),
                detection: Some(GuardDetection {
                    detect: DetectConfig::default(),
                    enforce: true,
                    attack_rate_factor: f,
                }),
            });
            assert!(r.is_err(), "{f}");
        }
    }
}
