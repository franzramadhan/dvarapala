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
    /// When a request without a pass gets `Challenge` (RFC 0012).
    pub challenge: ChallengeMode,
}

/// When a request without a pass gets `Challenge` (RFC 0012).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChallengeMode {
    /// Never.
    #[default]
    Off,
    /// While detection is in `Attack` and enforcing.
    Attack,
    /// On every request.
    Always,
}

/// What the caller knows about a request's challenge pass (RFC 0012).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Pass {
    /// No pass; the mode decides.
    #[default]
    Missing,
    /// A valid pass: no challenge, and the normal limit during an attack.
    Valid,
    /// No pass, and a rule asks for one whatever the detector says.
    Required,
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
    challenge: ChallengeMode,
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
            challenge: config.challenge,
        })
    }

    /// The verdict for one request from `key` at `now`, without a pass.
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

    /// The verdict for one request from `key` at `now`. The bucket comes
    /// first, so a client without a pass gets `Challenge` only within its
    /// limit; heavy hitters are dropped with or without one.
    pub fn check_passed(&mut self, key: ClientKey, now: Instant, pass: Pass) -> Decision {
        let _ = (key, now, pass, self.challenge);
        todo!("rfc 0012")
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
            challenge: ChallengeMode::Off,
        })
        .unwrap()
    }

    fn challenging(mode: ChallengeMode, enforce: bool) -> Guard {
        Guard::new(GuardConfig {
            limit: Limit::new(10, 20).unwrap(),
            max_clients: NonZeroUsize::new(1024).unwrap(),
            detection: Some(GuardDetection {
                detect: DetectConfig {
                    warmup_windows: 1,
                    trigger_windows: 1,
                    ..DetectConfig::default()
                },
                enforce,
                attack_rate_factor: 0.1,
            }),
            challenge: mode,
        })
        .unwrap()
    }

    /// A quiet window, then a flood from one heavy /24 and many small
    /// sources, so the detector is in `Attack` at the returned instant.
    fn attack(g: &mut Guard) -> Instant {
        let t0 = Instant::now();
        let src = |i: u32| ClientKey::from(IpAddr::V4(Ipv4Addr::from(0xc633_0000 | i << 8)));
        for i in 0..50 {
            g.check(src(i), t0);
        }
        let t1 = t0 + Duration::from_secs(1);
        for i in 0..3000 {
            g.check(src(i % 200), t1);
        }
        for _ in 0..500 {
            g.check(key(1), t1);
        }
        let t2 = t1 + Duration::from_secs(1);
        g.check(src(0), t2);
        assert_eq!(g.detector().unwrap().state(), State::Attack);
        t2
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn always_challenges_without_a_pass() {
        let mut g = challenging(ChallengeMode::Always, false);
        let t = Instant::now();
        assert_eq!(g.check(key(1), t).verdict, Verdict::Challenge);
        let d = g.check_passed(key(1), t, Pass::Valid);
        assert_eq!(d.verdict, Verdict::Allow);
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn attack_challenges_and_a_pass_keeps_the_normal_limit() {
        let mut g = challenging(ChallengeMode::Attack, true);
        let t = attack(&mut g);
        assert_eq!(g.check(key(9), t).verdict, Verdict::Challenge);
        // the attack limit (factor 0.1) still lets the burst through; a
        // pass is checked against the normal rate after it
        let passed: Vec<_> = (0..21)
            .map(|i| g.check_passed(key(10), t + Duration::from_millis(100 * i), Pass::Valid))
            .map(|d| d.verdict)
            .collect();
        assert!(passed.iter().all(|v| *v == Verdict::Allow), "{passed:?}");
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn no_challenge_in_observe_or_normal() {
        let mut g = challenging(ChallengeMode::Attack, false);
        let t = attack(&mut g);
        assert_eq!(g.check(key(9), t).verdict, Verdict::Allow);
        let mut g = challenging(ChallengeMode::Attack, true);
        assert_eq!(g.check(key(9), Instant::now()).verdict, Verdict::Allow);
        // a rule that asks for a pass applies without an attack
        let d = g.check_passed(key(9), Instant::now(), Pass::Required);
        assert_eq!(d.verdict, Verdict::Challenge);
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn heavy_hitter_dropped_with_a_pass() {
        let mut g = challenging(ChallengeMode::Attack, true);
        let t = attack(&mut g);
        assert!(g.detector().unwrap().is_heavy(key(1).into()));
        let d = g.check_passed(key(1), t, Pass::Valid);
        assert_eq!(d.verdict, Verdict::Drop);
    }

    #[test]
    #[ignore = "rfc 0012"]
    fn bucket_before_challenge() {
        let mut g = Guard::<()>::new(GuardConfig {
            challenge: ChallengeMode::Always,
            ..guard_config(1, 1)
        })
        .unwrap();
        let t = Instant::now();
        assert_eq!(g.check(key(1), t).verdict, Verdict::Challenge);
        assert!(matches!(
            g.check(key(1), t).verdict,
            Verdict::Throttle { .. }
        ));
    }

    fn guard_config(rate: u32, burst: u32) -> GuardConfig {
        GuardConfig {
            limit: Limit::new(rate, burst).unwrap(),
            max_clients: NonZeroUsize::new(2).unwrap(),
            detection: None,
            challenge: ChallengeMode::Off,
        }
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
                challenge: ChallengeMode::Off,
            });
            assert!(r.is_err(), "{f}");
        }
    }
}
