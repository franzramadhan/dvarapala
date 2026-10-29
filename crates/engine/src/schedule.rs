use std::fmt;
use std::time::{Duration, Instant};

/// Limits of one [`Schedule`] (RFC 0007).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScheduleConfig {
    /// Sends per second, at least 0.001.
    pub rate: f64,
    /// Sends that may go at once after an idle period; at least 1.
    pub burst: u32,
    /// Requests waiting at once; 0 refuses instead of waiting.
    pub max_queue: usize,
    /// Longest wait for a slot; a later slot is refused.
    pub max_wait: Duration,
    /// Cap on a pause the destination asks for; zero ignores pauses.
    pub max_pause: Duration,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            rate: 1.0,
            burst: 1,
            max_queue: 100,
            max_wait: Duration::from_secs(2),
            max_pause: Duration::from_secs(60),
        }
    }
}

/// When a request may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Send now.
    Now,
    /// Send after this long; the caller counts itself as waiting until then.
    Wait(Duration),
    /// Too far away or the queue is full; the next free slot is this far.
    Refuse(Duration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleError(pub String);

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScheduleError {}

/// One send budget shared by every caller of a destination: a generic cell
/// rate algorithm that hands out send times instead of a yes or no. Time
/// is an input; nothing here reads a clock.
///
/// Not thread-safe; callers wrap it in a lock.
#[derive(Debug, Clone)]
pub struct Schedule {
    config: ScheduleConfig,
    /// time between sends
    interval: Duration,
    /// how far ahead of `tat` a send may go: `interval * (burst - 1)`
    tolerance: Duration,
    /// theoretical arrival time of the next send
    tat: Option<Instant>,
    paused_until: Option<Instant>,
}

impl Schedule {
    pub fn new(config: ScheduleConfig) -> Result<Self, ScheduleError> {
        if !(0.001..=f64::MAX).contains(&config.rate) {
            return Err(ScheduleError(format!(
                "rate must be at least 0.001, got {}",
                config.rate
            )));
        }
        if config.burst == 0 {
            return Err(ScheduleError("burst must be at least 1".into()));
        }
        let interval = Duration::from_nanos((1e9 / config.rate).ceil() as u64);
        Ok(Self {
            config,
            interval,
            tolerance: interval * (config.burst - 1),
            tat: None,
            paused_until: None,
        })
    }

    pub fn config(&self) -> &ScheduleConfig {
        &self.config
    }

    /// New limits that keep the queue position and any pause (RFC 0010:
    /// the budget split by live replicas).
    pub fn reconfigure(&mut self, config: ScheduleConfig) -> Result<(), ScheduleError> {
        *self = Self {
            tat: self.tat,
            paused_until: self.paused_until,
            ..Self::new(config)?
        };
        Ok(())
    }

    /// The slot for one request at `now`, with `waiting` requests already
    /// waiting. `Now` and `Wait` take the slot; `Refuse` takes nothing.
    pub fn reserve(&mut self, now: Instant, waiting: usize) -> Slot {
        let tat = self.tat.map_or(now, |t| t.max(now));
        let mut at = tat.checked_sub(self.tolerance).map_or(now, |t| t.max(now));
        if let Some(p) = self.paused_until {
            at = at.max(p);
        }
        let wait = at - now;
        let slot = if wait.is_zero() {
            Slot::Now
        } else if wait <= self.config.max_wait && waiting < self.config.max_queue {
            Slot::Wait(wait)
        } else {
            return Slot::Refuse(wait);
        };
        // only a pause puts `at` past `tat`: the burst starts again there
        self.tat = Some(tat.max(at) + self.interval);
        slot
    }

    /// Holds every send until `now + retry_after`, capped by `max_pause`.
    /// Returns whether the pause applied.
    pub fn pause(&mut self, now: Instant, retry_after: Duration) -> bool {
        let d = retry_after.min(self.config.max_pause);
        let Some(until) = now.checked_add(d).filter(|_| !d.is_zero()) else {
            return false;
        };
        self.paused_until = Some(self.paused_until.map_or(until, |p| p.max(until)));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);

    fn schedule(rate: f64, burst: u32, max_queue: usize, max_wait: Duration) -> Schedule {
        Schedule::new(ScheduleConfig {
            rate,
            burst,
            max_queue,
            max_wait,
            max_pause: Duration::from_secs(60),
        })
        .unwrap()
    }

    /// Reserves `n` slots at `t`, counting each `Wait` as a waiter.
    fn burst_at(s: &mut Schedule, t: Instant, n: usize) -> Vec<Slot> {
        let mut waiting = 0;
        (0..n)
            .map(|_| {
                let slot = s.reserve(t, waiting);
                if let Slot::Wait(_) = slot {
                    waiting += 1;
                }
                slot
            })
            .collect()
    }

    #[test]
    fn reconfigure_keeps_the_pause() {
        let mut s = schedule(10.0, 1, 0, Duration::ZERO);
        let t = Instant::now();
        assert!(s.pause(t, Duration::from_secs(1)));
        s.reconfigure(ScheduleConfig {
            rate: 5.0,
            ..*s.config()
        })
        .unwrap();
        assert_eq!(s.config().rate, 5.0);
        assert!(matches!(s.reserve(t, 0), Slot::Refuse(_)));
        assert!(
            s.reconfigure(ScheduleConfig {
                rate: 0.0,
                ..*s.config()
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_bad_config() {
        let bad = |rate, burst| {
            Schedule::new(ScheduleConfig {
                rate,
                burst,
                ..ScheduleConfig::default()
            })
            .is_err()
        };
        assert!(bad(0.0, 1));
        assert!(bad(f64::NAN, 1));
        assert!(bad(0.0001, 1));
        assert!(bad(1.0, 0));
        assert!(!bad(0.5, 1));
        let e = Schedule::new(ScheduleConfig {
            burst: 0,
            ..ScheduleConfig::default()
        })
        .err()
        .expect("refused");
        assert_eq!(e.to_string(), "burst must be at least 1");
    }

    /// RFC 0007 case 1
    #[test]
    fn spaces_sends_at_the_rate() {
        let mut s = schedule(10.0, 1, 100, Duration::from_secs(2));
        let t = Instant::now();
        let want: Vec<Slot> = (0..10)
            .map(|i| match i {
                0 => Slot::Now,
                i => Slot::Wait(100 * MS * i),
            })
            .collect();
        assert_eq!(burst_at(&mut s, t, 10), want);
    }

    /// RFC 0007 case 2
    #[test]
    fn burst_goes_at_once() {
        let mut s = schedule(10.0, 5, 100, Duration::from_secs(2));
        let t = Instant::now();
        assert_eq!(burst_at(&mut s, t, 5), vec![Slot::Now; 5]);
        assert_eq!(s.reserve(t, 0), Slot::Wait(100 * MS));
    }

    /// RFC 0007 case 3
    #[test]
    fn slots_past_max_wait_are_refused() {
        let mut s = schedule(10.0, 1, 100, 300 * MS);
        let t = Instant::now();
        let slots = burst_at(&mut s, t, 10);
        assert_eq!(
            slots[..4],
            [
                Slot::Now,
                Slot::Wait(100 * MS),
                Slot::Wait(200 * MS),
                Slot::Wait(300 * MS)
            ]
        );
        assert_eq!(slots[4..], [Slot::Refuse(400 * MS); 6]);
        // refusals took no slot: the next one is still 400 ms away
        assert_eq!(s.reserve(t + 100 * MS, 0), Slot::Wait(300 * MS));
    }

    /// RFC 0007 case 4
    #[test]
    fn full_queue_refuses() {
        let mut s = schedule(10.0, 1, 2, Duration::from_secs(2));
        let slots = burst_at(&mut s, Instant::now(), 5);
        assert_eq!(slots[0], Slot::Now);
        assert!(matches!(slots[1..3], [Slot::Wait(_), Slot::Wait(_)]));
        assert_eq!(slots[3..], [Slot::Refuse(300 * MS); 2]);
    }

    /// RFC 0007 case 5
    #[test]
    fn pause_is_capped_by_max_pause() {
        let mut s = Schedule::new(ScheduleConfig {
            rate: 100.0,
            burst: 10,
            max_wait: Duration::from_secs(2),
            max_pause: Duration::from_secs(1),
            ..ScheduleConfig::default()
        })
        .unwrap();
        let t = Instant::now();
        assert!(s.pause(t, Duration::from_secs(2)));
        assert_eq!(s.reserve(t, 0), Slot::Wait(Duration::from_secs(1)));
        // the rest of the burst also goes when the pause ends, then the rate
        let at_end = burst_at(&mut s, t, 9);
        assert_eq!(at_end, vec![Slot::Wait(Duration::from_secs(1)); 9]);
        assert_eq!(s.reserve(t, 0), Slot::Wait(Duration::from_millis(1010)));
        let mut ignore = Schedule::new(ScheduleConfig {
            max_pause: Duration::ZERO,
            ..ScheduleConfig::default()
        })
        .unwrap();
        assert!(!ignore.pause(t, Duration::from_secs(2)));
        assert_eq!(ignore.reserve(t, 0), Slot::Now);
    }

    /// RFC 0007 case 6, with a seeded generator instead of proptest: never
    /// more than `burst + rate * t` sends in any window of length `t`.
    #[test]
    fn never_exceeds_the_rate() {
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let rate = 1.0 + (next() % 1000) as f64 / 10.0;
            let burst = 1 + (next() % 20) as u32;
            let mut s = Schedule::new(ScheduleConfig {
                rate,
                burst,
                max_queue: (next() % 50) as usize,
                max_wait: MS * (next() % 2000) as u32,
                max_pause: Duration::ZERO,
            })
            .unwrap();
            let start = Instant::now();
            let mut now = start;
            let mut sends = Vec::new();
            let mut waiting: Vec<Instant> = Vec::new();
            for _ in 0..300 {
                now += Duration::from_micros(next() % 50_000);
                waiting.retain(|&at| at > now);
                match s.reserve(now, waiting.len()) {
                    Slot::Now => sends.push(now),
                    Slot::Wait(d) => {
                        sends.push(now + d);
                        waiting.push(now + d);
                    }
                    Slot::Refuse(_) => {}
                }
            }
            sends.sort();
            for (i, &a) in sends.iter().enumerate() {
                for (j, &b) in sends[i..].iter().enumerate() {
                    let allowed = f64::from(burst) + rate * (b - a).as_secs_f64();
                    assert!(
                        (j + 1) as f64 <= allowed + 1e-6,
                        "{} sends in {:?} (rate {rate}, burst {burst})",
                        j + 1,
                        b - a
                    );
                }
            }
        }
    }
}
