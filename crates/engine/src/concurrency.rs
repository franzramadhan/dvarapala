//! RFC 0032: a cap on requests in flight to the upstream, fixed or learned
//! from its latency, and the order in which classes of clients are shed.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Latency histogram buckets: 4 per power of two of microseconds, from
/// 1 us to about 70 minutes.
const BUCKETS: usize = 128;
/// How far the no-load latency moves toward a higher window p50, per window.
const NOLOAD_DRIFT: f64 = 0.01;
/// A failed request counts as this many times the no-load latency, at least.
const FAILURE_FACTOR: f64 = 10.0;
/// A window p50 up to this many times the no-load latency reads as flat:
/// one histogram bucket (19%) or timer jitter must not shrink the limit.
const TOLERANCE: f64 = 1.2;

/// Who a request comes from, in the order the limit sheds them last.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Class {
    /// A valid challenge pass or a low model score.
    Trusted,
    #[default]
    Normal,
    /// A heavy hitter while an attack is on.
    Suspect,
}

impl Class {
    pub const ALL: [Class; 3] = [Class::Trusted, Class::Normal, Class::Suspect];

    pub fn name(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Normal => "normal",
            Self::Suspect => "suspect",
        }
    }
}

/// What the rate limiter decided about a request for the limit: its class
/// and how many slots it takes. A weight of 0 bypasses the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    pub class: Class,
    pub weight: u32,
}

impl Default for Priority {
    fn default() -> Self {
        Self {
            class: Class::Normal,
            weight: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitMode {
    /// A hard cap of `limit`.
    Fixed,
    /// Between `min` and `max`, moved by the latency every `window`.
    Gradient,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConcurrencyConfig {
    pub mode: LimitMode,
    /// The cap in `Fixed` mode, the start value in `Gradient` (0: `min`).
    pub limit: u32,
    pub min: u32,
    pub max: u32,
    pub window: Duration,
    /// Share of the limit kept for trusted requests, `[0, 0.5]`.
    pub reserve: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcurrencyError(pub &'static str);

impl fmt::Display for ConcurrencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ConcurrencyError {}

impl ConcurrencyConfig {
    pub fn validate(&self) -> Result<(), ConcurrencyError> {
        if !(0.0..=0.5).contains(&self.reserve) {
            return Err(ConcurrencyError("reserve must be in [0, 0.5]"));
        }
        match self.mode {
            LimitMode::Fixed if self.limit == 0 => {
                Err(ConcurrencyError("limit must be at least 1 in fixed mode"))
            }
            LimitMode::Gradient if self.min == 0 || self.min > self.max => {
                Err(ConcurrencyError("min must be at least 1 and at most max"))
            }
            LimitMode::Gradient if self.window < Duration::from_millis(100) => {
                Err(ConcurrencyError("window must be at least 100ms"))
            }
            _ => Ok(()),
        }
    }

    fn start(&self) -> u32 {
        match self.mode {
            LimitMode::Fixed => self.limit,
            LimitMode::Gradient if self.limit == 0 => self.min,
            LimitMode::Gradient => self.limit.clamp(self.min, self.max),
        }
    }
}

/// How a request in flight ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The response head arrived after this long.
    Answered(Duration),
    /// Connect error, timeout or a `502` to `504` after this long.
    Failed(Duration),
    /// Cancelled before an answer: no latency sample.
    Dropped,
}

/// A new limit, after a window closed in `Gradient` mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Update {
    pub limit: u32,
    /// The no-load latency the gradient compares against.
    pub noload: Duration,
    /// The window's p50.
    pub window: Duration,
}

/// The limit and the requests in flight. Admit and release are atomics;
/// only closing a window takes a lock, and never waits for it.
pub struct Concurrency {
    in_flight: AtomicU32,
    limit: AtomicU32,
    /// the most in flight during the window
    peak: AtomicU32,
    reserve_milli: AtomicU32,
    /// the no-load latency in microseconds, as f64 bits; 0 until known
    noload: AtomicU64,
    hist: [AtomicU32; BUCKETS],
    epoch: Instant,
    /// the mode never changes (`reconfigure` refuses it); fixed has no
    /// windows, so release skips the histogram and the lock
    fixed: bool,
    /// ns since `epoch` when the window closes; 0 before the first sample
    window_end: AtomicU64,
    state: Mutex<Window>,
}

struct Window {
    config: ConcurrencyConfig,
    /// the gradient's estimate, before rounding
    estimate: f64,
    /// microseconds; 0 until the first window
    noload: f64,
}

impl Concurrency {
    pub fn new(config: ConcurrencyConfig, now: Instant) -> Result<Self, ConcurrencyError> {
        config.validate()?;
        let start = config.start();
        Ok(Self {
            in_flight: AtomicU32::new(0),
            limit: AtomicU32::new(start),
            peak: AtomicU32::new(0),
            reserve_milli: AtomicU32::new(milli(config.reserve)),
            noload: AtomicU64::new(0),
            hist: std::array::from_fn(|_| AtomicU32::new(0)),
            epoch: now,
            fixed: config.mode == LimitMode::Fixed,
            window_end: AtomicU64::new(0),
            state: Mutex::new(Window {
                config,
                estimate: f64::from(start),
                noload: 0.0,
            }),
        })
    }

    /// Applies new bounds, reserve and window; the mode stays. A fixed
    /// limit takes the new cap, a gradient one is clamped into `[min, max]`.
    pub fn reconfigure(&self, config: ConcurrencyConfig) -> Result<(), ConcurrencyError> {
        config.validate()?;
        let mut w = self.lock();
        if config.mode != w.config.mode {
            return Err(ConcurrencyError("mode needs a restart"));
        }
        let limit = match config.mode {
            LimitMode::Fixed => config.limit,
            LimitMode::Gradient => (w.estimate.round() as u32).clamp(config.min, config.max),
        };
        w.estimate = f64::from(limit);
        self.reserve_milli.store(milli(config.reserve), Relaxed);
        self.limit.store(limit, Relaxed);
        w.config = config;
        Ok(())
    }

    pub fn limit(&self) -> u32 {
        self.limit.load(Relaxed)
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Relaxed)
    }

    /// The slots taken when `p` fits under its class's share of the limit,
    /// `None` when it is shed. A weight over the share is cut to the share,
    /// so a heavy route still runs alone.
    pub fn admit(&self, p: Priority) -> Option<u32> {
        if p.weight == 0 {
            return Some(0);
        }
        let limit = u64::from(self.limit());
        let reserve = u64::from(self.reserve_milli.load(Relaxed));
        let share = match p.class {
            Class::Trusted => 1000,
            Class::Normal => 1000 - reserve,
            Class::Suspect => 1000 - 2 * reserve,
        };
        let cap = (limit * share / 1000) as u32;
        if cap == 0 {
            return None;
        }
        let w = p.weight.min(cap);
        let mut cur = self.in_flight.load(Relaxed);
        loop {
            if cur + w > cap {
                return None;
            }
            match self
                .in_flight
                .compare_exchange_weak(cur, cur + w, Relaxed, Relaxed)
            {
                Ok(_) => break,
                Err(now) => cur = now,
            }
        }
        // a load first: most admits do not raise the peak, and a write
        // on every one would bounce the cache line between threads
        if self.peak.load(Relaxed) < cur + w {
            self.peak.fetch_max(cur + w, Relaxed);
        }
        Some(w)
    }

    /// Gives back `weight` slots and records the latency; returns the new
    /// limit when this closed a window.
    pub fn release(&self, weight: u32, outcome: Outcome, now: Instant) -> Option<Update> {
        if weight == 0 {
            return None;
        }
        self.in_flight.fetch_sub(weight, Relaxed);
        if self.fixed {
            return None;
        }
        let latency = match outcome {
            Outcome::Answered(d) => d.as_secs_f64() * 1e6,
            Outcome::Failed(d) => {
                let noload = f64::from_bits(self.noload.load(Relaxed));
                (d.as_secs_f64() * 1e6).max(noload * FAILURE_FACTOR)
            }
            Outcome::Dropped => return self.tick(now),
        };
        self.hist[bucket(latency)].fetch_add(1, Relaxed);
        self.tick(now)
    }

    /// Closes the window when it has ended, unless another thread is.
    pub fn tick(&self, now: Instant) -> Option<Update> {
        let at = now.saturating_duration_since(self.epoch).as_nanos() as u64;
        let end = self.window_end.load(Relaxed);
        if end != 0 && at < end {
            return None;
        }
        let mut w = self.state.try_lock().ok()?;
        if w.config.mode == LimitMode::Fixed {
            return None;
        }
        let next = at + w.config.window.as_nanos() as u64;
        if self
            .window_end
            .compare_exchange(end, next.max(1), Relaxed, Relaxed)
            .is_err()
        {
            return None;
        }
        let counts: Vec<u32> = self.hist.iter().map(|b| b.swap(0, Relaxed)).collect();
        let peak = self.peak.swap(self.in_flight(), Relaxed);
        if end == 0 {
            return None;
        }
        let p50 = median(&counts)?;
        Some(self.close(&mut w, p50, peak))
    }

    fn close(&self, w: &mut Window, p50: f64, peak: u32) -> Update {
        w.noload = if w.noload == 0.0 || p50 < w.noload {
            p50
        } else {
            w.noload + (p50 - w.noload) * NOLOAD_DRIFT
        };
        self.noload.store(w.noload.to_bits(), Relaxed);
        let old = w.estimate;
        let gradient = (TOLERANCE * w.noload / p50).clamp(0.5, 1.0);
        // app limited: a limit the traffic never came near does not grow
        if gradient < 1.0 || f64::from(peak) >= old / 2.0 {
            w.estimate = (old * gradient + old.sqrt())
                .clamp(f64::from(w.config.min), f64::from(w.config.max));
        }
        let limit = w.estimate.round() as u32;
        self.limit.store(limit, Relaxed);
        Update {
            limit,
            noload: Duration::from_secs_f64(w.noload / 1e6),
            window: Duration::from_secs_f64(p50 / 1e6),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn milli(share: f64) -> u32 {
    (share * 1000.0).round() as u32
}

fn bucket(us: f64) -> usize {
    ((us.max(1.0).log2() * 4.0) as usize).min(BUCKETS - 1)
}

/// The middle of bucket `i`, in microseconds.
fn value(i: usize) -> f64 {
    ((i as f64 + 0.5) / 4.0).exp2()
}

fn median(counts: &[u32]) -> Option<f64> {
    let n: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    if n == 0 {
        return None;
    }
    let mut seen = 0;
    for (i, &c) in counts.iter().enumerate() {
        seen += u64::from(c);
        if seen * 2 >= n {
            return Some(value(i));
        }
    }
    None
}

#[cfg(test)]
#[path = "concurrency_tests.rs"]
mod tests;
