//! RFC 0032: a cap on requests in flight to the upstream, fixed or learned
//! from its latency, and the order in which classes of clients are shed.
#![allow(unused_variables, unused_imports, dead_code)]

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
        todo!("rfc 0032")
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
        todo!("rfc 0032")
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
        todo!("rfc 0032")
    }
}

impl std::error::Error for ConcurrencyError {}

impl ConcurrencyConfig {
    pub fn validate(&self) -> Result<(), ConcurrencyError> {
        todo!("rfc 0032")
    }

    fn start(&self) -> u32 {
        todo!("rfc 0032")
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
        todo!("rfc 0032")
    }

    /// Applies new bounds, reserve and window; the mode stays. A fixed
    /// limit takes the new cap, a gradient one is clamped into `[min, max]`.
    pub fn reconfigure(&self, config: ConcurrencyConfig) -> Result<(), ConcurrencyError> {
        todo!("rfc 0032")
    }

    pub fn limit(&self) -> u32 {
        todo!("rfc 0032")
    }

    pub fn in_flight(&self) -> u32 {
        todo!("rfc 0032")
    }

    /// The slots taken when `p` fits under its class's share of the limit,
    /// `None` when it is shed. A weight over the share is cut to the share,
    /// so a heavy route still runs alone.
    pub fn admit(&self, p: Priority) -> Option<u32> {
        todo!("rfc 0032")
    }

    /// Gives back `weight` slots and records the latency; returns the new
    /// limit when this closed a window.
    pub fn release(&self, weight: u32, outcome: Outcome, now: Instant) -> Option<Update> {
        todo!("rfc 0032")
    }

    /// Closes the window when it has ended, unless another thread is.
    pub fn tick(&self, now: Instant) -> Option<Update> {
        todo!("rfc 0032")
    }

    fn close(&self, w: &mut Window, p50: f64, peak: u32) -> Update {
        todo!("rfc 0032")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Window> {
        todo!("rfc 0032")
    }
}

fn milli(share: f64) -> u32 {
    todo!("rfc 0032")
}

fn bucket(us: f64) -> usize {
    todo!("rfc 0032")
}

/// The middle of bucket `i`, in microseconds.
fn value(i: usize) -> f64 {
    todo!("rfc 0032")
}

fn median(counts: &[u32]) -> Option<f64> {
    todo!("rfc 0032")
}

#[cfg(test)]
#[path = "concurrency_tests.rs"]
mod tests;
