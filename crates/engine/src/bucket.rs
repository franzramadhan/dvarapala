use std::fmt;
use std::time::{Duration, Instant};

use crate::Verdict;

/// Refill rate and bucket size, validated once at config load.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limit {
    rate: f64,
    burst: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    ZeroRate,
    ZeroBurst,
}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRate => f.write_str("rate must be at least 1 per second"),
            Self::ZeroBurst => f.write_str("burst must be at least 1"),
        }
    }
}

impl std::error::Error for LimitError {}

impl Limit {
    /// `rate` tokens per second, at most `burst` tokens saved up.
    pub fn new(rate: u32, burst: u32) -> Result<Self, LimitError> {
        if rate == 0 {
            return Err(LimitError::ZeroRate);
        }
        if burst == 0 {
            return Err(LimitError::ZeroBurst);
        }
        Ok(Self {
            rate: f64::from(rate),
            burst: f64::from(burst),
        })
    }

    /// Same burst, refill rate times `factor` (in `(0, 1]`).
    pub fn scaled(&self, factor: f64) -> Self {
        Self {
            rate: self.rate * factor,
            burst: self.burst,
        }
    }

    /// Most requests one client can send in `d`: the burst plus the refill.
    pub fn allowance(&self, d: Duration) -> f64 {
        self.burst + self.rate * d.as_secs_f64()
    }
}

/// Token bucket for one client. Time is an input: `take` never reads a clock.
#[derive(Debug, Clone)]
pub struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub fn full(limit: &Limit, now: Instant) -> Self {
        Self {
            tokens: limit.burst,
            last: now,
        }
    }

    pub fn take(&mut self, limit: &Limit, now: Instant) -> Verdict {
        // a clock that went backwards refills nothing and moves `last` nowhere
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * limit.rate).min(limit.burst);
        self.last = self.last.max(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Verdict::Allow
        } else {
            Verdict::Throttle {
                retry_after: Duration::from_secs_f64((1.0 - self.tokens) / limit.rate),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(rate: u32, burst: u32) -> Limit {
        Limit::new(rate, burst).unwrap()
    }

    #[test]
    fn burst_then_throttle_with_retry_after() {
        let l = limit(1, 2);
        let t0 = Instant::now();
        let mut b = Bucket::full(&l, t0);
        assert_eq!(b.take(&l, t0), Verdict::Allow);
        assert_eq!(b.take(&l, t0), Verdict::Allow);
        assert_eq!(
            b.take(&l, t0),
            Verdict::Throttle {
                retry_after: Duration::from_secs(1)
            }
        );
    }

    #[test]
    fn refills_over_time() {
        let l = limit(10, 1);
        let t0 = Instant::now();
        let mut b = Bucket::full(&l, t0);
        assert_eq!(b.take(&l, t0), Verdict::Allow);
        assert!(matches!(b.take(&l, t0), Verdict::Throttle { .. }));
        assert_eq!(b.take(&l, t0 + Duration::from_millis(100)), Verdict::Allow);
    }

    #[test]
    fn idle_refill_caps_at_burst() {
        let l = limit(100, 3);
        let t0 = Instant::now();
        let mut b = Bucket::full(&l, t0);
        for _ in 0..3 {
            b.take(&l, t0);
        }
        let later = t0 + Duration::from_secs(3600);
        for _ in 0..3 {
            assert_eq!(b.take(&l, later), Verdict::Allow);
        }
        assert!(matches!(b.take(&l, later), Verdict::Throttle { .. }));
    }

    #[test]
    fn clock_going_backwards_gains_nothing() {
        let l = limit(1, 1);
        let t1 = Instant::now() + Duration::from_secs(10);
        let mut b = Bucket::full(&l, t1);
        assert_eq!(b.take(&l, t1), Verdict::Allow);
        let earlier = t1 - Duration::from_secs(5);
        assert!(matches!(b.take(&l, earlier), Verdict::Throttle { .. }));
        // and the bucket does not owe time after the clock comes back
        assert_eq!(b.take(&l, t1 + Duration::from_secs(1)), Verdict::Allow);
    }

    #[test]
    fn scaled_slows_refill_only() {
        let l = limit(4, 1).scaled(0.25);
        let t0 = Instant::now();
        let mut b = Bucket::full(&l, t0);
        assert_eq!(b.take(&l, t0), Verdict::Allow);
        assert!(matches!(
            b.take(&l, t0 + Duration::from_millis(500)),
            Verdict::Throttle { .. }
        ));
        assert_eq!(b.take(&l, t0 + Duration::from_secs(1)), Verdict::Allow);
    }

    #[test]
    fn allowance_is_burst_plus_refill() {
        assert_eq!(limit(20, 40).allowance(Duration::from_secs(1)), 60.0);
        assert_eq!(limit(20, 40).allowance(Duration::from_millis(500)), 50.0);
    }

    #[test]
    fn rejects_zero_rate_and_burst() {
        assert_eq!(Limit::new(0, 1), Err(LimitError::ZeroRate));
        assert_eq!(Limit::new(1, 0), Err(LimitError::ZeroBurst));
    }
}
