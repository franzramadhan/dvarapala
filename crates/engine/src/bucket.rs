use std::fmt;
use std::time::Instant;

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
    pub fn new(_rate: u32, _burst: u32) -> Result<Self, LimitError> {
        todo!("rfc 0001")
    }

    /// The same limit with the rate multiplied by `factor` (RFC 0002 attack mode).
    pub fn scaled(&self, _factor: f64) -> Self {
        todo!("rfc 0001")
    }
}

/// Token bucket for one client. Time is an input: `take` never reads a clock.
#[derive(Debug, Clone)]
pub struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub fn full(_limit: &Limit, _now: Instant) -> Self {
        todo!("rfc 0001")
    }

    pub fn take(&mut self, _limit: &Limit, _now: Instant) -> Verdict {
        let _ = (self.tokens, self.last);
        todo!("rfc 0001")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limit(rate: u32, burst: u32) -> Limit {
        Limit::new(rate, burst).unwrap()
    }

    #[test]
    #[ignore = "rfc 0001 case 1"]
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
    #[ignore = "rfc 0001 case 2"]
    fn refills_over_time() {
        let l = limit(10, 1);
        let t0 = Instant::now();
        let mut b = Bucket::full(&l, t0);
        assert_eq!(b.take(&l, t0), Verdict::Allow);
        assert!(matches!(b.take(&l, t0), Verdict::Throttle { .. }));
        assert_eq!(b.take(&l, t0 + Duration::from_millis(100)), Verdict::Allow);
    }

    #[test]
    #[ignore = "rfc 0001 case 3"]
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
    #[ignore = "rfc 0001 case 4"]
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
    #[ignore = "rfc 0001"]
    fn rejects_zero_rate_and_burst() {
        assert_eq!(Limit::new(0, 1), Err(LimitError::ZeroRate));
        assert_eq!(Limit::new(1, 0), Err(LimitError::ZeroBurst));
    }
}
