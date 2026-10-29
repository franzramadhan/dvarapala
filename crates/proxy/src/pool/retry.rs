use std::sync::atomic::{AtomicU64, Ordering};

/// Retries earned by traffic (RFC 0015): each request adds `per_request`,
/// a retry spends 1, at most [`RetryBudget::MAX`] banked.
#[derive(Debug)]
pub struct RetryBudget {
    /// thousandths of a retry
    milli: AtomicU64,
    per_request: u64,
}

impl RetryBudget {
    pub const MAX: u64 = 10;

    /// Starts full. `per_request` is clamped to `[0, 1]`.
    pub fn new(per_request: f64) -> Self {
        Self {
            milli: AtomicU64::new(Self::MAX * 1000),
            per_request: (per_request.clamp(0.0, 1.0) * 1000.0) as u64,
        }
    }

    pub fn earn(&self) {
        let _ = self
            .milli
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |m| {
                Some((m + self.per_request).min(Self::MAX * 1000))
            });
    }

    /// Spends one retry; `false` when the budget is empty.
    pub fn spend(&self) -> bool {
        self.milli
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |m| {
                m.checked_sub(1000)
            })
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0015 case 6
    #[test]
    fn retries_stay_a_share_of_traffic() {
        let b = RetryBudget::new(0.2);
        let mut retries = 0;
        for _ in 0..100 {
            b.earn();
            if b.spend() {
                retries += 1;
            }
        }
        assert!(retries <= 30, "{retries}");
        assert!(retries >= 20, "{retries}");
        let none = RetryBudget::new(0.0);
        let spent = (0..100).filter(|_| none.spend()).count();
        assert_eq!(spent, 10);
    }
}
