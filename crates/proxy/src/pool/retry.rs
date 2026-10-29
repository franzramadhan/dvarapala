#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]
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
        todo!("rfc 0015")
    }

    pub fn earn(&self) {
        todo!("rfc 0015")
    }

    /// Spends one retry; `false` when the budget is empty.
    pub fn spend(&self) -> bool {
        todo!("rfc 0015")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0015 case 6
    #[test]
    #[ignore = "rfc 0015"]
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
