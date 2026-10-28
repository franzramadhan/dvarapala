use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::UpgradeConfig;

/// Open tunnels, counted against `max_tunnels` (RFC 0005). A place is taken
/// before the upgrade reaches the upstream and held until the tunnel ends.
pub(crate) struct Tunnels {
    pub(crate) config: UpgradeConfig,
    open: AtomicUsize,
    /// unix second of the last "tunnel limit reached" log
    logged: AtomicU64,
}

/// One place in [`Tunnels`]; dropping it frees the place.
pub(crate) struct Slot(pub(crate) Arc<Tunnels>);

impl Tunnels {
    pub(crate) fn new(config: UpgradeConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            open: AtomicUsize::new(0),
            logged: AtomicU64::new(0),
        })
    }

    /// A place, or `None` (counted, logged at most once a second) when all
    /// `max_tunnels` are taken.
    pub(crate) fn acquire(self: &Arc<Self>) -> Option<Slot> {
        let max = self.config.max_tunnels;
        let taken = self
            .open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .is_ok();
        if taken {
            return Some(Slot(self.clone()));
        }
        metrics::counter!("dvarapala_tunnels_rejected_total").increment(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if self.logged.swap(now, Ordering::Relaxed) != now {
            tracing::warn!(max_tunnels = max, "tunnel limit reached");
        }
        None
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_are_bounded_and_freed() {
        let t = Tunnels::new(UpgradeConfig {
            max_tunnels: 2,
            ..UpgradeConfig::default()
        });
        let a = t.acquire().unwrap();
        let _b = t.acquire().unwrap();
        assert!(t.acquire().is_none());
        drop(a);
        assert!(t.acquire().is_some());
    }
}
