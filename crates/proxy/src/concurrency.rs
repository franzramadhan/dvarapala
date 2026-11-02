//! RFC 0032: the upstream concurrency limit around the pool, with its
//! metrics. The engine owns the algorithm; this owns the clock.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dvarapala_engine::{
    Class, Concurrency as Limiter, ConcurrencyConfig, ConcurrencyError, Outcome, Priority, Update,
};

/// The limit every listener's requests to the pool share.
pub struct Concurrency {
    limiter: Limiter,
    epoch: Instant,
    /// next `concurrency shedding` log allowed, ms since the epoch
    shed_log: AtomicU64,
    /// shed since that log, per class
    shed: [AtomicU64; 3],
}

impl Concurrency {
    pub fn new(config: ConcurrencyConfig) -> Result<Self, ConcurrencyError> {
        let epoch = Instant::now();
        let c = Self {
            limiter: Limiter::new(config, epoch)?,
            epoch,
            shed_log: AtomicU64::new(0),
            shed: Default::default(),
        };
        c.publish();
        Ok(c)
    }

    /// Sets the gauges again, for a recorder installed after [`Self::new`].
    pub fn publish(&self) {
        metrics::gauge!("dvarapala_concurrency_limit").set(self.limiter.limit());
        metrics::gauge!("dvarapala_concurrency_in_flight").set(self.limiter.in_flight());
    }

    /// Applies new bounds on a reload; the mode needs a restart.
    pub fn reconfigure(&self, config: ConcurrencyConfig) -> Result<(), ConcurrencyError> {
        self.limiter.reconfigure(config)?;
        metrics::gauge!("dvarapala_concurrency_limit").set(self.limiter.limit());
        Ok(())
    }

    pub fn limit(&self) -> u32 {
        self.limiter.limit()
    }

    pub fn in_flight(&self) -> u32 {
        self.limiter.in_flight()
    }

    /// A slot for `p`, or `None` when it is shed (counted and logged).
    pub(crate) fn admit(self: &Arc<Self>, p: Priority) -> Option<Slot> {
        let Some(weight) = self.limiter.admit(p) else {
            self.shed(p.class);
            return None;
        };
        if weight > 0 {
            metrics::gauge!("dvarapala_concurrency_in_flight").set(self.limiter.in_flight());
        }
        Some(Slot {
            limit: self.clone(),
            weight,
            start: Instant::now(),
            outcome: Outcome::Dropped,
        })
    }

    fn shed(&self, class: Class) {
        metrics::counter!("dvarapala_concurrency_shed_total", "class" => class.name()).increment(1);
        let i = Class::ALL.iter().position(|c| *c == class).unwrap_or(1);
        self.shed[i].fetch_add(1, Ordering::Relaxed);
        let now = self.epoch.elapsed().as_millis() as u64;
        let next = self.shed_log.load(Ordering::Relaxed);
        if now >= next
            && self
                .shed_log
                .compare_exchange(next, now + 1000, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let [trusted, normal, suspect] =
                self.shed.each_ref().map(|n| n.swap(0, Ordering::Relaxed));
            tracing::warn!(
                msg = "concurrency shedding",
                limit = self.limiter.limit(),
                class = class.name(),
                trusted,
                normal,
                suspect
            );
        }
    }

    fn release(&self, weight: u32, outcome: Outcome) {
        let update = self.limiter.release(weight, outcome, Instant::now());
        metrics::gauge!("dvarapala_concurrency_in_flight").set(self.limiter.in_flight());
        if let Some(Update {
            limit,
            noload,
            window,
        }) = update
        {
            metrics::gauge!("dvarapala_concurrency_limit").set(limit);
            metrics::gauge!("dvarapala_concurrency_rtt_seconds", "kind" => "noload")
                .set(noload.as_secs_f64());
            metrics::gauge!("dvarapala_concurrency_rtt_seconds", "kind" => "window")
                .set(window.as_secs_f64());
        }
    }
}

/// Slots taken until dropped; a slot dropped without [`Slot::done`]
/// (a cancelled request) gives them back without a latency sample.
pub(crate) struct Slot {
    limit: Arc<Concurrency>,
    weight: u32,
    start: Instant,
    outcome: Outcome,
}

impl Slot {
    /// The response head arrived (`ok`), or the upstream failed.
    pub(crate) fn done(mut self, ok: bool) {
        let d = self.start.elapsed();
        self.outcome = if ok {
            Outcome::Answered(d)
        } else {
            Outcome::Failed(d)
        };
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        if self.weight > 0 {
            self.limit.release(self.weight, self.outcome);
        }
    }
}
