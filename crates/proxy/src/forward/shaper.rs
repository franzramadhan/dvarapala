use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{Schedule, Slot};
use metrics::Gauge;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// One destination's budget: the schedule, the requests waiting on it, the
/// places in flight and provider pauses (RFC 0007).
pub(crate) struct Shaper {
    pub(crate) name: String,
    schedule: Mutex<Schedule>,
    waiting: AtomicUsize,
    /// `None` when `max_concurrent` is 0
    places: Option<Arc<Semaphore>>,
    queue: Gauge,
    in_flight: Gauge,
    /// unix second of the last "egress refused" log
    logged: AtomicU64,
}

/// A request or tunnel allowed to go; dropping it frees its place.
pub(crate) struct Pass {
    _permit: Option<OwnedSemaphorePermit>,
    in_flight: Gauge,
}

impl Drop for Pass {
    fn drop(&mut self) {
        self.in_flight.decrement(1.0);
    }
}

/// Counts one waiter for as long as it lives, also when the client goes
/// away mid-wait.
struct Waiter<'a>(&'a Shaper);

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        self.0.waiting.fetch_sub(1, Ordering::AcqRel);
        self.0.queue.decrement(1.0);
    }
}

impl Shaper {
    pub(crate) fn new(name: String, schedule: Schedule, max_concurrent: usize) -> Self {
        let label = name.clone();
        Self {
            name,
            schedule: Mutex::new(schedule),
            waiting: AtomicUsize::new(0),
            places: (max_concurrent > 0).then(|| Arc::new(Semaphore::new(max_concurrent))),
            queue: metrics::gauge!("dvarapala_egress_queue", "destination" => label.clone()),
            in_flight: metrics::gauge!("dvarapala_egress_in_flight", "destination" => label),
            logged: AtomicU64::new(0),
        }
    }

    /// Waits for a slot and a place within `max_wait`, or returns how long
    /// until the next slot. Counts the outcome.
    pub(crate) async fn admit(&self) -> Result<Pass, Duration> {
        let start = Instant::now();
        let max_wait = self.lock().config().max_wait;
        let slot = {
            let mut s = self.lock();
            let slot = s.reserve(start, self.waiting.load(Ordering::Acquire));
            if let Slot::Wait(_) = slot {
                // inside the lock: the next caller sees this waiter
                self.waiting.fetch_add(1, Ordering::AcqRel);
            }
            slot
        };
        let mut delayed = false;
        match slot {
            Slot::Now => {}
            Slot::Wait(d) => {
                self.queue.increment(1.0);
                let _waiter = Waiter(self);
                tokio::time::sleep(d).await;
                delayed = true;
            }
            Slot::Refuse(d) => return Err(self.refuse("rate", d)),
        }
        let permit = match &self.places {
            None => None,
            Some(places) => match places.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    delayed = true;
                    let left = max_wait.saturating_sub(start.elapsed());
                    match tokio::time::timeout(left, places.clone().acquire_owned()).await {
                        Ok(Ok(p)) => Some(p),
                        // ponytail: 1 s hint, no estimate of when a place frees
                        _ => return Err(self.refuse("max_concurrent", Duration::from_secs(1))),
                    }
                }
            },
        };
        let result = if delayed { "delayed" } else { "sent" };
        self.count(result);
        if delayed {
            metrics::histogram!("dvarapala_egress_wait_seconds", "destination" => self.name.clone())
                .record(start.elapsed().as_secs_f64());
        }
        self.in_flight.increment(1.0);
        Ok(Pass {
            _permit: permit,
            in_flight: self.in_flight.clone(),
        })
    }

    /// Holds every send for `retry_after`, capped by `max_pause`.
    pub(crate) fn pause(&self, retry_after: Duration) {
        if self.lock().pause(Instant::now(), retry_after) {
            metrics::counter!("dvarapala_egress_provider_pauses_total", "destination" => self.name.clone())
                .increment(1);
        }
    }

    pub(crate) fn count(&self, result: &'static str) {
        count(&self.name, result);
    }

    fn refuse(&self, reason: &'static str, retry: Duration) -> Duration {
        self.count("refused");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if self.logged.swap(now, Ordering::Relaxed) != now {
            tracing::warn!(destination = %self.name, reason, "egress refused");
        }
        retry
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Schedule> {
        // the schedule has no invariant a panic can break mid-update
        self.schedule.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub(crate) fn count(destination: &str, result: &'static str) {
    metrics::counter!(
        "dvarapala_egress_requests_total",
        "destination" => destination.to_owned(),
        "result" => result
    )
    .increment(1);
}
