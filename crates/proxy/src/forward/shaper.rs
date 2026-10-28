use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{Cluster, Schedule, ScheduleConfig, Slot, split};
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
    shared: Option<Shared>,
}

/// The destination's share of a cluster budget (RFC 0010).
struct Shared {
    cluster: Arc<Mutex<Cluster>>,
    /// the whole cluster's budget
    schedule: ScheduleConfig,
    max_concurrent: usize,
    /// replicas the budget is split by, and the places handed out
    split: Mutex<(u32, usize)>,
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
    pub(crate) fn new(
        name: String,
        schedule: Schedule,
        max_concurrent: usize,
        cluster: Option<Arc<Mutex<Cluster>>>,
    ) -> Self {
        let label = name.clone();
        let shared = cluster.map(|cluster| Shared {
            cluster,
            schedule: *schedule.config(),
            max_concurrent,
            split: Mutex::new((1, max_concurrent)),
        });
        Self {
            name,
            schedule: Mutex::new(schedule),
            waiting: AtomicUsize::new(0),
            places: (max_concurrent > 0).then(|| Arc::new(Semaphore::new(max_concurrent))),
            queue: metrics::gauge!("dvarapala_egress_queue", "destination" => label.clone()),
            in_flight: metrics::gauge!("dvarapala_egress_in_flight", "destination" => label),
            logged: AtomicU64::new(0),
            shared,
        }
    }

    /// Follows the cluster: the budget split by live replicas (fail
    /// closed toward the provider) and pauses seen on other replicas.
    fn follow(&self, now: Instant) {
        let Some(sh) = &self.shared else { return };
        let (replicas, pause) = {
            let c = sh.cluster.lock().unwrap_or_else(|e| e.into_inner());
            (c.replicas(), c.pause(&self.name, now))
        };
        let mut split_now = sh.split.lock().unwrap_or_else(|e| e.into_inner());
        let (share, places) = split(&sh.schedule, sh.max_concurrent, replicas);
        if split_now.0 != replicas {
            // a share of a valid budget is valid
            let _ = self.lock().reconfigure(share);
            split_now.0 = replicas;
        }
        if let Some(sem) = &self.places
            && split_now.1 != places
        {
            if places > split_now.1 {
                sem.add_permits(places - split_now.1);
                split_now.1 = places;
            } else {
                // only free places can go; the rest go on a later request
                split_now.1 -= sem.forget_permits(split_now.1 - places);
            }
        }
        drop(split_now);
        if let Some(d) = pause {
            self.lock().pause(now, d);
        }
    }

    /// Waits for a slot and a place within `max_wait`, or returns how long
    /// until the next slot. Counts the outcome.
    pub(crate) async fn admit(&self) -> Result<Pass, Duration> {
        let start = Instant::now();
        self.follow(start);
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
        if let Some(sh) = &self.shared {
            let mut c = sh.cluster.lock().unwrap_or_else(|e| e.into_inner());
            c.publish_pause(&self.name, retry_after.min(self.lock().config().max_pause));
        }
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

#[cfg(test)]
mod tests {
    use dvarapala_engine::{ClusterConfig, Reply};

    use super::*;

    fn shaper(cluster: &Arc<Mutex<Cluster>>) -> Shaper {
        let s = Schedule::new(ScheduleConfig {
            rate: 10.0,
            burst: 4,
            max_queue: 0,
            ..ScheduleConfig::default()
        })
        .unwrap();
        Shaper::new("api".into(), s, 4, Some(cluster.clone()))
    }

    fn cluster(replicas: u32, pauses: Vec<(String, Duration)>) -> Arc<Mutex<Cluster>> {
        let mut c = Cluster::new(ClusterConfig {
            limit: None,
            window: Duration::from_secs(1),
            max_keys: 10,
            max_clients: 10,
        });
        c.apply(
            Reply {
                replicas,
                pauses,
                ..Reply::default()
            },
            Instant::now(),
            0,
        );
        Arc::new(Mutex::new(c))
    }

    // RFC 0010 case 4 in the proxy: the budget follows the replica count
    #[tokio::test]
    async fn budget_is_split_by_live_replicas() {
        let c = cluster(2, vec![]);
        let s = shaper(&c);
        let passes: Vec<_> = (0..3).map(|_| s.admit()).collect();
        let mut ok = Vec::new();
        for p in passes {
            if let Ok(p) = p.await {
                ok.push(p);
            }
        }
        // burst 4 / 2 replicas: two go at once, and two places of four
        assert_eq!(ok.len(), 2);
        assert_eq!(s.lock().config().rate, 5.0);
        assert_eq!(s.places.as_ref().unwrap().available_permits(), 0);
        drop(ok);
        // back to one replica: the whole budget again
        c.lock().unwrap().apply(
            Reply {
                replicas: 1,
                ..Reply::default()
            },
            Instant::now(),
            0,
        );
        s.follow(Instant::now());
        assert_eq!(s.lock().config().rate, 10.0);
        assert_eq!(s.places.as_ref().unwrap().available_permits(), 4);
    }

    // RFC 0010 case 7: pauses go both ways
    #[tokio::test]
    async fn pauses_are_shared() {
        let c = cluster(1, vec![("api".into(), Duration::from_secs(2))]);
        let s = shaper(&c);
        assert!(s.admit().await.is_err(), "paused by another replica");
        let c = cluster(1, vec![]);
        let s = shaper(&c);
        s.pause(Duration::from_secs(3));
        assert_eq!(
            c.lock().unwrap().drain(0).pauses,
            vec![("api".into(), Duration::from_secs(3))]
        );
    }
}
