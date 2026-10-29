use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use http::uri::{Authority, Scheme};

use super::{HealthConfig, RetryBudget};
use crate::reverse::parse;

/// Endpoints in one pool at most.
const MAX_ENDPOINTS: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Balance {
    #[default]
    RoundRobin,
    /// The endpoint with the fewest requests in flight, ties in turn.
    LeastRequests,
}

#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Base URLs, `http://` or `https://`, each with its own path.
    pub upstreams: Vec<String>,
    pub balance: Balance,
    /// Active checks; `None` turns them off.
    pub health: Option<HealthConfig>,
    /// Failed requests in a row that eject an endpoint; 0 never ejects.
    pub eject_after: u32,
    pub eject_time: Duration,
    /// Retries of a request that failed to connect; 0 never retries.
    pub retries: u32,
    /// Retries earned per request, `[0, 1]`.
    pub retry_budget: f64,
    /// The clock. `Instant::now` outside tests.
    pub now: fn() -> Instant,
}

impl PoolConfig {
    /// One upstream, no health checks, no ejection, no retries: the
    /// behavior before RFC 0015.
    pub fn single(upstream: &str) -> Self {
        Self {
            upstreams: vec![upstream.to_owned()],
            balance: Balance::RoundRobin,
            health: None,
            eject_after: 0,
            eject_time: Duration::ZERO,
            retries: 0,
            retry_budget: 0.0,
            now: Instant::now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    Empty,
    TooMany(usize),
    Upstream(crate::UpstreamError),
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the pool has no upstream"),
            Self::TooMany(n) => write!(f, "{n} upstreams, at most {MAX_ENDPOINTS}"),
            Self::Upstream(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PoolError {}

pub(crate) struct Endpoint {
    pub(crate) scheme: Scheme,
    pub(crate) authority: Authority,
    pub(crate) base_path: String,
    /// `host:port`, the metrics label; leaked once, bounded by the config
    pub(crate) label: &'static str,
    in_flight: AtomicUsize,
    /// failed requests in a row
    failures: AtomicU32,
    /// ms since the pool's epoch until which the endpoint is ejected; 0 none
    ejected_until: AtomicU64,
    /// taken out by active checks
    down: AtomicBool,
    /// checks in a row: positive passed, negative failed (the check task only)
    streak: AtomicU32,
}

/// Endpoints with their state, shared by every listener (RFC 0015).
pub struct Pool {
    pub(crate) endpoints: Vec<Endpoint>,
    balance: Balance,
    next: AtomicUsize,
    eject_after: u32,
    eject_time: Duration,
    pub(crate) retries: u32,
    pub(crate) budget: RetryBudget,
    pub(crate) health: Option<HealthConfig>,
    now: fn() -> Instant,
    epoch: Instant,
    /// last `pool degraded` log, ms since the epoch
    degraded_log: AtomicU64,
}

/// One request in flight on an endpoint, until dropped.
pub(crate) struct InFlight<'a>(&'a Endpoint);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let n = self.0.in_flight.fetch_sub(1, Ordering::Relaxed) - 1;
        metrics::gauge!("dvarapala_upstream_in_flight", "upstream" => self.0.label).set(n as f64);
    }
}

impl Pool {
    /// Fails on an empty list, more than 64 upstreams or a bad URL.
    pub fn new(config: PoolConfig) -> Result<Self, PoolError> {
        let n = config.upstreams.len();
        if n == 0 {
            return Err(PoolError::Empty);
        }
        if n > MAX_ENDPOINTS {
            return Err(PoolError::TooMany(n));
        }
        let endpoints = config
            .upstreams
            .iter()
            .map(|u| {
                let (scheme, authority, base_path) =
                    parse(u, cfg!(feature = "tls")).map_err(PoolError::Upstream)?;
                let label = Box::leak(authority.as_str().to_owned().into_boxed_str());
                Ok(Endpoint {
                    scheme,
                    authority,
                    base_path,
                    label,
                    in_flight: AtomicUsize::new(0),
                    failures: AtomicU32::new(0),
                    ejected_until: AtomicU64::new(0),
                    down: AtomicBool::new(false),
                    streak: AtomicU32::new(0),
                })
            })
            .collect::<Result<_, PoolError>>()?;
        let pool = Self {
            endpoints,
            balance: config.balance,
            next: AtomicUsize::new(0),
            eject_after: config.eject_after,
            eject_time: config.eject_time,
            retries: config.retries,
            budget: RetryBudget::new(config.retry_budget),
            health: config.health,
            now: config.now,
            epoch: (config.now)(),
            degraded_log: AtomicU64::new(0),
        };
        pool.endpoints.iter().for_each(|e| pool.gauge(e));
        Ok(pool)
    }

    /// Whether any endpoint is `https://`.
    #[cfg(feature = "tls")]
    pub(crate) fn https(&self) -> bool {
        self.endpoints.iter().any(|e| e.scheme == Scheme::HTTPS)
    }

    fn ms(&self) -> u64 {
        // +1 so that 0 stays "not ejected"
        (self.now)()
            .saturating_duration_since(self.epoch)
            .as_millis() as u64
            + 1
    }

    fn up(&self, e: &Endpoint, now: u64) -> bool {
        !e.down.load(Ordering::Relaxed) && e.ejected_until.load(Ordering::Relaxed) <= now
    }

    /// The endpoint for the next request, never `skip` when another is
    /// left. With none up, any of them (fail open, counted).
    pub fn pick(&self, skip: Option<usize>) -> usize {
        let n = self.endpoints.len();
        // a retry does not move the rotation
        let start = match skip {
            None => self.next.fetch_add(1, Ordering::Relaxed),
            Some(_) => self.next.load(Ordering::Relaxed),
        };
        let now = self.ms();
        let order = (0..n)
            .map(|k| (start + k) % n)
            .filter(|&i| Some(i) != skip || n == 1);
        let best = |up: bool| {
            let mut found: Option<(usize, usize)> = None;
            for i in order.clone() {
                let e = &self.endpoints[i];
                if up && !self.up(e, now) {
                    continue;
                }
                let load = match self.balance {
                    Balance::RoundRobin => return Some(i),
                    Balance::LeastRequests => e.in_flight.load(Ordering::Relaxed),
                };
                if found.is_none_or(|(_, l)| load < l) {
                    found = Some((i, load));
                }
            }
            found.map(|(i, _)| i)
        };
        if let Some(i) = best(true) {
            return i;
        }
        metrics::counter!("dvarapala_upstream_degraded_total").increment(1);
        let last = self.degraded_log.load(Ordering::Relaxed);
        if now >= last + 1000
            && self
                .degraded_log
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!(
                msg = "pool degraded",
                "no upstream healthy, picking among all"
            );
        }
        best(false).unwrap_or(start % n)
    }

    pub(crate) fn start(&self, i: usize) -> InFlight<'_> {
        let e = &self.endpoints[i];
        let n = e.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::gauge!("dvarapala_upstream_in_flight", "upstream" => e.label).set(n as f64);
        InFlight(e)
    }

    /// A finished request: `ok` false on a connect error, a timeout or a
    /// `502` to `504`.
    pub fn report(&self, i: usize, ok: bool) {
        let e = &self.endpoints[i];
        let result = if ok { "ok" } else { "error" };
        metrics::counter!("dvarapala_upstream_requests_total", "upstream" => e.label, "result" => result)
            .increment(1);
        if ok {
            e.failures.store(0, Ordering::Relaxed);
            if e.ejected_until.swap(0, Ordering::Relaxed) != 0 {
                self.gauge(e);
            }
            return;
        }
        let failures = e.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if self.eject_after == 0 || failures < self.eject_after {
            return;
        }
        // one failure short, so that a failed trial ejects again
        e.failures.store(self.eject_after - 1, Ordering::Relaxed);
        let until = self.ms() + self.eject_time.as_millis() as u64;
        e.ejected_until.store(until, Ordering::Relaxed);
        metrics::counter!("dvarapala_upstream_ejections_total", "upstream" => e.label).increment(1);
        self.gauge(e);
        tracing::warn!(msg = "upstream ejected", upstream = e.label, failures, eject_time = ?self.eject_time);
    }

    /// An active check result; `unhealthy_after` and `healthy_after` from
    /// the health config.
    pub fn check(&self, i: usize, ok: bool) {
        let Some(h) = &self.health else { return };
        let e = &self.endpoints[i];
        // streak: passes in the low half, failures in the high half
        let s = e.streak.load(Ordering::Relaxed);
        let (passed, failed) = if ok {
            ((s & 0xffff) + 1, 0)
        } else {
            (0, (s >> 16) + 1)
        };
        e.streak.store(
            (failed.min(0xffff) << 16) | passed.min(0xffff),
            Ordering::Relaxed,
        );
        let down = e.down.load(Ordering::Relaxed);
        if !down && failed >= h.unhealthy_after {
            e.down.store(true, Ordering::Relaxed);
            tracing::warn!(msg = "upstream unhealthy", upstream = e.label, failed);
        } else if down && passed >= h.healthy_after {
            e.down.store(false, Ordering::Relaxed);
            tracing::info!(msg = "upstream healthy", upstream = e.label, passed);
        } else {
            return;
        }
        self.gauge(e);
    }

    fn gauge(&self, e: &Endpoint) {
        let up = self.up(e, self.ms());
        metrics::gauge!("dvarapala_upstream_healthy", "upstream" => e.label)
            .set(f64::from(u8::from(up)));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn pool(n: usize, balance: Balance) -> Pool {
        let mut c = PoolConfig::single("http://192.0.2.1:80");
        c.upstreams = (0..n)
            .map(|i| format!("http://192.0.2.{}:80", i + 1))
            .collect();
        c.balance = balance;
        Pool::new(c).unwrap()
    }

    // RFC 0015 case 1
    #[test]
    fn round_robin_spreads_evenly() {
        let p = pool(3, Balance::RoundRobin);
        let mut n = [0; 3];
        for _ in 0..300 {
            n[p.pick(None)] += 1;
        }
        assert_eq!(n, [100; 3]);
    }

    // RFC 0015 case 2
    #[test]
    fn least_requests_picks_the_idlest() {
        let p = pool(3, Balance::LeastRequests);
        let a = [p.start(0), p.start(0)];
        let c = p.start(2);
        assert_eq!(p.pick(None), 1);
        let b = p.start(1);
        assert_ne!(p.pick(None), 0, "1 and 2 tie at one, 0 has two");
        drop((a, b, c));
        // all idle: in turn
        let picks: Vec<_> = (0..3).map(|_| p.pick(None)).collect();
        let mut sorted = picks.clone();
        sorted.sort();
        assert_eq!(sorted, [0, 1, 2], "{picks:?}");
    }

    static NOW: Mutex<Option<Instant>> = Mutex::new(None);

    fn clock() -> Instant {
        NOW.lock().unwrap().unwrap()
    }

    // RFC 0015 case 3
    #[test]
    fn ejection_and_trial() {
        let t0 = Instant::now();
        *NOW.lock().unwrap() = Some(t0);
        let mut c = PoolConfig::single("http://192.0.2.1:80");
        c.upstreams.push("http://192.0.2.2:80".into());
        c.eject_after = 5;
        c.eject_time = Duration::from_secs(30);
        c.now = clock;
        let p = Pool::new(c).unwrap();
        for _ in 0..5 {
            p.report(0, false);
        }
        let at = |s| *NOW.lock().unwrap() = Some(t0 + Duration::from_secs(s));
        at(10);
        assert!((0..10).all(|_| p.pick(None) == 1));
        at(31);
        assert!((0..10).any(|_| p.pick(None) == 0), "trial");
        p.report(0, false);
        assert!(
            (0..10).all(|_| p.pick(None) == 1),
            "a failed trial ejects again"
        );
        at(62);
        p.report(0, true);
        p.report(0, false);
        assert!(
            (0..10).any(|_| p.pick(None) == 0),
            "one failure after a success"
        );
    }

    // RFC 0015 case 4
    #[test]
    fn active_checks_take_out_and_bring_back() {
        let mut c = PoolConfig::single("http://192.0.2.1:80");
        c.upstreams.push("http://192.0.2.2:80".into());
        c.health = Some(HealthConfig {
            path: "/healthz".into(),
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            unhealthy_after: 3,
            healthy_after: 2,
        });
        let p = Pool::new(c).unwrap();
        let picks0 = |p: &Pool| (0..10).filter(|_| p.pick(None) == 0).count();
        p.check(0, false);
        p.check(0, false);
        assert!(picks0(&p) > 0);
        p.check(0, false);
        assert_eq!(picks0(&p), 0);
        p.check(0, true);
        assert_eq!(picks0(&p), 0);
        p.check(0, true);
        assert!(picks0(&p) > 0);
    }

    // RFC 0015 case 5
    #[test]
    fn none_up_picks_among_all() {
        let mut c = PoolConfig::single("http://192.0.2.1:80");
        c.upstreams.push("http://192.0.2.2:80".into());
        c.eject_after = 1;
        c.eject_time = Duration::from_secs(30);
        let p = Pool::new(c).unwrap();
        p.report(0, false);
        p.report(1, false);
        let picks: Vec<_> = (0..4).map(|_| p.pick(None)).collect();
        assert!(picks.contains(&0) && picks.contains(&1), "{picks:?}");
        // a retry still avoids the endpoint that failed
        assert_eq!(p.pick(Some(0)), 1);
    }

    #[test]
    fn bounds() {
        let mut c = PoolConfig::single("http://192.0.2.1:80");
        c.upstreams.clear();
        assert_eq!(Pool::new(c.clone()).err(), Some(PoolError::Empty));
        c.upstreams = vec!["http://192.0.2.1:80".into(); 65];
        assert_eq!(Pool::new(c.clone()).err(), Some(PoolError::TooMany(65)));
        c.upstreams = vec!["nope".into()];
        assert!(matches!(Pool::new(c), Err(PoolError::Upstream(_))));
    }
}
