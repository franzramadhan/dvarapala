#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]
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
        todo!("rfc 0015")
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
        todo!("rfc 0015")
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
        todo!("rfc 0015")
    }
}

impl Pool {
    /// Fails on an empty list, more than 64 upstreams or a bad URL.
    pub fn new(config: PoolConfig) -> Result<Self, PoolError> {
        todo!("rfc 0015")
    }

    /// Whether any endpoint is `https://`.
    #[cfg(feature = "tls")]
    pub(crate) fn https(&self) -> bool {
        todo!("rfc 0015")
    }

    fn ms(&self) -> u64 {
        todo!("rfc 0015")
    }

    fn up(&self, e: &Endpoint, now: u64) -> bool {
        todo!("rfc 0015")
    }

    /// The endpoint for the next request, never `skip` when another is
    /// left. With none up, any of them (fail open, counted).
    pub fn pick(&self, skip: Option<usize>) -> usize {
        todo!("rfc 0015")
    }

    pub(crate) fn start(&self, i: usize) -> InFlight<'_> {
        todo!("rfc 0015")
    }

    /// A finished request: `ok` false on a connect error, a timeout or a
    /// `502` to `504`.
    pub fn report(&self, i: usize, ok: bool) {
        todo!("rfc 0015")
    }

    /// An active check result; `unhealthy_after` and `healthy_after` from
    /// the health config.
    pub fn check(&self, i: usize, ok: bool) {
        todo!("rfc 0015")
    }

    fn gauge(&self, e: &Endpoint) {
        todo!("rfc 0015")
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
    #[ignore = "rfc 0015"]
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
    #[ignore = "rfc 0015"]
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
    #[ignore = "rfc 0015"]
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
    #[ignore = "rfc 0015"]
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
    #[ignore = "rfc 0015"]
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
    #[ignore = "rfc 0015"]
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
