//! The `[pool]` section (RFC 0015).
#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]

use std::time::{Duration, Instant};

use dvarapala_proxy::{Balance as ProxyBalance, HealthConfig, PoolConfig};
use serde::Deserialize;

use super::duration;

/// Endpoints in one pool at most, as in the proxy.
const MAX_UPSTREAMS: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    RoundRobin,
    LeastRequests,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Pool {
    pub upstreams: Vec<String>,
    pub balance: Balance,
    /// Empty turns active checks off.
    pub health_path: String,
    #[serde(deserialize_with = "duration")]
    pub health_interval: Duration,
    #[serde(deserialize_with = "duration")]
    pub health_timeout: Duration,
    pub unhealthy_after: u32,
    pub healthy_after: u32,
    pub eject_after: u32,
    #[serde(deserialize_with = "duration")]
    pub eject_time: Duration,
    pub retries: u32,
    pub retry_budget: f64,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            balance: Balance::RoundRobin,
            health_path: String::new(),
            health_interval: Duration::from_secs(5),
            health_timeout: Duration::from_secs(1),
            unhealthy_after: 3,
            healthy_after: 2,
            eject_after: 5,
            eject_time: Duration::from_secs(30),
            retries: 1,
            retry_budget: 0.2,
        }
    }
}

impl Pool {
    /// The pool for reverse mode. `upstream` alone is one endpoint with no
    /// checks, ejection or retries, as before RFC 0015. URLs are checked
    /// when the proxy builds the pool.
    pub fn config(&self, upstream: Option<&str>) -> Result<PoolConfig, String> {
        todo!("rfc 0015")
    }

    /// [`Pool::config`], then the proxy's pool, which checks the URLs.
    pub fn build(&self, upstream: Option<&str>) -> Result<dvarapala_proxy::Pool, String> {
        todo!("rfc 0015")
    }

    fn health(&self) -> Result<Option<HealthConfig>, String> {
        todo!("rfc 0015")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(f: fn(&mut Pool)) -> Result<PoolConfig, String> {
        let mut p = Pool {
            upstreams: vec!["http://192.0.2.1".into(), "http://192.0.2.2".into()],
            ..Pool::default()
        };
        f(&mut p);
        p.config(None)
    }

    // RFC 0015 case 10
    #[test]
    #[ignore = "rfc 0015"]
    fn bad_values_name_the_key() {
        let both = Pool {
            upstreams: vec!["http://192.0.2.1".into()],
            ..Pool::default()
        };
        let e = both.config(Some("http://192.0.2.9")).unwrap_err();
        assert!(
            e.contains("upstream") && e.contains("pool.upstreams"),
            "{e}"
        );
        let e = pool(|p| p.upstreams = (0..65).map(|i| format!("http://192.0.2.{i}")).collect())
            .unwrap_err();
        assert!(e.contains("pool.upstreams"), "{e}");
        assert!(
            pool(|p| p.retry_budget = 2.0)
                .unwrap_err()
                .contains("pool.retry_budget")
        );
        assert!(
            pool(|p| p.health_path = "healthz".into())
                .unwrap_err()
                .contains("pool.health_path")
        );
        let bad = Pool {
            upstreams: vec!["http://192.0.2.1".into(), "ftp://192.0.2.2".into()],
            ..Pool::default()
        };
        let e = bad.build(None).err().unwrap();
        assert!(e.contains("pool.upstreams") && e.contains("ftp://"), "{e}");
        let e = Pool::default().config(None).unwrap_err();
        assert!(e.contains("upstream"), "{e}");
    }

    #[test]
    #[ignore = "rfc 0015"]
    fn upstream_alone_is_the_old_behavior() {
        let c = Pool::default().config(Some("http://192.0.2.1")).unwrap();
        assert_eq!((c.upstreams.len(), c.retries, c.eject_after), (1, 0, 0));
        let tuned = Pool {
            retries: 0,
            ..Pool::default()
        };
        assert!(tuned.config(Some("http://192.0.2.1")).is_err());
        let c = pool(|p| p.health_path = "/healthz".into()).unwrap();
        assert_eq!(c.health.unwrap().interval, Duration::from_secs(5));
    }
}
