//! The `[pool]` section (RFC 0015).

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
        match (upstream, self.upstreams.is_empty()) {
            (Some(_), false) => {
                return Err("upstream and pool.upstreams are both set: keep one".into());
            }
            (None, true) => {
                return Err(
                    "upstream or pool.upstreams is required with mode = \"reverse\"".into(),
                );
            }
            (Some(u), true) if *self == Self::default() => return Ok(PoolConfig::single(u)),
            (Some(_), true) => {
                return Err("[pool] needs pool.upstreams in place of upstream".into());
            }
            (None, false) => {}
        }
        let n = self.upstreams.len();
        if n > MAX_UPSTREAMS {
            return Err(format!(
                "pool.upstreams: {n} upstreams, at most {MAX_UPSTREAMS}"
            ));
        }
        if !(0.0..=1.0).contains(&self.retry_budget) {
            return Err(format!(
                "pool.retry_budget: {} is outside [0, 1]",
                self.retry_budget
            ));
        }
        if self.eject_after > 0 && self.eject_time.is_zero() {
            return Err("pool.eject_time must be above 0 with eject_after".into());
        }
        Ok(PoolConfig {
            upstreams: self.upstreams.clone(),
            balance: match self.balance {
                Balance::RoundRobin => ProxyBalance::RoundRobin,
                Balance::LeastRequests => ProxyBalance::LeastRequests,
            },
            health: self.health()?,
            eject_after: self.eject_after,
            eject_time: self.eject_time,
            retries: self.retries,
            retry_budget: self.retry_budget,
            now: Instant::now,
        })
    }

    /// [`Pool::config`], then the proxy's pool, which checks the URLs.
    pub fn build(&self, upstream: Option<&str>) -> Result<dvarapala_proxy::Pool, String> {
        let key = if upstream.is_some() {
            "upstream"
        } else {
            "pool.upstreams"
        };
        dvarapala_proxy::Pool::new(self.config(upstream)?).map_err(|e| format!("{key}: {e}"))
    }

    fn health(&self) -> Result<Option<HealthConfig>, String> {
        if self.health_path.is_empty() {
            return Ok(None);
        }
        if !self.health_path.starts_with('/') {
            return Err(format!(
                "pool.health_path: {:?} must start with /",
                self.health_path
            ));
        }
        if self.health_interval.is_zero() || self.health_timeout.is_zero() {
            return Err("pool.health_interval and pool.health_timeout must be above 0".into());
        }
        if self.unhealthy_after == 0 || self.healthy_after == 0 {
            return Err("pool.unhealthy_after and pool.healthy_after must be at least 1".into());
        }
        Ok(Some(HealthConfig {
            path: self.health_path.clone(),
            interval: self.health_interval,
            timeout: self.health_timeout,
            unhealthy_after: self.unhealthy_after,
            healthy_after: self.healthy_after,
        }))
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
