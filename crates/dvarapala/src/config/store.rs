//! The `[store]` section (RFC 0010).

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use super::duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Nothing shared: no task, no socket.
    #[default]
    Memory,
    Redis,
    Postgres,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Store {
    pub backend: Backend,
    /// Holds the password; never logged (see `Debug`).
    pub url: Option<String>,
    pub cluster: String,
    #[serde(deserialize_with = "duration")]
    pub sync_interval: Duration,
    pub max_keys: usize,
    #[serde(deserialize_with = "duration")]
    pub timeout: Duration,
    /// PostgreSQL only: apply missing schema versions at start.
    pub migrate: bool,
    /// PEM roots for `rediss://` and PostgreSQL TLS; system roots if unset.
    pub ca_file: Option<PathBuf>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            backend: Backend::Memory,
            url: None,
            cluster: "dvarapala".into(),
            sync_interval: Duration::from_secs(1),
            max_keys: 10_000,
            timeout: Duration::from_millis(500),
            migrate: true,
            ca_file: None,
        }
    }
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("backend", &self.backend)
            .field("url", &self.url.as_ref().map(|_| "<redacted>"))
            .field("cluster", &self.cluster)
            .field("sync_interval", &self.sync_interval)
            .field("max_keys", &self.max_keys)
            .field("timeout", &self.timeout)
            .field("migrate", &self.migrate)
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

impl Store {
    /// The URL of a shared backend, after checking the other keys; `None`
    /// for `"memory"`.
    pub fn shared_url(&self) -> Result<Option<&str>, String> {
        if self.backend == Backend::Memory {
            return Ok(None);
        }
        if self.sync_interval.is_zero() {
            return Err("store.sync_interval must be above 0".into());
        }
        if self.timeout.is_zero() {
            return Err("store.timeout must be above 0".into());
        }
        if self.max_keys == 0 {
            return Err("store.max_keys must be at least 1".into());
        }
        if self.cluster.is_empty() {
            return Err("store.cluster must not be empty".into());
        }
        match self.url.as_deref() {
            Some(u) if !u.is_empty() => Ok(Some(u)),
            _ => Err(format!(
                "store.url is required with store.backend = \"{}\"",
                match self.backend {
                    Backend::Redis => "redis",
                    _ => "postgres",
                }
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0010 case 12
    #[test]
    fn debug_hides_the_password() {
        let s = Store {
            backend: Backend::Redis,
            url: Some("redis://:<token>@192.0.2.1:6379/0".into()),
            ..Store::default()
        };
        let shown = format!("{s:?}");
        assert!(!shown.contains("<token>"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }

    // RFC 0010 case 13
    #[test]
    fn a_shared_backend_needs_a_url() {
        for backend in [Backend::Redis, Backend::Postgres] {
            let s = Store {
                backend,
                ..Store::default()
            };
            assert!(s.shared_url().unwrap_err().contains("store.url"));
        }
        assert_eq!(Store::default().shared_url(), Ok(None));
    }

    #[test]
    fn rejects_zero_values() {
        let s = Store {
            backend: Backend::Postgres,
            url: Some("postgres://<host>/db".into()),
            max_keys: 0,
            ..Store::default()
        };
        assert!(s.shared_url().unwrap_err().contains("store.max_keys"));
    }
}
