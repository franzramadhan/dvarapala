//! Config from a TOML file, overridden by `DVARAPALA__*` environment
//! variables (`DVARAPALA__RATE_LIMIT__RATE=5` sets `rate_limit.rate`).

use std::net::SocketAddr;
use std::path::Path;

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub upstream: String,
    #[serde(default)]
    pub metrics: Metrics,
    #[serde(default)]
    pub rate_limit: RateLimit,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Metrics {
    /// Empty turns the endpoint off.
    pub listen: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RateLimit {
    pub enabled: bool,
    pub rate: u32,
    pub burst: u32,
    pub max_clients: usize,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8080))
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:9090".into(),
        }
    }
}

impl Default for RateLimit {
    fn default() -> Self {
        Self {
            enabled: true,
            rate: 20,
            burst: 40,
            max_clients: 100_000,
        }
    }
}

/// Reads `path` (when given) and the environment.
pub fn load(path: Option<&Path>) -> Result<Config, Box<figment::Error>> {
    let mut f = Figment::new();
    if let Some(path) = path {
        // file_exact: a missing --config file is an error, not an empty config
        f = f.merge(Toml::file_exact(path));
    }
    f.merge(Env::prefixed("DVARAPALA__").split("__"))
        .extract()
        .map_err(Box::new)
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;

    #[test]
    fn env_overrides_file() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\n[rate_limit]\nrate = 50\n",
            )?;
            j.set_env("DVARAPALA__RATE_LIMIT__RATE", "5");
            let c = load(Some(Path::new("d.toml"))).map_err(|e| e.to_string())?;
            assert_eq!(c.rate_limit.rate, 5);
            assert_eq!(c.rate_limit.burst, 40);
            Ok(())
        });
    }

    #[test]
    fn missing_upstream_names_the_key() {
        Jail::expect_with(|j| {
            j.create_file("d.toml", "listen = \"127.0.0.1:8080\"\n")?;
            let e = load(Some(Path::new("d.toml"))).unwrap_err().to_string();
            assert!(e.contains("upstream"), "{e}");
            Ok(())
        });
    }

    #[test]
    fn defaults_match_the_rfc() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            let c = load(None).map_err(|e| e.to_string())?;
            assert_eq!(c.listen, "0.0.0.0:8080".parse().unwrap());
            assert_eq!(c.metrics.listen, "127.0.0.1:9090");
            assert_eq!(
                c.rate_limit,
                RateLimit {
                    enabled: true,
                    rate: 20,
                    burst: 40,
                    max_clients: 100_000
                }
            );
            assert!(c.trusted_proxies.is_empty());
            Ok(())
        });
    }

    #[test]
    fn unknown_key_is_an_error() {
        Jail::expect_with(|j| {
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\nrate_limt = {}\n",
            )?;
            let e = load(Some(Path::new("d.toml"))).unwrap_err().to_string();
            assert!(e.contains("rate_limt"), "{e}");
            Ok(())
        });
    }

    #[test]
    fn example_config_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/dvarapala.toml");
        load(Some(&path)).unwrap();
    }
}
