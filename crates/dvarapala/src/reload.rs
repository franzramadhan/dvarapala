//! RFC 0014 config reload: the keys a new config file changes in place,
//! and the ones that keep their running value until a restart.
#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use dvarapala_engine::{Cidr, Limit, TrustedProxies};
use dvarapala_l7::{RateLimitLayer, Reload, RouteKey, unix_now};

use crate::config::{self, Config};

/// The last reload, for the admin API.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Unix seconds.
    pub at: u64,
    /// The keys that kept their running value, or why the file was refused.
    pub result: Result<Vec<&'static str>, String>,
}

pub struct Reloader {
    /// The file the process started with; `None` reads the environment only.
    path: Option<PathBuf>,
    layer: Option<RateLimitLayer>,
    /// whether the TLS listener computes JA4
    ja4: bool,
    /// restart keys are compared with this, the config they still hold
    start: Config,
    /// the routes in force, so an unchanged list keeps its buckets
    routes: Mutex<Vec<config::Route>>,
    last: Mutex<Option<Outcome>>,
}

impl Reloader {
    pub fn new(
        path: Option<PathBuf>,
        layer: Option<RateLimitLayer>,
        ja4: bool,
        start: Config,
    ) -> Self {
        todo!("rfc 0014")
    }

    /// Reads the file again and applies it, or keeps everything running
    /// when it does not load or validate. Logs and counts the outcome.
    pub fn reload(&self) -> Outcome {
        todo!("rfc 0014")
    }

    pub fn last(&self) -> Option<Outcome> {
        todo!("rfc 0014")
    }

    fn apply(&self) -> Result<Vec<&'static str>, String> {
        todo!("rfc 0014")
    }
}

/// Reloads on every `SIGHUP`.
pub fn on_hangup(r: Arc<Reloader>) -> std::io::Result<()> {
    todo!("rfc 0014")
}

/// The keys the layer applies in place, validated as at start.
pub fn policy(cfg: &Config) -> Result<Reload, String> {
    todo!("rfc 0014")
}

/// The keys that differ from `start` but need a restart.
pub fn restart(start: &Config, new: &Config) -> Vec<&'static str> {
    todo!("rfc 0014")
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    todo!("rfc 0014")
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::time::Instant;

    use dvarapala_l7::RateLimitConfig;
    use figment::Jail;

    use super::*;

    const BASE: &str = "upstream = \"http://127.0.0.1:8081\"\nlisten = \"127.0.0.1:8080\"\n";

    fn reloader(path: &str) -> Reloader {
        let start = config::load(Some(Path::new(path))).unwrap();
        let layer = RateLimitLayer::new(RateLimitConfig {
            limit: Limit::new(10, 10).unwrap(),
            max_clients: NonZeroUsize::new(16).unwrap(),
            trusted: TrustedProxies::new(Vec::new()),
            detection: None,
            scoring: None,
            now: Instant::now,
            cluster: None,
            block: None,
            challenge: None,
            fingerprints: Default::default(),
            routes: Vec::new(),
            max_blocks: 4,
        })
        .unwrap();
        Reloader::new(Some(path.into()), Some(layer), false, start)
    }

    // RFC 0014 case 7
    #[test]
    #[ignore = "rfc 0014"]
    fn rate_applied_listen_needs_a_restart() {
        Jail::expect_with(|j| {
            j.create_file("d.toml", &format!("{BASE}[rate_limit]\nrate = 10\n"))?;
            let r = reloader("d.toml");
            j.create_file(
                "d.toml",
                "upstream = \"http://127.0.0.1:8081\"\nlisten = \"127.0.0.1:9000\"\n[rate_limit]\nrate = 1\nburst = 1\n",
            )?;
            let out = r.reload();
            assert_eq!(out.result, Ok(vec!["listen"]));
            assert_eq!(r.last(), Some(out));
            Ok(())
        });
    }

    // RFC 0014 case 8
    #[test]
    #[ignore = "rfc 0014"]
    fn invalid_route_refused_whole() {
        Jail::expect_with(|j| {
            j.create_file("d.toml", BASE)?;
            let r = reloader("d.toml");
            j.create_file(
                "d.toml",
                &format!("{BASE}[rate_limit]\nrate = 1\n[[routes]]\nname = \"x\"\npath = \"\"\n"),
            )?;
            let e = r.reload().result.unwrap_err();
            assert!(e.contains("routes \"x\""), "{e}");
            // the routes in force did not move
            assert!(lock(&r.routes).is_empty());
            j.create_file("d.toml", "not toml [")?;
            assert!(r.reload().result.is_err());
            Ok(())
        });
    }

    #[test]
    #[ignore = "rfc 0014"]
    fn detection_mode_and_factor_reload_in_place() {
        let start = Config {
            upstream: Some("http://127.0.0.1:8081".into()),
            ..config::load(None).unwrap()
        };
        let mut new = start.clone();
        new.detection.mode = config::Mode::Enforce;
        new.detection.attack_rate_factor = 0.5;
        new.rate_limit.rate = 1;
        assert!(restart(&start, &new).is_empty());
        new.detection.window = std::time::Duration::from_secs(9);
        new.store.backend = config::Backend::Redis;
        assert_eq!(restart(&start, &new), ["detection", "store"]);
    }
}
