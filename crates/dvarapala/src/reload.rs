//! RFC 0014 config reload: the keys a new config file changes in place,
//! and the ones that keep their running value until a restart.

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
    /// RFC 0017: off until a reload turns it on, when built
    waf: crate::waf::Layer,
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
        waf: crate::waf::Layer,
        ja4: bool,
        start: Config,
    ) -> Self {
        Self {
            path,
            layer,
            waf,
            ja4,
            routes: Mutex::new(start.routes.clone()),
            start,
            last: Mutex::new(None),
        }
    }

    /// Reads the file again and applies it, or keeps everything running
    /// when it does not load or validate. Logs and counts the outcome.
    pub fn reload(&self) -> Outcome {
        let result = self.apply();
        match &result {
            Ok(restart) => {
                tracing::info!(msg = "config reloaded", restart = restart.join(","));
                ::metrics::counter!("dvarapala_config_reloads_total", "result" => "ok")
                    .increment(1);
            }
            Err(e) => {
                tracing::warn!(msg = "config reload failed", error = %e);
                ::metrics::counter!("dvarapala_config_reloads_total", "result" => "failed")
                    .increment(1);
            }
        }
        let outcome = Outcome {
            at: unix_now(),
            result,
        };
        *lock(&self.last) = Some(outcome.clone());
        outcome
    }

    pub fn last(&self) -> Option<Outcome> {
        lock(&self.last).clone()
    }

    fn apply(&self) -> Result<Vec<&'static str>, String> {
        let new = config::load(self.path.as_deref()).map_err(|e| e.to_string())?;
        let mut reload = policy(&new)?;
        let waf = crate::waf::config(&new)?;
        let mut restart = restart(&self.start, &new);
        let ja4 = reload.fingerprints.enabled()
            || reload
                .routes
                .iter()
                .flatten()
                .any(|r| r.key == RouteKey::Ja4);
        if ja4 && !self.ja4 {
            restart.push("fingerprint (JA4 at the TLS listener)");
        }
        let mut routes = lock(&self.routes);
        if new.routes == *routes {
            reload.routes = None;
        }
        if let Some(l) = &self.layer {
            l.reload(reload).map_err(|e| e.to_string())?;
        }
        self.waf.reload(waf);
        *routes = new.routes;
        Ok(restart)
    }
}

/// Reloads on every `SIGHUP`.
pub fn on_hangup(r: Arc<Reloader>) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hup = signal(SignalKind::hangup())?;
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                r.reload();
            }
        });
    }
    #[cfg(not(unix))]
    let _ = r;
    Ok(())
}

/// The keys the layer applies in place, validated as at start.
pub fn policy(cfg: &Config) -> Result<Reload, String> {
    let trusted = cfg
        .trusted_proxies
        .iter()
        .map(|c| {
            c.parse::<Cidr>()
                .map_err(|e| format!("trusted_proxies: {e}"))
        })
        .collect::<Result<_, _>>()?;
    // RFC 0015: needs a restart, but a bad [pool] still refuses the file
    if cfg.mode == config::ProxyMode::Reverse {
        cfg.pool.config(cfg.upstream.as_deref())?;
    }
    Ok(Reload {
        limit: Limit::new(cfg.rate_limit.rate, cfg.rate_limit.burst)
            .map_err(|e| format!("rate_limit: {e}"))?,
        trusted: TrustedProxies::new(trusted),
        enforce: cfg.detection.mode == config::Mode::Enforce,
        attack_rate_factor: cfg.detection.attack_rate_factor,
        challenge: cfg.challenge.config(cfg.detection.enabled)?,
        fingerprints: cfg.fingerprint.rules(cfg.challenge.mode)?,
        routes: Some(config::routes(&cfg.routes)?),
    })
}

/// The keys that differ from `start` but need a restart.
pub fn restart(start: &Config, new: &Config) -> Vec<&'static str> {
    // detection keys other than the two a reload applies
    let fixed = |d: &config::Detection| config::Detection {
        mode: config::Mode::Observe,
        attack_rate_factor: 0.0,
        ..d.clone()
    };
    let (a, b) = (&start.rate_limit, &new.rate_limit);
    let shared = start.store.backend != config::Backend::Memory;
    [
        ("mode", start.mode != new.mode),
        ("listen", start.listen != new.listen),
        ("upstream", start.upstream != new.upstream),
        (
            "upstream_protocol",
            start.upstream_protocol != new.upstream_protocol,
        ),
        ("metrics", start.metrics != new.metrics),
        ("rate_limit.enabled", a.enabled != b.enabled),
        ("rate_limit.max_clients", a.max_clients != b.max_clients),
        // the cluster budget (RFC 0010) is set at start
        (
            "rate_limit (store budget)",
            shared && (a.rate, a.burst) != (b.rate, b.burst),
        ),
        (
            "detection",
            fixed(&start.detection) != fixed(&new.detection),
        ),
        ("ml", start.ml != new.ml),
        ("tls", start.tls != new.tls),
        ("upstream_tls", start.upstream_tls != new.upstream_tls),
        ("http2", start.http2 != new.http2),
        ("upgrade", start.upgrade != new.upgrade),
        ("forward", start.forward != new.forward),
        ("l4", start.l4 != new.l4),
        ("quic", start.quic != new.quic),
        ("store", start.store != new.store),
        ("xdp", start.xdp != new.xdp),
        ("admin", start.admin != new.admin),
        ("pool", start.pool != new.pool),
        ("config_watch", start.config_watch != new.config_watch),
    ]
    .into_iter()
    .filter_map(|(k, changed)| changed.then_some(k))
    .collect()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
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
        Reloader::new(
            Some(path.into()),
            Some(layer),
            Default::default(),
            false,
            start,
        )
    }

    // RFC 0014 case 7
    #[test]
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
    fn ja4_needs_a_restart_bad_keys_refuse_the_file() {
        Jail::expect_with(|j| {
            j.create_file("d.toml", BASE)?;
            let r = reloader("d.toml");
            j.create_file(
                "d.toml",
                &format!("{BASE}[fingerprint]\ndeny = [\"t13d*\"]\n"),
            )?;
            assert_eq!(
                r.reload().result,
                Ok(vec!["fingerprint (JA4 at the TLS listener)"])
            );
            j.create_file("d.toml", &format!("{BASE}trusted_proxies = [\"nope\"]\n"))?;
            let e = r.reload().result.unwrap_err();
            assert!(e.contains("trusted_proxies"), "{e}");
            j.create_file(
                "d.toml",
                &format!("{BASE}[pool]\nupstreams = [\"http://192.0.2.1\"]\n"),
            )?;
            let e = r.reload().result.unwrap_err();
            assert!(e.contains("pool.upstreams"), "{e}");
            Ok(())
        });
    }

    #[test]
    fn detection_mode_and_factor_reload_in_place() {
        // in a jail, so no `DVARAPALA__*` another test sets leaks in
        let mut defaults = None;
        Jail::expect_with(|_| {
            defaults = Some(config::load(None).map_err(|e| e.to_string())?);
            Ok(())
        });
        let start = Config {
            upstream: Some("http://127.0.0.1:8081".into()),
            ..defaults.unwrap()
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
