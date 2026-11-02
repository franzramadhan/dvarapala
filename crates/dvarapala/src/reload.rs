//! RFC 0014 config reload: the keys a new config file changes in place,
//! and the ones that keep their running value until a restart.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use dvarapala_engine::{Cidr, Limit, TrustedProxies};
use dvarapala_l7::{ModeLayer, RateLimitLayer, Reload, RouteKey, unix_now};
use hyper::StatusCode;

use crate::admin::switch::Switches;

use crate::config::{self, Config};
use crate::model::{self, Model};

/// The last reload, for the admin API.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// Unix seconds.
    pub at: u64,
    /// The keys that kept their running value, or why the file was refused.
    pub result: Result<Vec<&'static str>, String>,
}

/// Runs after each applied reload with the new config.
pub type OnReload = Box<dyn Fn(&Config) + Send + Sync>;

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
    /// RFC 0021: the file as last applied, and the switches over it
    current: Mutex<Config>,
    /// RFC 0029: the model in force
    model: Mutex<Option<Model>>,
    pub switches: Switches,
    /// RFC 0023: ends the console's LLM sampling switch; RFC 0024: the
    /// label retention.
    pub on_reload: std::sync::OnceLock<OnReload>,
    /// RFC 0032: the upstream limit, when `[concurrency]` is on
    pub concurrency: std::sync::OnceLock<Arc<dvarapala_proxy::Concurrency>>,
    /// RFC 0031: the feeds and the GeoIP database in force
    intel: crate::intel::Running,
}

impl Reloader {
    pub fn new(
        path: Option<PathBuf>,
        layer: Option<RateLimitLayer>,
        waf: crate::waf::Layer,
        ja4: bool,
        start: Config,
        model: Option<Model>,
    ) -> Self {
        model::publish(model.as_ref(), None);
        Self {
            path,
            layer,
            waf,
            ja4,
            routes: Mutex::new(start.routes.clone()),
            current: Mutex::new(start.clone()),
            start,
            last: Mutex::new(None),
            model: Mutex::new(model),
            switches: Switches::default(),
            on_reload: std::sync::OnceLock::new(),
            concurrency: std::sync::OnceLock::new(),
            intel: Default::default(),
        }
    }

    /// RFC 0031: loads `[intel]` at start; a `path` feed or a database
    /// that does not load stops the start. Needs the rate limiter.
    pub fn start_intel(&self) -> Result<(), String> {
        let p = self.intel.prepare(&self.start)?;
        match &self.layer {
            Some(l) => self.intel.commit(p, l),
            None if self.start.intel != config::Intel::default() => {
                tracing::warn!("intel runs inside the reverse proxy's rate limiter, which is off");
            }
            None => {}
        }
        Ok(())
    }

    /// RFC 0031: the `path` feeds and the database `config_watch` polls.
    pub fn intel_files(&self) -> Vec<PathBuf> {
        crate::intel::Running::files(&lock(&self.current))
    }

    /// Reads the file again and applies it, or keeps everything running
    /// when it does not load or validate. Logs and counts the outcome.
    pub fn reload(&self) -> Outcome {
        let result = self.apply();
        match &result {
            Ok(restart) => {
                tracing::info!(msg = "config reloaded", restart = restart.join(","));
                let cur = lock(&self.current);
                self.switches.clear(|l| file_enforce(&cur, l));
                if let Some(f) = self.on_reload.get() {
                    f(&cur);
                }
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
        // RFC 0031: read before anything changes, put in force after
        let intel = self.intel.prepare(&new)?;
        let mut restart = restart(&self.start, &new);
        // RFC 0032: the mode needs a restart, the rest applies in place
        let limit = new.concurrency.config()?;
        if new.concurrency.mode != self.start.concurrency.mode {
            reload.priority = self.start.concurrency.priority();
        }
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
        // RFC 0029: reread on every reload, swapped only when the bytes change
        let mut running = lock(&self.model);
        let model = match (&self.layer, &new.ml.model) {
            (Some(_), Some(p)) => Some(model::load(p, running.as_ref())?),
            _ => None,
        };
        reload.scoring = Some(model::scoring(&new, model.as_ref()));
        if let Some(l) = &self.layer {
            l.reload(reload).map_err(|e| e.to_string())?;
            self.intel.commit(intel, l);
        }
        model::publish(model.as_ref(), running.as_ref());
        *running = model;
        drop(running);
        self.waf.reload(waf);
        if let (Some(c), Some(l)) = (self.concurrency.get(), limit)
            && new.concurrency.mode == self.start.concurrency.mode
        {
            c.reconfigure(l).map_err(|e| format!("concurrency: {e}"))?;
        }
        routes.clone_from(&new.routes);
        *lock(&self.current) = new;
        Ok(restart)
    }

    /// RFC 0029: the model in force.
    pub fn model(&self) -> Option<Model> {
        lock(&self.model).clone()
    }

    /// The config the process started with and the one last applied.
    pub fn configs(&self) -> (Config, Config) {
        (self.start.clone(), lock(&self.current).clone())
    }

    /// RFC 0021: runs `layer` in `enforce` (or observe) until the next
    /// reload, as a reload of its mode key would. Returns the mode it
    /// replaces.
    pub fn switch(
        &self,
        layer: ModeLayer,
        enforce: bool,
        actor: &str,
    ) -> Result<bool, (StatusCode, String)> {
        let conflict = |m: &str| Err((StatusCode::CONFLICT, m.to_owned()));
        let failed = |e: String| (StatusCode::INTERNAL_SERVER_ERROR, e);
        // held like a reload holds it, so the two never interleave
        let _routes = lock(&self.routes);
        let cfg = lock(&self.current).clone();
        match layer {
            ModeLayer::Detection => {
                let Some(l) = self.layer.as_ref().filter(|_| cfg.detection.enabled) else {
                    return conflict("detection is off");
                };
                let mut r = policy(&cfg).map_err(failed)?;
                r.enforce = enforce;
                r.routes = None;
                l.reload(r).map_err(|e| failed(e.to_string()))?;
            }
            ModeLayer::Waf => {
                #[cfg(feature = "waf")]
                {
                    let Some(mut w) = crate::waf::config(&cfg).map_err(failed)? else {
                        return conflict("the waf is off");
                    };
                    w.enforce = enforce;
                    self.waf.reload(Some(w));
                }
                #[cfg(not(feature = "waf"))]
                return conflict("the waf is off");
            }
        }
        Ok(self
            .switches
            .set(layer, enforce, file_enforce(&cfg, layer), actor))
    }

    /// The running mode of `layer`: the switch, else the file.
    pub fn enforce(&self, layer: ModeLayer) -> bool {
        self.switches
            .get(layer)
            .map_or_else(|| file_enforce(&lock(&self.current), layer), |w| w.enforce)
    }
}

fn file_enforce(cfg: &Config, layer: ModeLayer) -> bool {
    let mode = match layer {
        ModeLayer::Detection => cfg.detection.mode,
        ModeLayer::Waf => cfg.waf.mode,
    };
    mode == config::Mode::Enforce
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
    // RFC 0022: only history.retention applies in place, the rest is checked
    cfg.history.samples(&cfg.store)?;
    // RFC 0024: likewise ml.llm.retention
    cfg.ml.llm.check_store(&cfg.store)?;
    cfg.concurrency.config()?;
    Ok(Reload {
        limit: Limit::new(cfg.rate_limit.rate, cfg.rate_limit.burst)
            .map_err(|e| format!("rate_limit: {e}"))?,
        trusted: TrustedProxies::new(trusted),
        enforce: cfg.detection.mode == config::Mode::Enforce,
        attack_rate_factor: cfg.detection.attack_rate_factor,
        challenge: cfg.challenge.config(cfg.detection.enabled)?,
        fingerprints: cfg.fingerprint.rules(cfg.challenge.mode)?,
        routes: Some(config::routes(&cfg.routes, &cfg.intel)?),
        // RFC 0029: the reloader loads the model and fills it in
        scoring: None,
        priority: cfg.concurrency.priority(),
    })
}

/// Whether a reload applies the dotted `key` in place (RFC 0021), the
/// complement of [`restart`].
pub fn in_place(key: &str, cfg: &Config) -> bool {
    let (top, rest) = key.split_once('.').unwrap_or((key, ""));
    match top {
        "trusted_proxies" | "challenge" | "fingerprint" | "routes" | "waf" | "intel" => true,
        // the cluster budget (RFC 0010) is set at start
        "rate_limit" => {
            matches!(rest, "rate" | "burst") && cfg.store.backend == config::Backend::Memory
        }
        "detection" => matches!(rest, "mode" | "attack_rate_factor"),
        // RFC 0022: the sampling task reads it at each sweep
        "history" => rest == "retention",
        // RFC 0024: the sweep reads it each hour
        // RFC 0029: the model and its threshold too
        "ml" => matches!(rest, "llm.retention" | "model" | "threshold"),
        // RFC 0032: the limit and its bounds, not the mode
        "concurrency" => rest != "mode",
        _ => false,
    }
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
        // RFC 0029: only [ml.llm] is left, less its retention (RFC 0024)
        ("ml", {
            let mut llm = new.ml.llm.clone();
            llm.retention = start.ml.llm.retention;
            start.ml.llm != llm
        }),
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
        (
            "concurrency.mode",
            start.concurrency.mode != new.concurrency.mode,
        ),
        (
            "history",
            config::History {
                retention: new.history.retention,
                ..start.history.clone()
            } != new.history,
        ),
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
#[path = "reload_tests.rs"]
mod tests;
