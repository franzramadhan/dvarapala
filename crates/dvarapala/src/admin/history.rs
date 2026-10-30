//! RFC 0022: the sampling task behind `GET /history`, a ring in memory and
//! optionally minute rows in the PostgreSQL store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{Minute, Ring, Sample, Sampler, State, VERDICTS};
use dvarapala_l7::{RateLimitLayer, request_totals};

use crate::config;
use crate::reload::Reloader;

const NAMES: [&str; VERDICTS] = ["allow", "throttle", "challenge", "drop", "error"];
/// Minute rows between two retention sweeps.
const SWEEP_EVERY: u64 = 60;

#[cfg(feature = "postgres")]
pub type Db = Arc<tokio::sync::Mutex<dvarapala_store::Postgres>>;

pub struct History {
    ring: Mutex<Ring>,
    interval_ms: u64,
    window_ms: u64,
    #[cfg(feature = "postgres")]
    db: Option<(Db, String, Duration)>,
    down: AtomicBool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn state(name: &str) -> Option<State> {
    Some(match name {
        "normal" => State::Normal,
        "suspect" => State::Suspect,
        "attack" => State::Attack,
        "cooldown" => State::Cooldown,
        _ => return None,
    })
}

impl History {
    /// Checks `[history]` and starts the sampling task.
    pub fn start(
        cfg: &config::Config,
        layer: Option<RateLimitLayer>,
        reloader: Arc<Reloader>,
    ) -> Result<Arc<Self>, String> {
        let h = &cfg.history;
        let samples = h.samples(&cfg.store)?;
        let history = Arc::new(Self {
            ring: Mutex::new(Ring::new(samples)),
            interval_ms: h.interval.as_millis() as u64,
            window_ms: h.window.as_millis() as u64,
            #[cfg(feature = "postgres")]
            db: db(cfg)?,
            down: AtomicBool::new(false),
        });
        #[cfg(not(feature = "postgres"))]
        if h.persist {
            return Err("history.persist needs a binary built with the postgres feature".into());
        }
        let task = history.clone();
        let interval = h.interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            let mut sampler = Sampler::default();
            let mut minutes = 0u64;
            loop {
                tick.tick().await;
                let totals = request_totals().map(|(_, n)| n);
                let st = layer
                    .as_ref()
                    .and_then(|l| l.status().detection)
                    .and_then(state);
                let (sample, minute) = sampler.sample(now_ms(), totals, st);
                if let Some(s) = sample {
                    lock(&task.ring).push(s);
                }
                if let Some(m) = minute {
                    minutes += 1;
                    let retention = minutes
                        .is_multiple_of(SWEEP_EVERY)
                        .then(|| reloader.configs().1.history.retention);
                    task.persist(m, retention);
                }
            }
        });
        Ok(history)
    }

    /// The `GET /history` body for the last `range_secs`.
    pub async fn answer(&self, range_secs: u64) -> String {
        let now = now_ms();
        let since = now.saturating_sub(range_secs * 1000);
        let ring = lock(&self.ring).since(since);
        let mut out = Vec::new();
        let mut source = "memory";
        let mut interval_ms = self.interval_ms;
        if range_secs * 1000 > self.window_ms {
            // the ring's oldest point, or now when it is still empty
            let edge = ring.first().map_or(now, |s| s.t_ms);
            if let Some(minutes) = self.read(since).await {
                source = "store";
                interval_ms = 60_000;
                out.extend(
                    minutes
                        .iter()
                        .filter(|m| m.minute_ms + 60_000 <= edge)
                        .map(minute_sample),
                );
            }
        }
        out.extend(ring);
        let samples: Vec<_> = out.iter().map(sample_json).collect();
        serde_json::json!({
            "interval_ms": interval_ms,
            "source": source,
            "samples": samples,
        })
        .to_string()
    }

    /// Writes a minute row in the background; one write at a time.
    #[allow(unused_variables)]
    fn persist(self: &Arc<Self>, m: Minute, retention: Option<Duration>) {
        #[cfg(feature = "postgres")]
        if let Some((db, cluster, timeout)) = &self.db {
            let Ok(mut pg) = db.clone().try_lock_owned() else {
                ::metrics::counter!("dvarapala_history_writes_total", "result" => "skipped")
                    .increment(1);
                return;
            };
            let (me, cluster, timeout) = (self.clone(), cluster.clone(), *timeout);
            let replica = crate::store::replica();
            tokio::spawn(async move {
                let r = tokio::time::timeout(timeout, pg.history_write(&cluster, replica, &m))
                    .await
                    .map_err(|_| dvarapala_store::Error("timed out".into()))
                    .and_then(|r| r);
                let result = if r.is_ok() { "ok" } else { "error" };
                ::metrics::counter!("dvarapala_history_writes_total", "result" => result)
                    .increment(1);
                me.health(r.as_ref().err());
                if let (Ok(()), Some(keep)) = (r, retention) {
                    let before = m.minute_ms.saturating_sub(keep.as_millis() as u64);
                    let n =
                        tokio::time::timeout(timeout, pg.history_expire(&cluster, before)).await;
                    if let Ok(Ok(n)) = n {
                        ::metrics::counter!("dvarapala_history_rows_deleted_total").increment(n);
                    }
                }
            });
        }
    }

    /// The store's minutes since `since`, `None` without a store or on a
    /// failure (logged once).
    #[allow(unused_variables)]
    async fn read(&self, since: u64) -> Option<Vec<Minute>> {
        #[cfg(feature = "postgres")]
        if let Some((db, cluster, timeout)) = &self.db {
            let r = match tokio::time::timeout(*timeout, db.lock()).await {
                Ok(mut pg) => tokio::time::timeout(*timeout, pg.history_read(cluster, since))
                    .await
                    .map_err(|_| dvarapala_store::Error("timed out".into()))
                    .and_then(|r| r),
                Err(_) => Err(dvarapala_store::Error("busy".into())),
            };
            self.health(r.as_ref().err());
            return r.ok();
        }
        None
    }

    /// Logs the first failure of an outage and the recovery.
    #[allow(dead_code)]
    fn health(&self, e: Option<&dvarapala_store::Error>) {
        match e {
            Some(e) if !self.down.swap(true, Ordering::Relaxed) => {
                tracing::warn!(msg = "history store unavailable", error = %e);
            }
            None if self.down.swap(false, Ordering::Relaxed) => {
                tracing::info!(msg = "history store recovered");
            }
            _ => {}
        }
    }
}

#[cfg(feature = "postgres")]
fn db(cfg: &config::Config) -> Result<Option<(Db, String, Duration)>, String> {
    if !cfg.history.persist {
        return Ok(None);
    }
    connect(cfg, "history.persist").map(Some)
}

/// A connection of its own to the PostgreSQL store, its cluster and the
/// timeout of one call; `key` names the setting that needs it.
#[cfg(feature = "postgres")]
pub fn connect(cfg: &config::Config, key: &str) -> Result<(Db, String, Duration), String> {
    let url = cfg
        .store
        .shared_url()?
        .ok_or_else(|| format!("{key} needs store.url"))?;
    let ca = cfg
        .store
        .ca_file
        .as_ref()
        .map(|p| std::fs::read(p).map_err(|e| format!("store.ca_file {}: {e}", p.display())))
        .transpose()?;
    let pg =
        dvarapala_store::Postgres::new(url, ca.as_deref(), cfg.store.migrate, cfg.store.timeout)
            .map_err(|e| e.to_string())?;
    // connecting, migrations included, may take 10 times a round
    let timeout = cfg.store.timeout * 10;
    Ok((
        Arc::new(tokio::sync::Mutex::new(pg)),
        cfg.store.cluster.clone(),
        timeout,
    ))
}

fn minute_sample(m: &Minute) -> Sample {
    Sample {
        t_ms: m.minute_ms + 60_000,
        rates: std::array::from_fn(|i| m.counts[i] as f64 / 60.0),
        state: None,
    }
}

fn sample_json(s: &Sample) -> serde_json::Value {
    let mut o = serde_json::Map::new();
    o.insert("t".into(), s.t_ms.into());
    for (name, rate) in NAMES.iter().zip(s.rates) {
        // two decimals are plenty for a graph
        o.insert((*name).into(), ((rate * 100.0).round() / 100.0).into());
    }
    o.insert(
        "detection".into(),
        s.state
            .map_or(serde_json::Value::Null, |st| st.name().into()),
    );
    serde_json::Value::Object(o)
}
