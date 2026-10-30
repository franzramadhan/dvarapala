//! The sampling switch with its timer, the recent labels, the counts, the
//! export file and, with `persist`, the store (RFC 0024).

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use dvarapala_engine::FEATURE_NAMES;
use dvarapala_l7::{Answer, Llm, Sample};
use serde_json::{Map, Value, json};

#[cfg(feature = "postgres")]
use super::persist::Persist;
use crate::config::{self, parse_duration};

/// Labels `GET /llm` keeps.
const RECENT: usize = 200;
/// `POST /llm?on` without a duration.
const DEFAULT_ON: Duration = Duration::from_secs(30 * 60);

pub struct Labels {
    pub llm: Arc<Llm>,
    max_duration: Duration,
    /// The console's deadline in Unix ms, and a generation that a newer
    /// switch bumps so an older timer does nothing.
    until: Mutex<(Option<u64>, u64)>,
    recent: Mutex<VecDeque<Value>>,
    counts: Mutex<BTreeMap<(String, &'static str), u64>>,
    export: Option<Mutex<Export>>,
    #[cfg(feature = "postgres")]
    pub persist: std::sync::OnceLock<Arc<Persist>>,
}

struct Export {
    file: File,
    written: u64,
    max: u64,
    full: bool,
}

impl Labels {
    pub fn new(llm: Arc<Llm>, c: &config::Llm) -> Result<Arc<Self>, String> {
        let export = c
            .export
            .as_ref()
            .map(|p| {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .map_err(|e| format!("ml.llm.export {}: {e}", p.display()))?;
                let written = file.metadata().map_or(0, |m| m.len());
                Ok::<_, String>(Mutex::new(Export {
                    file,
                    written,
                    max: c.export_max as u64,
                    full: false,
                }))
            })
            .transpose()?;
        Ok(Arc::new(Self {
            llm,
            max_duration: c.max_duration,
            until: Mutex::new((None, 0)),
            recent: Mutex::new(VecDeque::new()),
            counts: Mutex::new(BTreeMap::new()),
            export,
            #[cfg(feature = "postgres")]
            persist: std::sync::OnceLock::new(),
        }))
    }

    /// `POST /llm?on=<d>`: samples until now plus `d`; returns the
    /// deadline in Unix ms.
    pub fn on(self: &Arc<Self>, d: &str, by: &str) -> Result<u64, String> {
        let d = if d.is_empty() {
            DEFAULT_ON
        } else {
            parse_duration(d)?
        };
        if d.is_zero() || d > self.max_duration {
            return Err("on must be above 0 and at most ml.llm.max_duration".into());
        }
        let until = unix_ms() + d.as_millis() as u64;
        let generation = {
            let mut u = lock(&self.until);
            u.1 += 1;
            u.0 = Some(until);
            u.1
        };
        self.llm.set(true);
        tracing::info!(msg = "llm sampling", on = true, until, by);
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(d).await;
            if lock(&me.until).1 == generation {
                me.off("expired");
            }
        });
        Ok(until)
    }

    /// Stops sampling: `console`, `expired` or `reload`.
    pub fn off(&self, reason: &str) {
        {
            let mut u = lock(&self.until);
            u.0 = None;
            u.1 += 1;
        }
        if self.llm.sampling() {
            tracing::info!(msg = "llm sampling", on = false, reason);
        }
        self.llm.set(false);
    }

    /// A reload ends the console's switch; `enabled = true` keeps sampling.
    /// `retention` applies to the next sweep.
    #[allow(unused_variables)]
    pub fn reload(&self, c: &config::Llm) {
        #[cfg(feature = "postgres")]
        if let Some(p) = self.persist.get() {
            p.set_retention(c.retention);
        }
        if self.llm.enabled() {
            lock(&self.until).0 = None;
        } else {
            self.off("reload");
        }
    }

    /// One answer: the recent list, the counts and the export line.
    pub fn record(&self, s: &Sample, a: &Answer) {
        let at = unix_ms();
        {
            let mut r = lock(&self.recent);
            if r.len() == RECENT {
                r.pop_front();
            }
            r.push_back(json!({
                "at": at,
                "trigger": s.trigger,
                "route": s.route,
                "method": s.method,
                "path": s.path,
                "label": a.label,
                "confidence": a.confidence,
                "pattern": a.pattern,
            }));
        }
        *lock(&self.counts)
            .entry((a.label.clone(), s.trigger))
            .or_default() += 1;
        let features = s.features.as_ref().map(|f| {
            FEATURE_NAMES
                .iter()
                .zip(f)
                .map(|(k, v)| ((*k).to_owned(), json!(v)))
                .collect::<Map<_, _>>()
        });
        if let (Some(e), Some(f)) = (&self.export, &features) {
            lock(e).write(line(f.clone(), &a.label, a.confidence, s.trigger, at));
        }
        #[cfg(feature = "postgres")]
        if let Some(p) = self.persist.get() {
            p.push(row(s, a, at, features));
        }
    }

    /// `GET /llm`: from the store with `persist`, else (or when it fails)
    /// this process's memory.
    #[cfg_attr(not(feature = "postgres"), allow(unused_mut))]
    pub async fn answer(&self) -> String {
        let mut j = self.json();
        #[cfg(feature = "postgres")]
        if let Some(p) = self.persist.get()
            && let Some((counts, recent)) = p.read().await
        {
            j["source"] = "store".into();
            j["counts"] = counts
                .iter()
                .map(|(label, trigger, n)| json!({"label": label, "trigger": trigger, "count": n}))
                .collect();
            j["recent"] = recent
                .iter()
                .map(|r| {
                    json!({
                        "at": r.at_ms,
                        "trigger": r.trigger,
                        "route": r.route,
                        "method": r.method,
                        "path": r.path,
                        "label": r.label,
                        "confidence": r.confidence,
                        "pattern": r.pattern,
                    })
                })
                .collect();
        }
        j.to_string()
    }

    /// `GET /llm/export`: the stored rows as JSON lines, `None` without
    /// `persist`.
    #[allow(unused_variables)]
    pub fn export(
        &self,
        q: dvarapala_l7::ExportQuery,
    ) -> Option<tokio::sync::mpsc::Receiver<Result<String, dvarapala_store::Error>>> {
        #[cfg(feature = "postgres")]
        if let Some(p) = self.persist.get() {
            return Some(p.export(q));
        }
        None
    }

    /// `GET /llm`.
    pub fn json(&self) -> Value {
        let counts: Vec<Value> = lock(&self.counts)
            .iter()
            .map(|((label, trigger), n)| json!({"label": label, "trigger": trigger, "count": n}))
            .collect();
        let recent: Vec<Value> = lock(&self.recent).iter().rev().cloned().collect();
        json!({
            "configured": true,
            "sampling": self.llm.sampling(),
            "until": lock(&self.until).0,
            "enabled": self.llm.enabled(),
            "max_duration_secs": self.max_duration.as_secs(),
            "counts": counts,
            "recent": recent,
            "source": "memory",
        })
    }
}

/// An export line, in the file and from the store: the features, the
/// label, the confidence, the trigger and the time.
fn line(mut o: Map<String, Value>, label: &str, confidence: f64, trigger: &str, at: u64) -> String {
    o.insert("label".into(), label.into());
    o.insert("confidence".into(), confidence.into());
    o.insert("trigger".into(), trigger.into());
    o.insert("at".into(), at.into());
    Value::Object(o).to_string()
}

/// The stored row of one answer.
#[cfg(feature = "postgres")]
fn row(
    s: &Sample,
    a: &Answer,
    at: u64,
    f: Option<Map<String, Value>>,
) -> dvarapala_store::LabelRow {
    dvarapala_store::LabelRow {
        at_ms: at,
        trigger: s.trigger.into(),
        route: s.route.clone(),
        method: s.method.clone(),
        path: s.path.clone(),
        label: a.label.clone(),
        confidence: a.confidence,
        pattern: a.pattern.clone(),
        features: f.map(|f| Value::Object(f).to_string()),
        ..Default::default()
    }
}

/// A stored row's export line.
#[cfg(feature = "postgres")]
pub fn export_line(r: &dvarapala_store::LabelRow) -> String {
    let features = r
        .features
        .as_deref()
        .and_then(|f| serde_json::from_str(f).ok())
        .unwrap_or_default();
    line(features, &r.label, r.confidence, &r.trigger, r.at_ms)
}

impl Export {
    fn write(&mut self, mut line: String) {
        line.push('\n');
        if self.full {
            return;
        }
        if self.written + line.len() as u64 > self.max {
            self.full = true;
            tracing::warn!(msg = "llm export full, stopped", max = self.max);
            return;
        }
        match self.file.write_all(line.as_bytes()) {
            Ok(()) => self.written += line.len() as u64,
            Err(e) => tracing::warn!(msg = "llm export failed", error = %e),
        }
    }
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use dvarapala_l7::LlmConfig;

    use super::*;

    fn labels(enabled: bool) -> Arc<Labels> {
        let cfg = LlmConfig {
            triggers: Vec::new(),
            per_client: Duration::from_secs(600),
            headers: Vec::new(),
            body_bytes: 0,
            max_clients: 10,
            enabled,
        };
        let llm = Arc::new(Llm::new(cfg, Box::new(|_| true), Instant::now));
        llm.set(enabled);
        let c = config::Llm {
            max_duration: Duration::from_secs(3600),
            ..config::Llm::default()
        };
        Labels::new(llm, &c).unwrap()
    }

    // RFC 0023 case 11
    #[tokio::test]
    async fn switch_expires() {
        let l = labels(false);
        assert!(l.on("2h", "token").is_err());
        assert!(l.on("0s", "token").is_err());
        let until = l.on("1s", "token").unwrap();
        assert!(l.llm.sampling());
        assert_eq!(l.json()["until"], until);
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(!l.llm.sampling());
        assert_eq!(l.json()["until"], Value::Null);
    }

    // RFC 0023 case 12, the switch
    #[tokio::test]
    async fn reload_stops_unless_enabled() {
        let l = labels(false);
        l.on("", "token").unwrap();
        l.reload(&config::Llm::default());
        assert!(!l.llm.sampling());
        let l = labels(true);
        l.on("5m", "token").unwrap();
        l.reload(&config::Llm::default());
        assert!(l.llm.sampling());
    }

    #[test]
    fn recent_is_bounded_and_newest_first() {
        let l = labels(true);
        let s = Sample {
            trigger: "waf",
            ..Sample::default()
        };
        for i in 0..250 {
            let a = Answer {
                label: "scanner".into(),
                confidence: f64::from(i) / 250.0,
                pattern: String::new(),
                tokens: (0, 0),
            };
            l.record(&s, &a);
        }
        let j = l.json();
        assert_eq!(j["recent"].as_array().unwrap().len(), RECENT);
        assert_eq!(j["recent"][0]["confidence"], 249.0 / 250.0);
        assert_eq!(j["counts"][0]["count"], 250);
        assert_eq!(j["source"], "memory");
    }

    // RFC 0024 case 7, the line: a stored row exports the file's line
    #[cfg(feature = "postgres")]
    #[test]
    fn a_stored_row_exports_the_file_line() {
        let path =
            std::env::temp_dir().join(format!("dvarapala-labels-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c = config::Llm {
            export: Some(path.clone()),
            ..config::Llm::default()
        };
        let l = Labels::new(labels(true).llm.clone(), &c).unwrap();
        let s = Sample {
            trigger: "waf",
            route: "login".into(),
            features: Some(std::array::from_fn(|i| i as f64 / 3.0)),
            ..Sample::default()
        };
        let a = Answer {
            label: "scanner".into(),
            confidence: 0.8413,
            pattern: "probes".into(),
            tokens: (0, 0),
        };
        l.record(&s, &a);
        let file = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let at = serde_json::from_str::<Value>(&file).unwrap()["at"]
            .as_u64()
            .unwrap();
        let f = FEATURE_NAMES
            .iter()
            .zip(s.features.unwrap())
            .map(|(k, v)| ((*k).to_owned(), json!(v)))
            .collect();
        assert_eq!(export_line(&row(&s, &a, at, Some(f))) + "\n", file);
    }
}
