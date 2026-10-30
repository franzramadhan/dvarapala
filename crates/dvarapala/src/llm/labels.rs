//! The sampling switch with its timer, the recent labels, the counts and
//! the export file.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use dvarapala_engine::FEATURE_NAMES;
use dvarapala_l7::{Answer, Llm, Sample};
use serde_json::{Map, Value, json};

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
    pub fn reload(&self) {
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
        if let (Some(e), Some(f)) = (&self.export, &s.features) {
            let mut line = Map::new();
            for (k, v) in FEATURE_NAMES.iter().zip(f) {
                line.insert((*k).into(), json!(v));
            }
            line.insert("label".into(), a.label.as_str().into());
            line.insert("confidence".into(), a.confidence.into());
            line.insert("trigger".into(), s.trigger.into());
            line.insert("at".into(), at.into());
            lock(e).write(Value::Object(line).to_string());
        }
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
        })
    }
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
        l.reload();
        assert!(!l.llm.sampling());
        let l = labels(true);
        l.on("5m", "token").unwrap();
        l.reload();
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
    }
}
