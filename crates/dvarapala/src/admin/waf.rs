//! RFC 0021: `GET /waf`, the settings, the matched rules and the agent's
//! rule files.

use std::time::UNIX_EPOCH;

use dvarapala_l7::ModeLayer;
use serde_json::{Value, json};

use super::Admin;
use super::switch::{self, Switch};

/// Largest rule file shown.
const MAX_FILE: u64 = 256 * 1024;

impl Admin {
    pub(super) fn waf(&self) -> Value {
        let (_, cur) = self.reloader.configs();
        let (rules, other) = matched();
        json!({
            "settings": cur.waf,
            "mode": switch::mode(self.reloader.enforce(ModeLayer::Waf)),
            "switch": self.reloader.switches.get(ModeLayer::Waf).as_ref().map(Switch::json),
            "rules": rules,
            "other": other,
            "files": cur.waf.rules_files.iter().map(|p| file(p)).collect::<Vec<_>>(),
        })
    }
}

#[cfg(feature = "waf")]
fn matched() -> (Vec<Value>, u64) {
    let (rules, other) = dvarapala_l7::matched_rules();
    let rules = rules
        .into_iter()
        .map(|m| {
            json!({
                "rule": m.rule,
                "count": m.count,
                "last_seen": m.last_seen,
                "method": m.method,
                "path": m.path,
                "anomaly_score": m.anomaly_score,
            })
        })
        .collect();
    (rules, other)
}

#[cfg(not(feature = "waf"))]
fn matched() -> (Vec<Value>, u64) {
    (Vec::new(), 0)
}

/// One rule file, read now: its content, or why it is not shown.
fn file(path: &str) -> Value {
    let read = || -> Result<Value, String> {
        let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
        if meta.len() > MAX_FILE {
            return Err(format!("{} bytes, over 256 KiB", meta.len()));
        }
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        Ok(json!({ "path": path, "size": meta.len(), "modified": modified, "content": content }))
    };
    read().unwrap_or_else(|error| {
        tracing::warn!(msg = "waf rules file unreadable", path, %error);
        json!({ "path": path, "error": error })
    })
}
