//! RFC 0029: the scoring model in force. Loaded at start, swapped by a
//! reload when the file's bytes change, kept when they do not.

use std::path::Path;
use std::sync::Arc;

use dvarapala_engine::{Features, Scorer};
use dvarapala_l7::Scoring;

use crate::config::Config;

/// A parsed model and the hash of the bytes it came from.
#[derive(Clone)]
pub struct Model {
    pub scorer: Arc<dyn Scorer>,
    /// hex SHA-256 of the file
    pub sha256: String,
    /// Unix seconds
    pub loaded_at: u64,
}

/// Reads and parses `path`, or returns `running` when the file holds the
/// same bytes. Errors name the key and the file.
pub fn load(path: &Path, running: Option<&Model>) -> Result<Model, String> {
    let err = |e: &dyn std::fmt::Display| format!("ml.model {}: {e}", path.display());
    #[cfg(not(feature = "ml"))]
    {
        let _ = running;
        Err(err(&"needs a build with the ml feature"))
    }
    #[cfg(feature = "ml")]
    {
        let bytes = std::fs::read(path).map_err(|e| err(&e))?;
        let d = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let sha256: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        if let Some(m) = running.filter(|m| m.sha256 == sha256) {
            return Ok(m.clone());
        }
        let model = dvarapala_engine::TreeEnsemble::from_json(&bytes).map_err(|e| err(&e))?;
        Ok(Model {
            scorer: Arc::new(model),
            sha256,
            loaded_at: dvarapala_l7::unix_now(),
        })
    }
}

/// The scorer for `cfg`: the model, else features only for LLM samples
/// (RFC 0023), else none.
pub fn scoring(cfg: &Config, model: Option<&Model>) -> Option<Scoring> {
    if let Some(m) = model {
        return Some(Scoring {
            scorer: m.scorer.clone(),
            threshold: cfg.ml.threshold,
        });
    }
    cfg.ml.llm.endpoint.as_ref()?;
    Some(Scoring {
        scorer: Arc::new(Unscored),
        threshold: f64::INFINITY,
    })
}

/// A NaN score never throttles and is not recorded.
struct Unscored;

impl Scorer for Unscored {
    fn score(&self, _: &Features) -> f64 {
        f64::NAN
    }
}

/// Logs and exports `new` when it replaces `old`; the same model is
/// silent.
pub fn publish(new: Option<&Model>, old: Option<&Model>) {
    let id = |m: &Model| m.sha256[..12].to_owned();
    if new.map(id) == old.map(id) {
        return;
    }
    if let Some(o) = old {
        ::metrics::gauge!("dvarapala_ml_model_info", "sha256" => id(o)).set(0.0);
    }
    if let Some(n) = new {
        tracing::info!(msg = "model loaded", sha256 = %n.sha256);
        ::metrics::gauge!("dvarapala_ml_model_info", "sha256" => id(n)).set(1.0);
        ::metrics::gauge!("dvarapala_ml_model_loaded_timestamp_seconds").set(n.loaded_at as f64);
    }
}

/// `GET /status` `ml`: the model in force, `null` without one.
pub fn status(cfg: &Config, model: Option<&Model>) -> String {
    model.map_or_else(
        || "null".into(),
        |m| {
            format!(
                "{{\"sha256\":\"{}\",\"threshold\":{},\"loaded_at\":{}}}",
                m.sha256, cfg.ml.threshold, m.loaded_at
            )
        },
    )
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
