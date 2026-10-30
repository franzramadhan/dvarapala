//! The `[ml]` section (RFC 0002) and `[ml.llm]`, the LLM labels for
//! sampled traffic (RFC 0023).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use dvarapala_l7::{LlmConfig, On, Trigger};
use http::HeaderName;
use serde::{Deserialize, Serialize};

use super::history::{retention, ser_retention};
use super::waf::size;
use super::{Config, ProxyMode, duration};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ml {
    /// XGBoost JSON model; unset turns scoring off.
    pub model: Option<PathBuf>,
    pub threshold: f64,
    pub llm: Llm,
}

impl Default for Ml {
    fn default() -> Self {
        Self {
            model: None,
            threshold: 0.9,
            llm: Llm::default(),
        }
    }
}

/// Largest `body_bytes`.
const MAX_BODY_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Llm {
    /// Unset turns the feature off.
    pub endpoint: Option<String>,
    pub protocol: Protocol,
    pub model: String,
    #[serde(serialize_with = "crate::config::view::redact")]
    pub api_key: String,
    pub enabled: bool,
    /// Label to description; the only answers taken.
    pub labels: BTreeMap<String, String>,
    pub instructions: String,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub per_client: Duration,
    pub queue: usize,
    pub concurrency: usize,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub timeout: Duration,
    pub headers: Vec<String>,
    pub body_bytes: usize,
    pub export: Option<PathBuf>,
    #[serde(deserialize_with = "size")]
    pub export_max: usize,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub max_duration: Duration,
    pub triggers: Vec<TriggerConfig>,
    /// RFC 0024: write labels to the PostgreSQL store.
    pub persist: bool,
    pub persist_queue: usize,
    #[serde(deserialize_with = "retention", serialize_with = "ser_retention")]
    pub retention: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Systemone,
    Chat,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerConfig {
    pub on: String,
    #[serde(default = "one")]
    pub rate: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<[f64; 2]>,
}

fn one() -> f64 {
    1.0
}

impl Default for Llm {
    fn default() -> Self {
        let labels = [
            ("benign", "ordinary use of the site"),
            ("scanner", "probing paths and known exploits"),
            ("scraper", "bulk reads of content"),
            (
                "credential_stuffing",
                "login attempts with many credentials",
            ),
            ("flood", "volume without intent to use the site"),
            ("spam", "posting unsolicited content"),
            ("other", "none of the above"),
        ];
        Self {
            endpoint: None,
            protocol: Protocol::Systemone,
            model: String::new(),
            api_key: String::new(),
            enabled: false,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            instructions: String::new(),
            per_client: Duration::from_secs(600),
            queue: 256,
            concurrency: 4,
            timeout: Duration::from_secs(20),
            headers: [
                "user-agent",
                "accept",
                "accept-language",
                "content-type",
                "referer",
            ]
            .map(String::from)
            .to_vec(),
            body_bytes: 0,
            export: None,
            export_max: 64 << 20,
            max_duration: Duration::from_secs(24 * 3600),
            triggers: Vec::new(),
            persist: false,
            persist_queue: 1024,
            retention: Duration::from_secs(30 * 24 * 3600),
        }
    }
}

impl Llm {
    /// The sampler's settings, `None` when `endpoint` is unset or the
    /// section does not apply (forward mode, no rate limiter).
    pub fn sampler(&self, cfg: &Config) -> Result<Option<LlmConfig>, String> {
        let Some(endpoint) = &self.endpoint else {
            return Ok(None);
        };
        if cfg.mode == ProxyMode::Forward || !cfg.rate_limit.enabled {
            tracing::warn!(
                "ml.llm samples inside the reverse proxy's rate limiter, which is off: ignored"
            );
            return Ok(None);
        }
        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(format!(
                "ml.llm.endpoint {endpoint:?}: use http:// or https://"
            ));
        }
        if self.model.is_empty() {
            return Err("ml.llm.model is required with ml.llm.endpoint".into());
        }
        if !(2..=32).contains(&self.labels.len()) {
            return Err("ml.llm.labels needs 2 to 32 entries".into());
        }
        if self.queue == 0 || self.concurrency == 0 || self.timeout.is_zero() {
            return Err("ml.llm.queue, concurrency and timeout must be above 0".into());
        }
        if self.body_bytes > MAX_BODY_BYTES {
            return Err(format!("ml.llm.body_bytes is at most {MAX_BODY_BYTES}"));
        }
        if self.max_duration.is_zero() {
            return Err("ml.llm.max_duration must be above 0".into());
        }
        let headers = self
            .headers
            .iter()
            .map(|h| {
                HeaderName::try_from(h.to_ascii_lowercase())
                    .map_err(|_| format!("ml.llm.headers: {h:?} is not a header name"))
            })
            .collect::<Result<_, _>>()?;
        let triggers = self
            .triggers
            .iter()
            .map(|t| t.trigger(cfg))
            .collect::<Result<Vec<_>, _>>()?;
        if triggers.is_empty() {
            tracing::warn!("ml.llm has no triggers: nothing is sampled");
        }
        Ok(Some(LlmConfig {
            triggers,
            per_client: self.per_client,
            headers,
            body_bytes: self.body_bytes,
            max_clients: cfg.rate_limit.max_clients,
            enabled: self.enabled,
        }))
    }
}

impl TriggerConfig {
    fn trigger(&self, cfg: &Config) -> Result<Trigger, String> {
        if !(self.rate > 0.0 && self.rate <= 1.0) {
            return Err(format!(
                "ml.llm.triggers rate {} is not in (0, 1]",
                self.rate
            ));
        }
        let on = match (self.on.as_str(), &self.route, self.band) {
            ("waf", None, None) => On::Waf,
            ("challenge_failed", None, None) => On::ChallengeFailed,
            ("attack", None, None) => On::Attack,
            ("route", Some(r), None) => {
                if !cfg.routes.iter().any(|x| x.name == *r) {
                    return Err(format!(
                        "ml.llm.triggers route {r:?}: no [[routes]] has that name"
                    ));
                }
                On::Route(r.clone())
            }
            ("ml_band", None, Some([lo, hi])) => {
                if cfg.ml.model.is_none() {
                    return Err("ml.llm.triggers band: ml_band needs ml.model".into());
                }
                if !(0.0..=1.0).contains(&lo) || !(lo..=1.0).contains(&hi) {
                    return Err(format!(
                        "ml.llm.triggers band [{lo}, {hi}]: use 0 <= low <= high <= 1"
                    ));
                }
                On::MlBand(lo, hi)
            }
            ("route", None, _) => return Err("ml.llm.triggers: on = \"route\" needs route".into()),
            ("ml_band", _, None) => {
                return Err("ml.llm.triggers: on = \"ml_band\" needs band".into());
            }
            (o, _, _) if ["waf", "challenge_failed", "attack", "route", "ml_band"].contains(&o) => {
                return Err(format!(
                    "ml.llm.triggers: route is for on = \"route\", band for on = \"ml_band\" (on = {o:?})"
                ));
            }
            (o, _, _) => {
                return Err(format!(
                    "ml.llm.triggers on {o:?}: use waf, challenge_failed, attack, ml_band or route"
                ));
            }
        };
        Ok(Trigger {
            on,
            rate: self.rate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(llm: &str, extra: &str) -> Config {
        let text = format!(
            "upstream = \"http://127.0.0.1:1\"\n{extra}\n[ml.llm]\nendpoint = \"http://127.0.0.1:4000/v1/systemone\"\nmodel = \"clef\"\n{llm}"
        );
        toml::from_str(&text).unwrap()
    }

    fn err(llm: &str, extra: &str) -> String {
        let c = cfg(llm, extra);
        c.ml.llm.sampler(&c).unwrap_err()
    }

    #[test]
    fn defaults_and_off_without_endpoint() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.ml.llm.sampler(&c), Ok(None));
        assert_eq!(c.ml.llm.labels.len(), 7);
        let c = cfg("[[ml.llm.triggers]]\non = \"waf\"\nrate = 0.5\n", "");
        let s = c.ml.llm.sampler(&c).unwrap().unwrap();
        assert_eq!(
            s.triggers,
            vec![Trigger {
                on: On::Waf,
                rate: 0.5
            }]
        );
        assert_eq!(s.headers.len(), 5);
    }

    // RFC 0023 case 16
    #[test]
    fn errors_name_the_key() {
        let e = err(
            "[[ml.llm.triggers]]\non = \"route\"\nroute = \"nope\"\n",
            "",
        );
        assert!(
            e.contains("ml.llm.triggers route") && e.contains("nope"),
            "{e}"
        );
        let e = err(
            "[[ml.llm.triggers]]\non = \"ml_band\"\nband = [0.4, 0.6]\n",
            "",
        );
        assert!(e.contains("ml.model"), "{e}");
        assert!(err("[[ml.llm.triggers]]\non = \"bogus\"\n", "").contains("bogus"));
        assert!(err("[[ml.llm.triggers]]\non = \"waf\"\nrate = 0.0\n", "").contains("rate"));
        assert!(err("body_bytes = 5000\n", "").contains("body_bytes"));
        assert!(err("[ml.llm.labels]\nonly = \"one\"\n", "").contains("labels"));
        let mut c = cfg("", "");
        c.ml.llm.model.clear();
        assert!(c.ml.llm.sampler(&c).unwrap_err().contains("ml.llm.model"));
        let c = cfg(
            "[[ml.llm.triggers]]\non = \"route\"\nroute = \"login\"\n",
            "[[routes]]\nname = \"login\"\npath = \"/login\"\n",
        );
        assert!(c.ml.llm.sampler(&c).unwrap().is_some());
    }

    // RFC 0024 cases 1 and 2
    #[test]
    #[ignore = "rfc 0024"]
    fn persist_needs_postgres_and_retention_an_hour() {
        let e = err("persist = true\n", "");
        assert!(e.contains("ml.llm.persist"), "{e}");
        let c = cfg("persist = true\n", "[store]\nbackend = \"postgres\"\n");
        assert!(c.ml.llm.sampler(&c).unwrap().is_some());
        let e = err("retention = \"10m\"\n", "");
        assert!(e.contains("ml.llm.retention") && e.contains("1h"), "{e}");
        assert!(err("persist_queue = 0\n", "").contains("ml.llm.persist_queue"));
        let c = cfg("retention = \"7d\"\n", "");
        assert_eq!(c.ml.llm.retention, Duration::from_secs(7 * 86_400));
    }

    // RFC 0023 case 17
    #[test]
    fn ignored_without_the_rate_limiter() {
        let c = cfg("", "[rate_limit]\nenabled = false\n");
        assert_eq!(c.ml.llm.sampler(&c), Ok(None));
        let c = cfg("", "mode = \"forward\"\n");
        assert_eq!(c.ml.llm.sampler(&c), Ok(None));
    }
}
