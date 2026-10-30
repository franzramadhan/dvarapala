//! The `[history]` section (RFC 0022): the console's traffic history.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Backend, Store, duration};

/// Samples the ring keeps at most.
pub const MAX_SAMPLES: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct History {
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub interval: Duration,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub window: Duration,
    /// Write a row per minute to the PostgreSQL store.
    pub persist: bool,
    #[serde(deserialize_with = "retention", serialize_with = "ser_retention")]
    pub retention: Duration,
}

impl Default for History {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            window: Duration::from_secs(15 * 60),
            persist: false,
            retention: Duration::from_secs(7 * 24 * 3600),
        }
    }
}

impl History {
    /// The ring's capacity in samples, after checking every key.
    pub fn samples(&self, store: &Store) -> Result<usize, String> {
        if self.interval < Duration::from_secs(1) {
            return Err("history.interval must be at least 1s".into());
        }
        let n = self.window.as_millis() / self.interval.as_millis();
        if n == 0 || n > u128::from(MAX_SAMPLES) {
            return Err(format!(
                "history.window / history.interval must be 1 to {MAX_SAMPLES} samples, not {n}"
            ));
        }
        if self.retention < Duration::from_secs(3600) {
            return Err("history.retention must be at least 1h".into());
        }
        if self.persist && store.backend != Backend::Postgres {
            return Err("history.persist needs store.backend = \"postgres\"".into());
        }
        Ok(n as usize)
    }
}

/// A duration as for every other key, or `"<n>d"` days.
fn retention<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let s = String::deserialize(d)?;
    match s.strip_suffix('d').map(str::parse::<u32>) {
        Some(Ok(n)) => Ok(Duration::from_secs(u64::from(n) * 24 * 3600)),
        _ => super::parse_duration(&s).map_err(serde::de::Error::custom),
    }
}

fn ser_retention<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    let secs = d.as_secs();
    if secs.is_multiple_of(86_400) && secs > 0 {
        s.serialize_str(&format!("{}d", secs / 86_400))
    } else {
        crate::config::view::ser_duration(d, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(interval: u64, window: u64) -> History {
        History {
            interval: Duration::from_millis(interval),
            window: Duration::from_millis(window),
            ..History::default()
        }
    }

    #[test]
    fn defaults_keep_180_samples() {
        assert_eq!(History::default().samples(&Store::default()), Ok(180));
    }

    // RFC 0022 case 5
    #[test]
    fn bounds() {
        let store = Store::default();
        let e = h(1, 900_000).samples(&store).unwrap_err();
        assert!(e.contains("history.interval"), "{e}");
        let e = h(1_000, 20_000_000).samples(&store).unwrap_err();
        assert!(e.contains("history.window"), "{e}");
        let e = h(5_000, 1_000).samples(&store).unwrap_err();
        assert!(e.contains("history.window"), "{e}");
        let short = History {
            retention: Duration::from_secs(60),
            ..History::default()
        };
        assert!(
            short
                .samples(&store)
                .unwrap_err()
                .contains("history.retention")
        );
    }

    // RFC 0022 case 6 (config side)
    #[test]
    fn persist_needs_postgres() {
        let on = History {
            persist: true,
            ..History::default()
        };
        let e = on.samples(&Store::default()).unwrap_err();
        assert!(e.contains("history.persist"), "{e}");
        let pg = Store {
            backend: Backend::Postgres,
            ..Store::default()
        };
        assert_eq!(on.samples(&pg), Ok(180));
    }

    #[test]
    fn retention_takes_days() {
        let c: History = toml::from_str("retention = \"7d\"").unwrap();
        assert_eq!(c.retention, Duration::from_secs(7 * 86_400));
        let c: History = toml::from_str("retention = \"36h\"").unwrap();
        assert_eq!(c.retention, Duration::from_secs(36 * 3_600));
        assert!(toml::from_str::<History>("retention = \"x\"").is_err());
    }
}
