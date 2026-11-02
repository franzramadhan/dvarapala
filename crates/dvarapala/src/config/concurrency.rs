//! The `[concurrency]` section (RFC 0032).

use std::sync::Arc;
use std::time::Duration;

use dvarapala_engine::{ConcurrencyConfig, LimitMode};
use dvarapala_proxy::{Concurrency as Limit, Pool};
use serde::{Deserialize, Serialize};

use super::duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Off,
    Fixed,
    Gradient,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Concurrency {
    pub mode: Mode,
    /// The cap in `fixed` mode, the start value in `gradient` (0: `min`).
    pub limit: u32,
    pub min: u32,
    pub max: u32,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub window: Duration,
    pub reserve: f64,
    pub trusted_score: f64,
}

impl Default for Concurrency {
    fn default() -> Self {
        Self {
            mode: Mode::Off,
            limit: 0,
            min: 20,
            max: 1000,
            window: Duration::from_secs(1),
            reserve: 0.2,
            trusted_score: 0.2,
        }
    }
}

impl Concurrency {
    /// The engine's config, `None` when off. Checked even when off, so a
    /// bad section refuses the file before anyone turns it on.
    pub fn config(&self) -> Result<Option<ConcurrencyConfig>, String> {
        if !(0.0..=1.0).contains(&self.trusted_score) {
            return Err(format!(
                "concurrency.trusted_score: {} is outside [0, 1]",
                self.trusted_score
            ));
        }
        let c = ConcurrencyConfig {
            mode: match self.mode {
                Mode::Off | Mode::Gradient => LimitMode::Gradient,
                Mode::Fixed => LimitMode::Fixed,
            },
            limit: self.limit,
            min: self.min,
            max: self.max,
            window: self.window,
            reserve: self.reserve,
        };
        if self.mode != Mode::Off {
            c.validate().map_err(|e| format!("concurrency: {e}"))?;
        } else if !(0.0..=0.5).contains(&self.reserve) {
            return Err("concurrency: reserve must be in [0, 0.5]".into());
        }
        Ok((self.mode != Mode::Off).then_some(c))
    }

    /// The rate limiter's trusted score, `None` when off.
    pub fn priority(&self) -> Option<f64> {
        (self.mode != Mode::Off).then_some(self.trusted_score)
    }

    /// Puts the limit on `pool`, when on; the handle is for reloads.
    pub fn attach(&self, pool: Pool) -> Result<(Pool, Option<Arc<Limit>>), String> {
        let Some(c) = self.config()? else {
            return Ok((pool, None));
        };
        let limit = Arc::new(Limit::new(c).map_err(|e| format!("concurrency: {e}"))?);
        Ok((pool.with_concurrency(limit.clone()), Some(limit)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_bad_values_refused_even_off() {
        let off = Concurrency::default();
        assert_eq!(off.config(), Ok(None));
        assert_eq!(off.priority(), None);
        let bad = Concurrency {
            trusted_score: 2.0,
            ..Concurrency::default()
        };
        assert!(bad.config().unwrap_err().contains("trusted_score"));
        let bad = Concurrency {
            reserve: 0.7,
            ..Concurrency::default()
        };
        assert!(bad.config().unwrap_err().contains("reserve"));
    }

    #[test]
    fn fixed_needs_a_limit_gradient_needs_bounds() {
        let fixed = Concurrency {
            mode: Mode::Fixed,
            ..Concurrency::default()
        };
        assert!(fixed.config().unwrap_err().contains("limit"));
        let fixed = Concurrency { limit: 5, ..fixed };
        assert_eq!(fixed.config().unwrap().unwrap().limit, 5);
        assert_eq!(fixed.priority(), Some(0.2));
        let gradient = Concurrency {
            mode: Mode::Gradient,
            min: 50,
            max: 10,
            ..Concurrency::default()
        };
        assert!(gradient.config().unwrap_err().contains("min"));
    }
}
