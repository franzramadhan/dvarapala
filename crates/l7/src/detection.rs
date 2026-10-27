//! RFC 0002 settings for the rate limit layer: adaptive detection and the
//! optional scorer.

use std::sync::Arc;

use dvarapala_engine::{DetectConfig, Scorer};

#[derive(Debug, Clone)]
pub struct Detection {
    pub detect: DetectConfig,
    /// `false` (observe) logs and exports metrics only; `true` changes verdicts.
    pub enforce: bool,
    /// Bucket rate multiplier for every client while in `Attack`, `(0, 1]`.
    pub attack_rate_factor: f64,
}

#[derive(Clone)]
pub struct Scoring {
    pub scorer: Arc<dyn Scorer>,
    /// A score above it turns `Allow` into `Throttle`.
    pub threshold: f64,
}

impl std::fmt::Debug for Scoring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scoring")
            .field("threshold", &self.threshold)
            .finish_non_exhaustive()
    }
}
