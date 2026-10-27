//! RFC 0002 settings for the rate limit layer: adaptive detection and the
//! optional scorer.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use dvarapala_engine::{DetectConfig, Detector, Scorer, State, WindowReport};

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

/// The detector plus what the layer needs to report on it.
pub(crate) struct Watch {
    detector: Detector,
    attack_since: Option<Instant>,
}

/// What the detector says about one request.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Check {
    pub attack: bool,
    /// the client's prefix was a heavy hitter in the last closed window
    pub heavy: bool,
}

impl Watch {
    pub(crate) fn new(detector: Detector) -> Self {
        Self {
            detector,
            attack_since: None,
        }
    }

    pub(crate) fn check(&mut self, ip: IpAddr, now: Instant) -> Check {
        if let Some(r) = self.detector.observe(ip, now) {
            self.report(&r, now);
        }
        let attack = self.detector.state() == State::Attack;
        Check {
            attack,
            heavy: attack && self.detector.is_heavy(ip),
        }
    }

    /// Metrics for every closed window, one log line per attack start and end.
    // runs under the layer's lock; transitions are rare, gauges are atomics
    fn report(&mut self, r: &WindowReport, now: Instant) {
        metrics::gauge!("dvarapala_detection_state").set(f64::from(r.to.code()));
        metrics::gauge!("dvarapala_detection_rate_zscore").set(r.zscore);
        metrics::gauge!("dvarapala_detection_source_entropy").set(r.entropy);
        metrics::gauge!("dvarapala_detection_heavy_hitters").set(r.heavy as f64);
        if r.from == r.to {
            return;
        }
        metrics::counter!(
            "dvarapala_detection_transitions_total",
            "from" => r.from.name(),
            "to" => r.to.name()
        )
        .increment(1);
        if r.to == State::Attack && self.attack_since.is_none() {
            self.attack_since = Some(now);
            let top: Vec<String> = self
                .detector
                .heavy()
                .iter()
                .take(8)
                .map(|(c, _)| c.to_string())
                .collect();
            tracing::info!(
                msg = "attack_started",
                zscore = r.zscore,
                entropy = r.entropy,
                top = top.join(",")
            );
        }
        if r.to == State::Normal
            && let Some(since) = self.attack_since.take()
        {
            let duration = now.saturating_duration_since(since);
            tracing::info!(msg = "attack_ended", duration = ?duration);
        }
    }
}
