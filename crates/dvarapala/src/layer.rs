//! The reverse proxy's protection layer from the config, shared by
//! `serve` and `replay` (RFC 0016).

use std::error::Error;
use std::num::NonZeroUsize;
#[cfg(feature = "ml")]
use std::sync::Arc;
use std::time::Instant;

use dvarapala_engine::{Cidr, DetectConfig, Limit, TrustedProxies};
use dvarapala_l7::{Detection, RateLimitConfig, Scoring};

use crate::config;

/// Everything but the store and the XDP block list, which need a network.
pub fn config(
    cfg: &config::Config,
    now: fn() -> Instant,
) -> Result<RateLimitConfig, Box<dyn Error>> {
    let trusted = cfg
        .trusted_proxies
        .iter()
        .map(|c| c.parse::<Cidr>())
        .collect::<Result<_, _>>()?;
    Ok(RateLimitConfig {
        limit: Limit::new(cfg.rate_limit.rate, cfg.rate_limit.burst)?,
        max_clients: NonZeroUsize::new(cfg.rate_limit.max_clients)
            .ok_or("rate_limit.max_clients must be at least 1")?,
        trusted: TrustedProxies::new(trusted),
        detection: detection(&cfg.detection),
        scoring: scoring(&cfg.ml)?,
        now,
        cluster: None,
        block: None,
        challenge: cfg.challenge.config(cfg.detection.enabled)?,
        fingerprints: cfg.fingerprint.rules(cfg.challenge.mode)?,
        routes: config::routes(&cfg.routes)?,
        max_blocks: cfg.admin.max_blocks,
    })
}

fn detection(d: &config::Detection) -> Option<Detection> {
    d.enabled.then(|| Detection {
        detect: DetectConfig {
            window: d.window,
            prefix_v4: d.prefix_v4,
            prefix_v6: d.prefix_v6,
            sketch_width: d.sketch_width,
            sketch_depth: d.sketch_depth,
            top_k: d.top_k,
            ewma_alpha: d.ewma_alpha,
            warmup_windows: d.warmup_windows,
            z_threshold: d.z_threshold,
            entropy_buckets: d.entropy_buckets,
            entropy_drop: d.entropy_drop,
            trigger_windows: d.trigger_windows,
            cooldown_windows: d.cooldown_windows,
            // set by the layer from the rate limit
            heavy_min: 0,
        },
        enforce: d.mode == config::Mode::Enforce,
        attack_rate_factor: d.attack_rate_factor,
    })
}

/// Loads `ml.model`; a model in a build without the `ml` feature is an error.
fn scoring(m: &config::Ml) -> Result<Option<Scoring>, Box<dyn Error>> {
    let Some(path) = &m.model else {
        return Ok(None);
    };
    #[cfg(feature = "ml")]
    {
        let bytes = std::fs::read(path).map_err(|e| format!("ml.model {}: {e}", path.display()))?;
        let model = dvarapala_engine::TreeEnsemble::from_json(&bytes)
            .map_err(|e| format!("ml.model {}: {e}", path.display()))?;
        Ok(Some(Scoring {
            scorer: Arc::new(model),
            threshold: m.threshold,
        }))
    }
    #[cfg(not(feature = "ml"))]
    Err(format!(
        "ml.model {} needs a build with the ml feature",
        path.display()
    )
    .into())
}
