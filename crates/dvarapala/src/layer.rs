//! The reverse proxy's protection layer from the config, shared by
//! `serve` and `replay` (RFC 0016).

use std::error::Error;
use std::num::NonZeroUsize;
use std::time::Instant;

use dvarapala_engine::{Cidr, DetectConfig, Limit, TrustedProxies};
use dvarapala_l7::{Detection, RateLimitConfig};

use crate::config;
use crate::model::{self, Model};

/// Everything but the store and the XDP block list, which need a network.
/// `model` is `ml.model` loaded by [`crate::model::load`].
pub fn config(
    cfg: &config::Config,
    now: fn() -> Instant,
    model: Option<&Model>,
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
        scoring: model::scoring(cfg, model),
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
