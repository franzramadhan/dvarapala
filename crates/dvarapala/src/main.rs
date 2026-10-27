mod config;
mod metrics;

use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(feature = "ml")]
use std::sync::Arc;
use std::time::Instant;

use dvarapala_engine::{Cidr, DetectConfig, Limit, TrustedProxies};
use dvarapala_l7::{Detection, RateLimitConfig, RateLimitLayer, Scoring};
use dvarapala_proxy::{ReverseProxy, serve};
use hyper::body::Incoming;
use tokio::net::TcpListener;
use tower_layer::Layer;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "usage: dvarapala serve [--config <file>]

Config keys can also be set as DVARAPALA__<SECTION>__<KEY>.
Log level comes from RUST_LOG (default info).";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let config = match (
        args.next().as_deref(),
        args.next().as_deref(),
        args.next(),
        args.next(),
    ) {
        (Some("serve"), None, None, None) => None,
        (Some("serve"), Some("--config"), Some(path), None) => Some(PathBuf::from(path)),
        (Some("--version"), None, None, None) => {
            println!("dvarapala {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dvarapala: {e}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main]
async fn run(config: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    let cfg = config::load(config.as_deref())?;
    let proxy = ReverseProxy::<Incoming>::new(&cfg.upstream)?;
    let limiter = if cfg.rate_limit.enabled {
        let trusted = cfg
            .trusted_proxies
            .iter()
            .map(|c| c.parse::<Cidr>())
            .collect::<Result<_, _>>()?;
        Some(RateLimitLayer::new(RateLimitConfig {
            limit: Limit::new(cfg.rate_limit.rate, cfg.rate_limit.burst)?,
            max_clients: NonZeroUsize::new(cfg.rate_limit.max_clients)
                .ok_or("rate_limit.max_clients must be at least 1")?,
            trusted: TrustedProxies::new(trusted),
            detection: detection(&cfg.detection),
            scoring: scoring(&cfg.ml)?,
            now: Instant::now,
        })?)
    } else {
        if cfg.detection.enabled || cfg.ml.model.is_some() {
            tracing::warn!("detection and scoring run inside the rate limiter, which is off");
        }
        None
    };
    if !cfg.metrics.listen.is_empty() {
        let addr = cfg.metrics.listen.parse()?;
        metrics::serve(addr, metrics::install()?).await?;
    }

    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, "proxy listening");
    match limiter {
        Some(l) => serve(listener, l.layer(proxy), shutdown()).await,
        None => serve(listener, proxy, shutdown()).await,
    }
    tracing::info!("stopped");
    Ok(())
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

/// Resolves on Ctrl-C or SIGTERM.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down, draining connections");
}
