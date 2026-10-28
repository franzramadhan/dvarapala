mod config;
mod metrics;

use std::convert::Infallible;
use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(feature = "ml")]
use std::sync::Arc;
use std::time::Instant;

use dvarapala_engine::{Cidr, DetectConfig, Limit, TrustedProxies};
use dvarapala_l7::{Detection, RateLimitConfig, RateLimitLayer, Scoring};
#[cfg(feature = "tls")]
use dvarapala_proxy::UpstreamConfig;
#[cfg(feature = "tls")]
use dvarapala_proxy::tls::{Tls, TlsConfig, UpstreamTls};
use dvarapala_proxy::{Http2Limits, ProxyBody, ReverseProxy, serve};
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tower_layer::Layer;
use tower_service::Service;
use tracing_subscriber::EnvFilter;

/// Never built without the `tls` feature.
#[cfg(not(feature = "tls"))]
enum Tls {}

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
    #[cfg(feature = "tls")]
    let proxy = ReverseProxy::<Incoming>::with_config(
        &cfg.upstream,
        &UpstreamConfig {
            tls: UpstreamTls {
                ca_file: cfg.upstream_tls.ca_file.clone(),
                server_name: cfg.upstream_tls.server_name.clone(),
            },
            ..UpstreamConfig::default()
        },
    )?;
    #[cfg(not(feature = "tls"))]
    let proxy = {
        no_tls(&cfg.tls, &cfg.upstream)?;
        ReverseProxy::<Incoming>::new(&cfg.upstream)?
    };
    let tls = listener_tls(&cfg.tls)?;
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
    tracing::info!(listen = %cfg.listen, upstream = %cfg.upstream, tls = tls.is_some(), "proxy listening");
    match limiter {
        Some(l) => listen(listener, tls, l.layer(proxy)).await,
        None => listen(listener, tls, proxy).await,
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

/// A build without the `tls` feature refuses `[tls]` and `https://`
/// instead of ignoring them.
#[cfg(not(feature = "tls"))]
fn no_tls(tls: &config::Tls, upstream: &str) -> Result<(), String> {
    if tls.paths() != Ok(None) {
        return Err("[tls] needs a build with the tls feature".into());
    }
    if upstream.starts_with("https://") {
        return Err(format!(
            "upstream {upstream:?}: https:// needs a build with the tls feature"
        ));
    }
    Ok(())
}

/// The listener's TLS, when `[tls]` is set.
#[cfg(feature = "tls")]
fn listener_tls(t: &config::Tls) -> Result<Option<Tls>, Box<dyn Error>> {
    let Some((cert, key)) = t.paths()? else {
        return Ok(None);
    };
    if t.max_handshakes == 0 {
        return Err("tls.max_handshakes must be at least 1".into());
    }
    let tls = Tls::new(TlsConfig {
        cert: cert.to_owned(),
        key: key.to_owned(),
        handshake_timeout: t.handshake_timeout,
        max_handshakes: t.max_handshakes,
    })
    .map_err(|e| format!("tls: {e}"))?;
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut hup = signal(SignalKind::hangup())?;
        let tls = tls.clone();
        tokio::spawn(async move {
            while hup.recv().await.is_some() {
                // reload logs the outcome and keeps the old pair on error
                let _ = tls.reload();
            }
        });
    }
    Ok(Some(tls))
}

#[cfg(not(feature = "tls"))]
fn listener_tls(t: &config::Tls) -> Result<Option<Tls>, Box<dyn Error>> {
    no_tls(t, "")?;
    Ok(None)
}

/// Serves `svc`, with TLS when `tls` is set.
async fn listen<S>(listener: TcpListener, tls: Option<Tls>, svc: S)
where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    match tls {
        None => serve(listener, Http2Limits::default(), svc, shutdown()).await,
        #[cfg(feature = "tls")]
        Some(tls) => {
            dvarapala_proxy::serve_tls(listener, tls, Http2Limits::default(), svc, shutdown()).await
        }
        #[cfg(not(feature = "tls"))]
        Some(never) => match never {},
    }
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

#[cfg(all(test, not(feature = "tls")))]
mod tests {
    use super::*;

    #[test]
    fn tls_needs_the_feature() {
        let on = config::Tls {
            cert: Some("c.pem".into()),
            key: Some("k.pem".into()),
            ..config::Tls::default()
        };
        assert!(
            no_tls(&on, "http://127.0.0.1:1")
                .unwrap_err()
                .contains("tls feature")
        );
        let off = config::Tls::default();
        assert!(
            no_tls(&off, "https://127.0.0.1:1")
                .unwrap_err()
                .contains("tls feature")
        );
        assert_eq!(no_tls(&off, "http://127.0.0.1:1"), Ok(()));
    }
}
