mod config;
mod metrics;
#[cfg(feature = "http3")]
mod quic;
mod store;

use std::convert::Infallible;
use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(feature = "ml")]
use std::sync::Arc;
use std::time::Instant;

use dvarapala_engine::{Cidr, DetectConfig, Limit, TrustedProxies};
use dvarapala_l4::Listener;
use dvarapala_l7::{Detection, RateLimitConfig, RateLimitLayer, Scoring};
#[cfg(feature = "tls")]
use dvarapala_proxy::tls::{Tls, TlsConfig, UpstreamTls};
use dvarapala_proxy::{
    AltSvc, ForwardConfig, ForwardProxy, Http2Limits, ProxyBody, ReverseProxy, UpgradeConfig,
    UpstreamConfig, UpstreamProtocol, serve,
};
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
       dvarapala store schema [--from <version>]

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
        (Some("store"), Some("schema"), from, n) => {
            // RFC 0010: the PostgreSQL schema for a hand-run migration
            let from = match (from.as_deref(), n) {
                (None, None) => Some(0),
                (Some("--from"), Some(n)) => n.parse().ok(),
                _ => None,
            };
            let Some(from) = from.filter(|_| args.next().is_none()) else {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            print!("{}", dvarapala_store::render(from));
            return ExitCode::SUCCESS;
        }
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
    let h2 = http2(&cfg.http2)?;
    let tls = listener_tls(&cfg.tls)?;
    let tunnels = upgrade(&cfg.upgrade)?;
    #[cfg(feature = "tls")]
    let upstream_tls = UpstreamTls {
        ca_file: cfg.upstream_tls.ca_file.clone(),
        server_name: cfg.upstream_tls.server_name.clone(),
    };
    if cfg.mode == config::ProxyMode::Forward {
        if cfg.quic.listen.is_some() {
            return Err("quic.listen works in reverse mode only".into());
        }
        // RFC 0007: the callers are our own services, no per-client limiter
        let (clients, destinations) = cfg.forward.parts()?;
        let cluster = store::start(&cfg.store, None, cfg.rate_limit.max_clients)?;
        let names: Vec<String> = destinations.iter().map(|d| d.name.clone()).collect();
        let proxy = ForwardProxy::<Incoming>::new(&ForwardConfig {
            clients,
            connect: cfg.forward.connect,
            destinations,
            tunnels,
            #[cfg(feature = "tls")]
            tls: upstream_tls,
            cluster,
        })?;
        let listener = bind(&cfg).await?;
        tracing::info!(listen = %cfg.listen, destinations = ?names, connect = cfg.forward.connect, tls = tls.is_some(), "forward proxy listening");
        listen(listener, tls, h2, proxy).await;
        tracing::info!("stopped");
        return Ok(());
    }
    let target = cfg.reverse_upstream()?;
    let quic = cfg.quic.plan(&cfg.tls)?;
    #[cfg(not(feature = "tls"))]
    no_tls(&cfg.tls, target)?;
    let upstream = UpstreamConfig {
        protocol: match cfg.upstream_protocol {
            config::UpstreamProtocol::Http1 => UpstreamProtocol::Http1,
            config::UpstreamProtocol::Http2 => UpstreamProtocol::Http2,
            config::UpstreamProtocol::Auto => UpstreamProtocol::Auto,
        },
        upgrade: tunnels,
        #[cfg(feature = "tls")]
        tls: upstream_tls,
    };
    let proxy = ReverseProxy::<Incoming>::with_config(target, &upstream)?;
    let limiter = if cfg.rate_limit.enabled {
        let limit = Limit::new(cfg.rate_limit.rate, cfg.rate_limit.burst)?;
        let cluster = store::start(&cfg.store, Some(limit), cfg.rate_limit.max_clients)?;
        let trusted = cfg
            .trusted_proxies
            .iter()
            .map(|c| c.parse::<Cidr>())
            .collect::<Result<_, _>>()?;
        Some(RateLimitLayer::new(RateLimitConfig {
            limit,
            max_clients: NonZeroUsize::new(cfg.rate_limit.max_clients)
                .ok_or("rate_limit.max_clients must be at least 1")?,
            trusted: TrustedProxies::new(trusted),
            detection: detection(&cfg.detection),
            scoring: scoring(&cfg.ml)?,
            now: Instant::now,
            cluster,
        })?)
    } else {
        if cfg.store.backend != config::Backend::Memory {
            tracing::warn!("store shares the rate limiter's counts, which is off");
        }
        if cfg.detection.enabled || cfg.ml.model.is_some() {
            tracing::warn!("detection and scoring run inside the rate limiter, which is off");
        }
        None
    };
    let listener = bind(&cfg).await?;
    #[cfg(feature = "http3")]
    let h3 = match (&quic, &tls) {
        (Some(q), Some(t)) => Some(quic::start(q, t, target, &upstream, limiter.clone())?),
        _ => None,
    };
    // the plan refuses quic.listen without the http3 feature
    #[cfg(not(feature = "http3"))]
    let h3: Option<std::future::Pending<()>> = None;
    tracing::info!(listen = %cfg.listen, upstream = %target, protocol = ?upstream.protocol, upgrades = ?upstream.upgrade.protocols, tls = tls.is_some(), "proxy listening");
    let alt_svc = quic.and_then(|q| q.alt_svc);
    let tcp = async {
        match limiter {
            Some(l) => listen_tcp(listener, tls, h2, l.layer(proxy), alt_svc).await,
            None => listen_tcp(listener, tls, h2, proxy, alt_svc).await,
        }
    };
    match h3 {
        Some(h3) => drop(tokio::join!(tcp, h3)),
        None => tcp.await,
    }
    tracing::info!("stopped");
    Ok(())
}

/// Starts the metrics endpoint when set, then binds the proxy listener
/// with the `[l4]` limits.
async fn bind(cfg: &config::Config) -> Result<Listener, Box<dyn Error>> {
    let l4 = cfg.l4.config()?;
    if !cfg.metrics.listen.is_empty() {
        let addr = cfg.metrics.listen.parse()?;
        metrics::serve(addr, metrics::install()?).await?;
    }
    Ok(Listener::new(TcpListener::bind(cfg.listen).await?, l4)?)
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

/// `[upgrade]` as tunnel limits; a zero lifetime turns that limit off.
fn upgrade(u: &config::Upgrade) -> Result<UpgradeConfig, String> {
    if u.max_tunnels == 0 || u.idle_timeout.is_zero() {
        return Err("upgrade.max_tunnels and upgrade.idle_timeout must be above 0; protocols = [] turns upgrades off".into());
    }
    Ok(UpgradeConfig {
        protocols: u.protocols.iter().map(|p| p.to_ascii_lowercase()).collect(),
        max_tunnels: u.max_tunnels,
        idle_timeout: u.idle_timeout,
        max_lifetime: (!u.max_lifetime.is_zero()).then_some(u.max_lifetime),
    })
}

/// `[http2]` as listener limits; a zero keepalive interval turns it off.
fn http2(h: &config::Http2) -> Result<Http2Limits, String> {
    if h.max_concurrent_streams == 0 {
        return Err("http2.max_concurrent_streams must be at least 1".into());
    }
    Ok(Http2Limits {
        max_concurrent_streams: h.max_concurrent_streams,
        max_pending_reset_streams: h.max_pending_reset_streams,
        max_local_error_resets: h.max_local_error_resets,
        max_header_list_size: h.max_header_list_size,
        keepalive_interval: (!h.keepalive_interval.is_zero()).then_some(h.keepalive_interval),
        keepalive_timeout: h.keepalive_timeout,
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

/// [`listen`], with `Alt-Svc` on every response when HTTP/3 is on.
async fn listen_tcp<S>(
    listener: Listener,
    tls: Option<Tls>,
    h2: Http2Limits,
    svc: S,
    alt_svc: Option<u16>,
) where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    match alt_svc {
        Some(port) => listen(listener, tls, h2, AltSvc::new(svc, port)).await,
        None => listen(listener, tls, h2, svc).await,
    }
}

/// Serves `svc`, with TLS when `tls` is set.
async fn listen<S>(listener: Listener, tls: Option<Tls>, h2: Http2Limits, svc: S)
where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    match tls {
        None => serve(listener, h2, svc, shutdown()).await,
        #[cfg(feature = "tls")]
        Some(tls) => dvarapala_proxy::serve_tls(listener, tls, h2, svc, shutdown()).await,
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
