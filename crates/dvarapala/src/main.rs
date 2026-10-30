mod admin;
mod config;
mod layer;
#[cfg(feature = "llm")]
mod llm;
mod metrics;
#[cfg(feature = "http3")]
mod quic;
mod reload;
#[cfg(feature = "replay")]
mod replay;
mod store;
mod waf;
mod watch;
mod xdp;

use std::convert::Infallible;
use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use dvarapala_engine::BlockSink;
use dvarapala_l4::Listener;
use dvarapala_l7::{RateLimitLayer, RouteKey};
#[cfg(feature = "tls")]
use dvarapala_proxy::tls::{Tls, TlsConfig, UpstreamTls};
use dvarapala_proxy::{
    AltSvc, ForwardConfig, ForwardProxy, Http2Limits, ProxyBody, ReverseProxy, UpgradeConfig,
    UpstreamConfig, UpstreamProtocol, serve, spawn_health,
};
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tower_layer::Layer;
use tower_service::Service;
use tracing_subscriber::EnvFilter;

/// RFC 0023: the labels behind `GET /llm`.
#[cfg(feature = "llm")]
type Labels = Option<Arc<llm::Labels>>;
#[cfg(not(feature = "llm"))]
type Labels = Option<Infallible>;

/// Never built without the `tls` feature.
#[cfg(not(feature = "tls"))]
enum Tls {}

const USAGE: &str = "usage: dvarapala serve [--config <file>]
       dvarapala store schema [--from <version>]
       dvarapala replay --config <file> [--out <file>] <log | ->

Config keys can also be set as DVARAPALA__<SECTION>__<KEY>.
Log level comes from RUST_LOG (default info).";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    #[cfg(feature = "replay")]
    if std::env::args().nth(1).as_deref() == Some("replay") {
        // RFC 0016
        return replay::main(args.skip(1));
    }
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
    let admin = cfg.admin.addr()?;
    // first: a fast path that was asked for and cannot attach stops here
    let block = xdp::start(&cfg)?;
    let h2 = http2(&cfg.http2)?;
    // RFC 0012: both run inside the reverse proxy's rate limiter
    let fingerprints = cfg.fingerprint.rules(cfg.challenge.mode)?;
    let challenge = cfg.challenge.config(cfg.detection.enabled)?;
    let routes = config::routes(&cfg.routes)?;
    let layered = cfg.mode == config::ProxyMode::Reverse && cfg.rate_limit.enabled;
    if !layered && (fingerprints.enabled() || challenge.is_some() || !routes.is_empty()) {
        tracing::warn!(
            "challenge, fingerprint and routes run inside the reverse proxy's rate limiter, which is off"
        );
    }
    if challenge.is_some()
        && cfg.challenge.secret.is_empty()
        && cfg.store.backend != config::Backend::Memory
    {
        tracing::warn!("challenge.secret is empty: passes from one replica fail on the others");
    }
    let ja4 = fingerprints.enabled() || routes.iter().any(|r| r.key == RouteKey::Ja4);
    let tls = listener_tls(&cfg.tls, layered && ja4)?;
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
        let listener = bind(&cfg, block).await?;
        let waf = waf::Layer::new(waf::config(&cfg)?);
        control(&cfg, config, admin, None, waf, false, None).await?;
        tracing::info!(listen = %cfg.listen, destinations = ?names, connect = cfg.forward.connect, tls = tls.is_some(), "forward proxy listening");
        listen(listener, tls, h2, proxy).await;
        tracing::info!("stopped");
        return Ok(());
    }
    let pool = Arc::new(cfg.pool.build(cfg.upstream.as_deref())?);
    let targets = cfg
        .upstream
        .iter()
        .chain(&cfg.pool.upstreams)
        .collect::<Vec<_>>();
    let quic = cfg.quic.plan(&cfg.tls)?;
    #[cfg(not(feature = "tls"))]
    for t in &targets {
        no_tls(&cfg.tls, t)?;
    }
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
    // RFC 0017: under the limiter, so routes can skip it
    let waf = waf::Layer::new(waf::config(&cfg)?);
    let proxy = ReverseProxy::<waf::Body<Incoming>>::with_pool(pool.clone(), &upstream)?;
    spawn_health(&pool, &upstream)?;
    let limiter = if cfg.rate_limit.enabled {
        let mut c = layer::config(&cfg, Instant::now)?;
        c.cluster = store::start(&cfg.store, Some(c.limit), cfg.rate_limit.max_clients)?;
        c.block = block.clone();
        Some(RateLimitLayer::new(c)?)
    } else {
        if cfg.store.backend != config::Backend::Memory {
            tracing::warn!("store shares the rate limiter's counts, which is off");
        }
        if cfg.detection.enabled || cfg.ml.model.is_some() {
            tracing::warn!("detection and scoring run inside the rate limiter, which is off");
        }
        None
    };
    let listener = bind(&cfg, block).await?;
    #[cfg(feature = "llm")]
    let labels = llm::start(&cfg, limiter.as_ref())?;
    #[cfg(not(feature = "llm"))]
    let labels = match cfg.ml.llm.sampler(&cfg)? {
        Some(_) => return Err("ml.llm.endpoint needs a build with the llm feature".into()),
        None => None,
    };
    control(
        &cfg,
        config,
        admin,
        limiter.clone(),
        waf.clone(),
        layered && ja4,
        labels,
    )
    .await?;
    #[cfg(feature = "http3")]
    let h3 = match (&quic, &tls) {
        (Some(q), Some(t)) => Some(quic::start(
            q,
            t,
            pool,
            &upstream,
            limiter.clone(),
            waf.clone(),
        )?),
        _ => None,
    };
    // the plan refuses quic.listen without the http3 feature
    #[cfg(not(feature = "http3"))]
    let h3: Option<std::future::Pending<()>> = None;
    tracing::info!(listen = %cfg.listen, upstreams = ?targets, protocol = ?upstream.protocol, upgrades = ?upstream.upgrade.protocols, tls = tls.is_some(), "proxy listening");
    let alt_svc = quic.and_then(|q| q.alt_svc);
    let tcp = async {
        match limiter {
            Some(l) => listen_tcp(listener, tls, h2, l.layer(waf.layer(proxy)), alt_svc).await,
            None => listen_tcp(listener, tls, h2, waf.layer(proxy), alt_svc).await,
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
/// with the `[l4]` limits, reporting accept-rate refusals to `block`.
async fn bind(cfg: &config::Config, block: Option<BlockSink>) -> Result<Listener, Box<dyn Error>> {
    let l4 = cfg.l4.config()?;
    if !cfg.metrics.listen.is_empty() {
        let addr = cfg.metrics.listen.parse()?;
        metrics::serve(addr, metrics::install()?).await?;
    } else if !cfg.admin.listen.is_empty() {
        // RFC 0021: the console reads the metrics on the admin listener
        metrics::install()?;
    }
    let listener = Listener::new(TcpListener::bind(cfg.listen).await?, l4)?;
    Ok(match block {
        Some(b) => listener.with_block(b),
        None => listener,
    })
}

/// RFC 0014: `SIGHUP` and the admin API reload the config; the admin API
/// also reads the state and blocks networks.
async fn control(
    cfg: &config::Config,
    path: Option<PathBuf>,
    admin: Option<std::net::SocketAddr>,
    layer: Option<RateLimitLayer>,
    waf: waf::Layer,
    ja4: bool,
    labels: Labels,
) -> Result<(), Box<dyn Error>> {
    let reloader = Arc::new(reload::Reloader::new(
        path.clone(),
        layer.clone(),
        waf,
        ja4,
        cfg.clone(),
    ));
    #[cfg(feature = "llm")]
    if let Some(l) = labels.clone() {
        let _ = reloader
            .on_reload
            .set(Box::new(move |c: &config::Config| l.reload(&c.ml.llm)));
    }
    reload::on_hangup(reloader.clone())?;
    watch::start(path.as_deref(), cfg.config_watch, reloader.clone())?;
    if let Some(addr) = admin {
        let history = admin::history::History::start(cfg, layer.clone(), reloader.clone())?;
        let a = admin::Admin {
            token: cfg.admin.token.clone(),
            max_block_ttl: cfg.admin.max_block_ttl,
            layer,
            reloader,
            metrics: metrics::install()?,
            mode_switch: cfg.admin.mode_switch,
            history,
            llm: labels,
            mode: match cfg.mode {
                config::ProxyMode::Reverse => "reverse",
                config::ProxyMode::Forward => "forward",
            },
            #[cfg(feature = "ui")]
            console: if cfg.admin.ui_enabled {
                Some(admin::Console::new(&cfg.admin)?)
            } else {
                None
            },
        };
        admin::serve(addr, a).await?;
    }
    Ok(())
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
fn listener_tls(t: &config::Tls, fingerprint: bool) -> Result<Option<Tls>, Box<dyn Error>> {
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
        fingerprint,
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
fn listener_tls(t: &config::Tls, _fingerprint: bool) -> Result<Option<Tls>, Box<dyn Error>> {
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
