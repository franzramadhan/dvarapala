use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http::{Request, Response};
use quinn::crypto::rustls::QuicServerConfig;
use tower_service::Service;

use super::limits::When;
use super::{ClientGuard, ClientLimits, H3Body, QuicConfig, Retry};
use crate::ProxyBody;
use crate::tls::Tls;

/// How long open connections get to finish after shutdown starts.
const DRAIN: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum QuicError {
    Bind(std::io::Error),
    Tls(String),
    /// The per-client limits (RFC 0036): bad grouping.
    Limits(String),
}

impl std::fmt::Display for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(e) => write!(f, "quic.listen: {e}"),
            Self::Tls(e) => write!(f, "quic tls: {e}"),
            Self::Limits(e) => write!(f, "quic limits: {e}"),
        }
    }
}

impl std::error::Error for QuicError {}

/// A bound QUIC endpoint with the `[tls]` certificate (TLS 1.3, ALPN `h3`,
/// no 0-RTT).
pub struct QuicListener {
    endpoint: quinn::Endpoint,
    config: QuicConfig,
    limits: Arc<ClientLimits>,
}

/// QUIC application error for a connection over a per-client limit.
const H3_EXCESSIVE_LOAD: u32 = 0x0107;

impl QuicListener {
    pub fn bind(config: QuicConfig, tls: &Tls) -> Result<Self, QuicError> {
        let limits = ClientLimits::new(&config.conns).map_err(|e| QuicError::Limits(e.0))?;
        let tls_err = |e: &dyn std::fmt::Display| QuicError::Tls(e.to_string());
        let crypto = tls.quic().map_err(|e| tls_err(&e))?;
        let crypto = QuicServerConfig::try_from(crypto).map_err(|e| tls_err(&e))?;
        let mut t = quinn::TransportConfig::default();
        t.max_concurrent_bidi_streams(config.max_streams.into())
            .max_idle_timeout(Some(
                config.idle_timeout.try_into().map_err(|e| tls_err(&e))?,
            ));
        let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        sc.transport_config(Arc::new(t))
            .retry_token_lifetime(config.retry_token_lifetime);
        let endpoint = quinn::Endpoint::server(sc, config.listen).map_err(QuicError::Bind)?;
        Ok(Self {
            endpoint,
            config,
            limits,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.endpoint
            .local_addr()
            .expect("a bound socket has an address")
    }

    /// Serves HTTP/3 into `service` until `shutdown`, then drains.
    pub async fn serve<S>(self, service: S, shutdown: impl Future<Output = ()>)
    where
        S: Service<Request<H3Body>, Response = Response<ProxyBody>, Error = Infallible>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        let (e, c) = (&self.endpoint, &self.config);
        let handshaking = Arc::new(AtomicUsize::new(0));
        let mut retrying = false;
        tokio::pin!(shutdown);
        loop {
            let incoming = tokio::select! {
                Some(i) = e.accept() => i,
                () = &mut shutdown => break,
                else => break,
            };
            // quinn counts connections from accept until they close,
            // handshakes included
            if e.open_connections() >= c.max_connections {
                incoming.refuse();
                count("refused");
                continue;
            }
            let load = handshaking.load(Ordering::Relaxed) >= c.retry_threshold;
            let retry = match c.retry {
                Retry::Always => true,
                Retry::UnderLoad => load,
                Retry::Never => false,
            };
            if c.retry == Retry::UnderLoad && load != retrying {
                retrying = load;
                tracing::warn!(
                    msg = if load {
                        "quic retry on"
                    } else {
                        "quic retry off"
                    },
                    handshaking = handshaking.load(Ordering::Relaxed)
                );
            }
            if retry && !incoming.remote_address_validated() {
                if incoming.retry().is_ok() {
                    metrics::counter!("dvarapala_quic_retries_total").increment(1);
                }
                continue;
            }
            // a validated address is counted now and refused before any
            // crypto; any other one only after its handshake
            let mut place = None;
            if When::of(incoming.remote_address_validated()) == When::Accept {
                match self.limits.admit(incoming.remote_address().ip()) {
                    Ok(g) => place = Some(g),
                    Err(_) => {
                        incoming.refuse();
                        continue;
                    }
                }
            }
            let Ok(connecting) = incoming.accept() else {
                count("failed");
                continue;
            };
            let (service, handshaking, timeout) =
                (service.clone(), handshaking.clone(), c.handshake_timeout);
            let limits = self.limits.clone();
            tokio::spawn(async move {
                handshaking.fetch_add(1, Ordering::Relaxed);
                let res = tokio::time::timeout(timeout, connecting).await;
                handshaking.fetch_sub(1, Ordering::Relaxed);
                let conn = match res {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(_)) => return count("failed"),
                    // dropping `connecting` closes it
                    Err(_) => return count("timeout"),
                };
                let Some(_place) = place.or_else(|| late_place(&limits, &conn)) else {
                    return;
                };
                count("ok");
                let open = metrics::gauge!("dvarapala_quic_connections_open");
                open.increment(1.0);
                super::h3::connection(conn, service).await;
                open.decrement(1.0);
            });
        }
        let _ = tokio::time::timeout(DRAIN, e.wait_idle()).await;
        e.close(0u32.into(), b"shutdown");
    }
}

fn count(result: &'static str) {
    metrics::counter!("dvarapala_quic_handshakes_total", "result" => result).increment(1);
}

/// Counts a connection whose address was proven by its handshake only; over
/// a limit it is closed before any request is read.
fn late_place(limits: &Arc<ClientLimits>, conn: &quinn::Connection) -> Option<ClientGuard> {
    let ip = conn.remote_address().ip();
    match limits.admit(ip) {
        Ok(g) => Some(g),
        Err(_) => {
            conn.close(H3_EXCESSIVE_LOAD.into(), b"too many connections");
            None
        }
    }
}
