use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{HandshakeKind, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use super::{CertPair, TlsError};

/// Listener TLS settings.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// Connections still handshaking after this are closed.
    pub handshake_timeout: Duration,
    /// Handshakes in progress at once; over it, close before any crypto.
    pub max_handshakes: usize,
    /// Compute the JA4 of each ClientHello (RFC 0012).
    pub fingerprint: bool,
}

/// A loaded TLS listener config. Clones share the certificate, so
/// [`Tls::reload`] on one is seen by all.
#[derive(Clone)]
pub struct Tls(Arc<Inner>);

struct Inner {
    config: TlsConfig,
    cert: Arc<Current>,
    acceptor: TlsAcceptor,
    handshakes: Arc<Semaphore>,
}

/// The certificate handed to every new handshake; swapped by reload.
#[derive(Debug)]
struct Current(RwLock<Arc<CertifiedKey>>);

impl ResolvesServerCert for Current {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.read().unwrap_or_else(|p| p.into_inner()).clone())
    }
}

impl std::fmt::Debug for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls")
            .field("config", &self.0.config)
            .finish()
    }
}

impl Tls {
    pub fn new(config: TlsConfig) -> Result<Self, TlsError> {
        let pair = CertPair::load(&config.cert, &config.key)?;
        record_expiry(&pair);
        let cert = Arc::new(Current(RwLock::new(pair.key)));
        let invalid = |e: rustls::Error| TlsError::Invalid(e.to_string());
        let mut sc =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(invalid)?
                .with_no_client_auth()
                .with_cert_resolver(cert.clone());
        sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        // stateless tickets, random key per process, rotated by rustls
        sc.ticketer = rustls::crypto::ring::Ticketer::new().map_err(invalid)?;
        Ok(Self(Arc::new(Inner {
            handshakes: Arc::new(Semaphore::new(config.max_handshakes)),
            config,
            cert,
            acceptor: TlsAcceptor::from(Arc::new(sc)),
        })))
    }

    /// Reads the certificate and key again. On error the old pair stays.
    pub fn reload(&self) -> Result<(), TlsError> {
        let c = &self.0.config;
        match CertPair::load(&c.cert, &c.key) {
            Ok(pair) => {
                record_expiry(&pair);
                *self.0.cert.0.write().unwrap_or_else(|p| p.into_inner()) = pair.key;
                tracing::info!(cert = %c.cert.display(), "tls reloaded");
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = %e, "tls reload failed, keeping the old certificate");
                Err(e)
            }
        }
    }

    /// The QUIC side (RFC 0006): the same certificate, so reload covers
    /// it; TLS 1.3 only, ALPN `h3`, no early data (0-RTT is replayable).
    #[cfg(feature = "http3")]
    pub(crate) fn quic(&self) -> Result<ServerConfig, rustls::Error> {
        let mut sc =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_cert_resolver(self.0.cert.clone());
        sc.alpn_protocols = vec![b"h3".to_vec()];
        sc.max_early_data_size = 0;
        Ok(sc)
    }

    /// The handshake, bounded in concurrency and time. `None` closes the
    /// connection.
    pub(crate) async fn accept<IO>(&self, tcp: IO) -> Option<TlsStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let Ok(_slot) = self.0.handshakes.clone().try_acquire_owned() else {
            count("rejected");
            limit_reached();
            return None;
        };
        let in_progress = metrics::gauge!("dvarapala_tls_handshakes_in_progress");
        in_progress.increment(1.0);
        let res =
            tokio::time::timeout(self.0.config.handshake_timeout, self.0.acceptor.accept(tcp))
                .await;
        in_progress.decrement(1.0);
        match res {
            Ok(Ok(s)) => {
                count("ok");
                if s.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed) {
                    metrics::counter!("dvarapala_tls_resumed_total").increment(1);
                }
                Some(s)
            }
            Ok(Err(_)) => {
                count("failed");
                None
            }
            Err(_) => {
                count("timeout");
                None
            }
        }
    }
}

fn count(result: &'static str) {
    metrics::counter!("dvarapala_tls_handshakes_total", "result" => result).increment(1);
}

fn record_expiry(pair: &CertPair) {
    if let Some(t) = pair
        .not_after()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
    {
        metrics::gauge!("dvarapala_tls_cert_expiry_timestamp_seconds").set(t.as_secs_f64());
    }
}

/// Logs at most once per second.
fn limit_reached() {
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if LAST.swap(now, Ordering::Relaxed) != now {
        tracing::warn!("handshake limit reached");
    }
}
