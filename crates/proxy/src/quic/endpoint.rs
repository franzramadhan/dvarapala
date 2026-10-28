use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;

use http::{Request, Response};
use tower_service::Service;

use super::{H3Body, QuicConfig};
use crate::ProxyBody;
use crate::tls::Tls;

#[derive(Debug)]
pub enum QuicError {
    Bind(std::io::Error),
    Tls(String),
}

impl std::fmt::Display for QuicError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(e) => write!(f, "quic.listen: {e}"),
            Self::Tls(e) => write!(f, "quic tls: {e}"),
        }
    }
}

impl std::error::Error for QuicError {}

/// A bound QUIC endpoint with the `[tls]` certificate (TLS 1.3, ALPN `h3`,
/// no 0-RTT).
pub struct QuicListener {}

impl QuicListener {
    pub fn bind(config: QuicConfig, tls: &Tls) -> Result<Self, QuicError> {
        let _ = (config, tls);
        todo!("rfc 0006")
    }

    pub fn local_addr(&self) -> SocketAddr {
        todo!("rfc 0006")
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
        let _ = (service, shutdown);
        todo!("rfc 0006")
    }
}
