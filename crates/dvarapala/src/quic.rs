//! The HTTP/3 listener next to the TCP one (RFC 0006).

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dvarapala_l7::RateLimitLayer;
use dvarapala_proxy::quic::{H3Body, QuicConfig, QuicListener, Retry};
use dvarapala_proxy::tls::Tls;
use dvarapala_proxy::{Pool, ReverseProxy, UpstreamConfig};
use tower_layer::Layer;

use crate::config::{QuicPlan, QuicRetry};

type Server = Pin<Box<dyn Future<Output = ()> + Send>>;

/// Binds `[quic]` and returns the server, behind the same limiter as TCP:
/// layer clones share one table.
pub fn start(
    plan: &QuicPlan,
    tls: &Tls,
    pool: Arc<Pool>,
    upstream: &UpstreamConfig,
    limiter: Option<RateLimitLayer>,
    waf: crate::waf::Layer,
) -> Result<Server, Box<dyn Error>> {
    let q = &plan.quic;
    let mut c = QuicConfig::new(plan.listen);
    c.retry = match q.retry {
        QuicRetry::UnderLoad => Retry::UnderLoad,
        QuicRetry::Always => Retry::Always,
        QuicRetry::Never => Retry::Never,
    };
    c.retry_threshold = q.retry_threshold;
    c.max_connections = q.max_connections;
    c.max_streams = q.max_streams;
    c.idle_timeout = q.idle_timeout;
    c.handshake_timeout = plan.handshake_timeout;
    // ponytail: retry_token_lifetime stays at the 10 s default, no key
    let listener = QuicListener::bind(c, tls)?;
    // own connections (the body type differs from TCP's), the TCP pool's
    // health (RFC 0015)
    let proxy = ReverseProxy::<crate::waf::Body<H3Body>>::with_pool(pool, upstream)?;
    tracing::info!(listen = %listener.local_addr(), retry = ?q.retry, "http3 listening");
    Ok(match limiter {
        Some(l) => Box::pin(listener.serve(l.layer(waf.layer(proxy)), crate::shutdown())),
        None => Box::pin(listener.serve(waf.layer(proxy), crate::shutdown())),
    })
}
