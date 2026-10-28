use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder;

/// HTTP/2 listener limits (RFC 0004). `Default` holds the RFC defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http2Limits {
    /// Streams open at once per connection; more are refused.
    pub max_concurrent_streams: u32,
    /// Streams reset by the client before they were served; over it, the
    /// connection gets `GOAWAY` (rapid reset).
    pub max_pending_reset_streams: usize,
    /// Streams the server resets for client errors before it closes the
    /// connection.
    pub max_local_error_resets: usize,
    /// Bytes of headers per request, CONTINUATION frames included.
    pub max_header_list_size: u32,
    /// PING interval; `None` turns keepalive off.
    pub keepalive_interval: Option<Duration>,
    /// Close the connection when a PING is not answered in time.
    pub keepalive_timeout: Duration,
}

impl Default for Http2Limits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: 100,
            max_pending_reset_streams: 20,
            max_local_error_resets: 1024,
            max_header_list_size: 16 * 1024,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_timeout: Duration::from_secs(10),
        }
    }
}

impl Http2Limits {
    pub(crate) fn apply(self, b: &mut Builder<TokioExecutor>) {
        b.http2()
            .max_concurrent_streams(self.max_concurrent_streams)
            .max_pending_accept_reset_streams(self.max_pending_reset_streams)
            .max_local_error_reset_streams(self.max_local_error_resets)
            .max_header_list_size(self.max_header_list_size)
            .keep_alive_interval(self.keepalive_interval)
            .keep_alive_timeout(self.keepalive_timeout);
    }
}

/// Counts and logs a connection that ended because h2 sent a `GOAWAY`:
/// `flood` for `ENHANCE_YOUR_CALM` (rapid reset, too many error resets,
/// CONTINUATION or header floods), `protocol` for any other error it found.
pub(crate) fn closed(e: &(dyn Error + 'static), peer: SocketAddr) {
    let Some(reason) = goaway_reason(e) else {
        return;
    };
    metrics::counter!("dvarapala_http2_goaway_total", "reason" => reason).increment(1);
    static CLOSED: AtomicU64 = AtomicU64::new(0);
    if CLOSED.fetch_add(1, Ordering::Relaxed).is_multiple_of(1024) {
        tracing::info!(msg = "http2 connection closed", reason, %peer);
    }
}

fn goaway_reason(e: &(dyn Error + 'static)) -> Option<&'static str> {
    let mut cur = Some(e);
    while let Some(e) = cur {
        if let Some(h2) = e.downcast_ref::<h2::Error>() {
            if !(h2.is_go_away() && h2.is_library()) {
                return None;
            }
            return Some(if h2.reason() == Some(h2::Reason::ENHANCE_YOUR_CALM) {
                "flood"
            } else {
                "protocol"
            });
        }
        cur = e.source();
    }
    None
}
