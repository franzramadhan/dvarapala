use std::time::Duration;

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
