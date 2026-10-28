/// The protocol spoken to the upstream (RFC 0004).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// HTTP/1.1, whatever the client used.
    #[default]
    Http1,
    /// HTTP/2 only: h2c with prior knowledge for `http://`, ALPN `h2` for
    /// `https://`. An upstream that cannot speak it gets a 502.
    Http2,
    /// ALPN chooses for `https://`; `http://` stays HTTP/1.1.
    Auto,
}

/// How the proxy talks to its upstream.
#[derive(Debug, Clone, Default)]
pub struct UpstreamConfig {
    pub protocol: UpstreamProtocol,
    /// Verification of `https://` upstreams (RFC 0003).
    #[cfg(feature = "tls")]
    pub tls: crate::tls::UpstreamTls,
}
