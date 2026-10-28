use http::Version;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

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

impl UpstreamProtocol {
    /// The version upstream requests are sent with.
    pub(crate) fn version(self) -> Version {
        match self {
            Self::Http2 => Version::HTTP_2,
            Self::Http1 | Self::Auto => Version::HTTP_11,
        }
    }

    /// `te: trailers` is kept whenever the upstream may speak HTTP/2.
    pub(crate) fn keeps_trailers(self) -> bool {
        self != Self::Http1
    }

    /// A client pool for `connector`. `Http2` speaks HTTP/2 on every
    /// connection: h2c with prior knowledge, or over TLS whatever ALPN
    /// chose (a server that cannot speak it fails the request).
    pub(crate) fn client<C, B>(self, connector: C) -> Client<C, B>
    where
        C: hyper_util::client::legacy::connect::Connect + Clone,
        B: hyper::body::Body + Send,
        B::Data: Send,
    {
        Client::builder(TokioExecutor::new())
            .http2_only(self == Self::Http2)
            .build(connector)
    }
}
