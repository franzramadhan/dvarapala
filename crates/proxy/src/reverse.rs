use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http::{Request, Response, Uri};
use http_body_util::combinators::BoxBody;
use hyper::body::Body;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use tower_service::Service;

/// Response body of the proxy: the upstream's, or a short local error.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// Not an absolute `http://host[:port][/path]` URL.
    Invalid(String),
    /// `https://` upstreams come with the TLS RFC.
    Unsupported(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(u) => write!(f, "upstream {u:?} is not an absolute http:// URL"),
            Self::Unsupported(u) => write!(f, "upstream {u:?}: only http:// is supported for now"),
        }
    }
}

impl std::error::Error for UpstreamError {}

/// Forwards every request to one upstream. Hop-by-hop headers are removed,
/// the peer is appended to `X-Forwarded-For`, and the path and query are
/// joined onto the upstream's base path.
pub struct ReverseProxy<B> {
    scheme: Scheme,
    authority: Authority,
    base_path: String,
    client: Client<HttpConnector, B>,
}

impl<B> Clone for ReverseProxy<B> {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            base_path: self.base_path.clone(),
            client: self.client.clone(),
        }
    }
}

impl<B> ReverseProxy<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub fn new(_upstream: &str) -> Result<Self, UpstreamError> {
        todo!("rfc 0001")
    }
}

impl<B> Service<Request<B>> for ReverseProxy<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Request<B>) -> Self::Future {
        let _ = Uri::default();
        todo!("rfc 0001")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Incoming;

    #[test]
    #[ignore = "rfc 0001"]
    fn parses_upstream() {
        assert!(ReverseProxy::<Incoming>::new("http://127.0.0.1:8081").is_ok());
        assert!(ReverseProxy::<Incoming>::new("http://app.internal/base/").is_ok());
        assert!(matches!(
            ReverseProxy::<Incoming>::new("https://app.internal"),
            Err(UpstreamError::Unsupported(_))
        ));
        for bad in ["", "app.internal", "/path", "ftp://app.internal"] {
            assert!(
                matches!(
                    ReverseProxy::<Incoming>::new(bad),
                    Err(UpstreamError::Invalid(_))
                ),
                "{bad:?}"
            );
        }
    }
}
