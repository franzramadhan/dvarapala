use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use dvarapala_l7::{GrpcStatus, PeerAddr, grpc_response, is_grpc};
use http::uri::{Authority, Scheme};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty};
use hyper::body::Body;
use hyper_util::client::legacy::Client;
#[cfg(not(feature = "tls"))]
use hyper_util::client::legacy::connect::HttpConnector;
use tower_service::Service;

use crate::hop::{append_forwarded_for, strip_hop_by_hop};
use crate::{UpstreamConfig, UpstreamProtocol};

/// Response body of the proxy: the upstream's, or a short local error.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamError {
    /// Not an absolute `http://host[:port][/path]` URL.
    Invalid(String),
    /// `https://` without the `tls` feature, or through [`ReverseProxy::new`].
    Unsupported(String),
    /// The upstream TLS settings could not be loaded.
    Tls(String),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(u) => write!(f, "upstream {u:?} is not an absolute http:// URL"),
            Self::Unsupported(u) => write!(f, "upstream {u:?}: https:// needs the tls feature"),
            Self::Tls(why) => write!(f, "upstream tls: {why}"),
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
    protocol: UpstreamProtocol,
    client: Client<Connector, B>,
}

#[cfg(feature = "tls")]
type Connector = crate::tls::Connector;
#[cfg(not(feature = "tls"))]
type Connector = HttpConnector;

impl<B> Clone for ReverseProxy<B> {
    fn clone(&self) -> Self {
        Self {
            scheme: self.scheme.clone(),
            authority: self.authority.clone(),
            base_path: self.base_path.clone(),
            protocol: self.protocol,
            client: self.client.clone(),
        }
    }
}

impl<B> ReverseProxy<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// An `http://` upstream.
    pub fn new(upstream: &str) -> Result<Self, UpstreamError> {
        let (scheme, authority, base_path) = parse(upstream, false)?;
        #[cfg(feature = "tls")]
        let connector = crate::tls::UpstreamTls::default()
            .connector(false, UpstreamProtocol::Http1)
            .map_err(UpstreamError::Tls)?;
        #[cfg(not(feature = "tls"))]
        let connector = HttpConnector::new();
        Ok(Self::build(
            scheme,
            authority,
            base_path,
            connector,
            UpstreamProtocol::Http1,
        ))
    }

    /// Like [`ReverseProxy::new`], with the protocol from `config`, and
    /// also `https://` upstreams with the `tls` feature (RFC 0003, 0004).
    pub fn with_config(upstream: &str, config: &UpstreamConfig) -> Result<Self, UpstreamError> {
        let (scheme, authority, base_path) = parse(upstream, cfg!(feature = "tls"))?;
        #[cfg(feature = "tls")]
        let connector = config
            .tls
            .connector(scheme == Scheme::HTTPS, config.protocol)
            .map_err(UpstreamError::Tls)?;
        #[cfg(not(feature = "tls"))]
        let connector = HttpConnector::new();
        Ok(Self::build(
            scheme,
            authority,
            base_path,
            connector,
            config.protocol,
        ))
    }

    fn build(
        scheme: Scheme,
        authority: Authority,
        base_path: String,
        connector: Connector,
        protocol: UpstreamProtocol,
    ) -> Self {
        Self {
            scheme,
            authority,
            base_path,
            protocol,
            client: protocol.client(connector),
        }
    }

    /// The upstream URI for `uri`: base path, then the request's path and query.
    fn target(&self, uri: &Uri) -> Result<Uri, http::Error> {
        let pq = uri.path_and_query().map_or("/", |pq| pq.as_str());
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(format!("{}{pq}", self.base_path))
            .build()
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

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (mut parts, body) = req.into_parts();
        let target = match self.target(&parts.uri) {
            Ok(t) => t,
            Err(_) => return Box::pin(async { Ok(status(StatusCode::BAD_REQUEST)) }),
        };
        parts.uri = target;
        // the upstream protocol is fixed by config, not by the client
        parts.version = self.protocol.version();
        let grpc = is_grpc(&parts.headers);
        strip_hop_by_hop(&mut parts.headers, self.protocol.keeps_trailers());
        if let Some(PeerAddr(peer)) = parts.extensions.get::<PeerAddr>() {
            append_forwarded_for(&mut parts.headers, peer.ip());
        }
        let fut = self.client.request(Request::from_parts(parts, body));
        Box::pin(async move {
            Ok(match fut.await {
                Ok(res) => {
                    let mut res = res.map(BodyExt::boxed);
                    strip_hop_by_hop(res.headers_mut(), false);
                    res
                }
                Err(e) => {
                    metrics::counter!("dvarapala_upstream_errors_total").increment(1);
                    tracing::warn!(error = %e, "upstream request failed");
                    if grpc {
                        grpc_response(GrpcStatus::Unavailable, None)
                    } else {
                        status(StatusCode::BAD_GATEWAY)
                    }
                }
            })
        })
    }
}

/// Scheme, authority and base path of an absolute upstream URL.
fn parse(upstream: &str, https: bool) -> Result<(Scheme, Authority, String), UpstreamError> {
    let invalid = || UpstreamError::Invalid(upstream.to_owned());
    let uri: Uri = upstream.parse().map_err(|_| invalid())?;
    let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) else {
        return Err(invalid());
    };
    if *scheme == Scheme::HTTPS && !https {
        return Err(UpstreamError::Unsupported(upstream.to_owned()));
    }
    if (*scheme != Scheme::HTTP && *scheme != Scheme::HTTPS) || uri.query().is_some() {
        return Err(invalid());
    }
    let base_path = uri.path().trim_end_matches('/').to_owned();
    Ok((scheme.clone(), authority.clone(), base_path))
}

fn status(code: StatusCode) -> Response<ProxyBody> {
    let mut res = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *res.status_mut() = code;
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Incoming;

    #[test]
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
