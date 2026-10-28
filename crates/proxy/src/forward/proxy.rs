use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::{Cidr, Schedule};
use dvarapala_l4::{BodyRate, MinBodyRate, is_too_slow};
use dvarapala_l7::PeerAddr;
use http::header::{HOST, HeaderValue, RETRY_AFTER};
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Body, Frame, SizeHint};
use hyper_util::client::legacy::Client;
#[cfg(not(feature = "tls"))]
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::net::TcpStream;
use tower_service::Service;

use crate::forward::shaper::{self, Pass, Shaper};
use crate::forward::{ForwardConfig, ForwardError, Routes};
use crate::hop::strip_hop_by_hop;
use crate::tunnels::Tunnels;
use crate::upgrade::{self, Drain};
use crate::{ProxyBody, UpstreamProtocol};

#[cfg(feature = "tls")]
type Connector = crate::tls::Connector;
#[cfg(not(feature = "tls"))]
type Connector = HttpConnector;

/// Forwards requests from allowed clients to listed destinations, each
/// shaped to its rate (RFC 0007). Absolute-form requests are sent by the
/// proxy, TLS included; `CONNECT` opens a tunnel per slot.
pub struct ForwardProxy<B> {
    inner: Arc<Inner>,
    client: Client<Connector, MinBodyRate<B>>,
}

struct Inner {
    routes: Routes,
    shapers: Vec<Shaper>,
    clients: Vec<Cidr>,
    connect: bool,
    tunnels: Arc<Tunnels>,
}

impl<B> Clone for ForwardProxy<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            client: self.client.clone(),
        }
    }
}

impl<B> ForwardProxy<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub fn new(config: &ForwardConfig) -> Result<Self, ForwardError> {
        let ds = &config.destinations;
        let routes =
            Routes::new(ds.iter().map(|d| d.origin.as_str())).map_err(ForwardError::Origin)?;
        let shapers = ds
            .iter()
            .map(|d| {
                let s = Schedule::new(d.schedule)
                    .map_err(|e| ForwardError::Schedule(format!("{}: {e}", d.name)))?;
                Ok(Shaper::new(
                    d.name.clone(),
                    s,
                    d.max_concurrent,
                    config.cluster.clone(),
                ))
            })
            .collect::<Result<_, ForwardError>>()?;
        #[cfg(feature = "tls")]
        let connector = config
            .tls
            .connector(
                ds.iter().any(|d| d.origin.starts_with("https:")),
                UpstreamProtocol::Auto,
            )
            .map_err(ForwardError::Tls)?;
        #[cfg(not(feature = "tls"))]
        let connector = match ds.iter().find(|d| d.origin.starts_with("https:")) {
            Some(d) => return Err(ForwardError::Unsupported(d.origin.clone())),
            None => HttpConnector::new(),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                routes,
                shapers,
                clients: config.clients.clone(),
                connect: config.connect,
                tunnels: Tunnels::new(config.tunnels.clone()),
            }),
            client: UpstreamProtocol::Auto.client(connector),
        })
    }
}

impl<B> Service<Request<B>> for ForwardProxy<B>
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
        let (inner, client) = (self.inner.clone(), self.client.clone());
        Box::pin(async move { Ok(handle(inner, client, req).await) })
    }
}

async fn handle<B>(
    inner: Arc<Inner>,
    client: Client<Connector, MinBodyRate<B>>,
    req: Request<B>,
) -> Response<ProxyBody>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let found = inner.routes.find(req.method(), req.uri());
    let allowed = req
        .extensions()
        .get::<PeerAddr>()
        .is_some_and(|PeerAddr(p)| inner.clients.iter().any(|c| c.contains(p.ip())));
    let connect = req.method() == Method::CONNECT;
    let Some(i) = found.filter(|_| allowed && (inner.connect || !connect)) else {
        let name = found.map_or("none", |i| inner.shapers[i].name.as_str());
        shaper::count(name, "denied");
        return status(StatusCode::FORBIDDEN);
    };
    let shaper = &inner.shapers[i];
    let pass = match shaper.admit().await {
        Ok(p) => p,
        Err(retry) => return too_many(retry),
    };
    if connect {
        return open_tunnel(&inner, req, pass).await;
    }
    let (mut parts, body) = req.into_parts();
    if let Some(a) = parts
        .uri
        .authority()
        .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
    {
        parts.headers.insert(HOST, a);
    }
    parts.version = Version::HTTP_11;
    // no X-Forwarded-For: the callers are our own services
    strip_hop_by_hop(&mut parts.headers, true);
    let rate = parts.extensions.get::<BodyRate>().map_or(0, |r| r.0);
    let body = MinBodyRate::new(body, rate);
    match client.request(Request::from_parts(parts, body)).await {
        Ok(res) => {
            let paused = matches!(
                res.status(),
                StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
            );
            // ponytail: delay-seconds only, an HTTP-date Retry-After is ignored
            let retry = res
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok()?.parse().ok());
            if let (true, Some(secs)) = (paused, retry) {
                shaper.pause(Duration::from_secs(secs));
            }
            let mut res = res.map(|b| {
                Held {
                    inner: b.boxed(),
                    _pass: pass,
                }
                .boxed()
            });
            strip_hop_by_hop(res.headers_mut(), false);
            res
        }
        Err(e) if is_too_slow(&e) => status(StatusCode::REQUEST_TIMEOUT),
        Err(e) => {
            metrics::counter!("dvarapala_upstream_errors_total").increment(1);
            tracing::warn!(destination = %shaper.name, error = %e, "egress request failed");
            status(StatusCode::BAD_GATEWAY)
        }
    }
}

/// `200` and a tunnel to the `CONNECT` target, holding `pass` until it
/// ends; `502` when the target cannot be reached, `503` over `max_tunnels`.
async fn open_tunnel<B>(inner: &Inner, mut req: Request<B>, pass: Pass) -> Response<ProxyBody> {
    let Some(slot) = inner.tunnels.acquire() else {
        return status(StatusCode::SERVICE_UNAVAILABLE);
    };
    // the route matched, so the target is `host:port`
    let target = req
        .uri()
        .authority()
        .map(|a| a.as_str().to_owned())
        .unwrap_or_default();
    let host = target
        .rsplit_once(':')
        .map_or("", |(h, _)| h.trim_matches(['[', ']']));
    let port = req.uri().port_u16().unwrap_or_default();
    let upstream = match TcpStream::connect((host, port)).await {
        Ok(s) => s,
        Err(e) => {
            metrics::counter!("dvarapala_upstream_errors_total").increment(1);
            tracing::warn!(target, error = %e, "connect failed");
            return status(StatusCode::BAD_GATEWAY);
        }
    };
    let drain = req.extensions_mut().remove::<Drain>();
    upgrade::spawn_connect(hyper::upgrade::on(&mut req), upstream, slot, drain, pass);
    status(StatusCode::OK)
}

fn too_many(retry: Duration) -> Response<ProxyBody> {
    let mut res = status(StatusCode::TOO_MANY_REQUESTS);
    // seconds, rounded up, at least 1
    let secs = retry.as_secs() + u64::from(retry.subsec_nanos() > 0);
    res.headers_mut().insert(RETRY_AFTER, secs.max(1).into());
    res
}

fn status(code: StatusCode) -> Response<ProxyBody> {
    let mut res = Response::new(Empty::new().map_err(|never| match never {}).boxed());
    *res.status_mut() = code;
    res
}

/// A response body that keeps its request's [`Pass`] until it is done.
struct Held {
    inner: ProxyBody,
    _pass: Pass,
}

impl Body for Held {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
