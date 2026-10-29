//! A small HTTP/1.1 server for the webhook (over TLS) and the metrics.
#![allow(unused_variables, unused_imports, dead_code)]

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The API server's own cap on an admission request.
const MAX_BODY: usize = 3 << 20;

/// Serves `handle(path, body)` on `addr` until the process exits; answers
/// `413` to a body over 3 MiB.
pub async fn serve<F, Fut>(
    addr: SocketAddr,
    tls: Option<TlsAcceptor>,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(String, Bytes) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response<Full<Bytes>>> + Send,
{
    todo!("rfc 0019")
}

pub fn status(code: StatusCode) -> Response<Full<Bytes>> {
    todo!("rfc 0019")
}

pub fn ok(body: Vec<u8>, content_type: &str) -> Response<Full<Bytes>> {
    todo!("rfc 0019")
}
