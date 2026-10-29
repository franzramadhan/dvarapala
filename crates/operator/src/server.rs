//! A small HTTP/1.1 server for the webhook (over TLS) and the metrics.

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
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, tls = tls.is_some(), "listening");
    let handle = Arc::new(handle);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let (handle, tls) = (handle.clone(), tls.clone());
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let handle = handle.clone();
                    async move {
                        let path = req.uri().path().to_owned();
                        let res = match Limited::new(req.into_body(), MAX_BODY).collect().await {
                            Ok(body) => handle(path, body.to_bytes()).await,
                            Err(_) => status(StatusCode::PAYLOAD_TOO_LARGE),
                        };
                        Ok::<_, Infallible>(res)
                    }
                });
                let http = hyper::server::conn::http1::Builder::new();
                let _ = match tls {
                    Some(tls) => match tls.accept(stream).await {
                        Ok(s) => http.serve_connection(TokioIo::new(s), svc).await,
                        Err(_) => return,
                    },
                    None => http.serve_connection(TokioIo::new(stream), svc).await,
                };
            });
        }
    });
    Ok(())
}

pub fn status(code: StatusCode) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::default());
    *r.status_mut() = code;
    r
}

pub fn ok(body: Vec<u8>, content_type: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    if let Ok(v) = content_type.parse() {
        r.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    r
}
