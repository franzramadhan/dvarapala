//! Prometheus text format on its own listener, apart from proxied traffic.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::OnceLock;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;

/// Installs the global recorder on the first call, before any metric is
/// touched; later calls return the same handle (the metrics listener and,
/// RFC 0021, the admin listener share it).
pub fn install() -> Result<PrometheusHandle, BuildError> {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    if let Some(h) = HANDLE.get() {
        return Ok(h.clone());
    }
    let h = PrometheusBuilder::new().install_recorder()?;
    Ok(HANDLE.get_or_init(|| h).clone())
}

/// Binds `addr` and serves `GET /metrics` until the process exits.
pub async fn serve(addr: SocketAddr, handle: PrometheusHandle) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics listening");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let handle = handle.clone();
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let res = if req.uri().path() == "/metrics" {
                    Response::new(Full::new(Bytes::from(handle.render())))
                } else {
                    let mut r = Response::new(Full::default());
                    *r.status_mut() = StatusCode::NOT_FOUND;
                    r
                };
                async move { Ok::<_, Infallible>(res) }
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc),
            );
        }
    });
    Ok(())
}
