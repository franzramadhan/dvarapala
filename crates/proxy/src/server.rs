use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::time::Duration;

use dvarapala_l7::PeerAddr;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tower_service::Service;

use crate::{Http2Limits, ProxyBody, http2};

/// How long open connections get to finish after shutdown starts.
const DRAIN: Duration = Duration::from_secs(30);

/// Serves `service` on `listener` (HTTP/1.1 and HTTP/2) until `shutdown`
/// resolves, then waits for open connections to finish. Every request gets
/// a [`dvarapala_l7::PeerAddr`] extension. HTTP/2 connections are bounded
/// by `h2` (RFC 0004).
pub async fn serve<S>(
    listener: TcpListener,
    h2: Http2Limits,
    service: S,
    shutdown: impl Future<Output = ()>,
) where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    run(listener, None, h2, service, shutdown).await;
}

/// Like [`serve`], with TLS on every connection (RFC 0003). The handshake
/// runs in the connection's task, bounded by the [`crate::tls::Tls`] limits.
#[cfg(feature = "tls")]
pub async fn serve_tls<S>(
    listener: TcpListener,
    tls: crate::tls::Tls,
    h2: Http2Limits,
    service: S,
    shutdown: impl Future<Output = ()>,
) where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    run(listener, Some(tls), h2, service, shutdown).await;
}

#[cfg(feature = "tls")]
type Tls = crate::tls::Tls;
/// Never built without the `tls` feature.
#[cfg(not(feature = "tls"))]
#[derive(Clone)]
enum Tls {}

async fn run<S>(
    listener: TcpListener,
    tls: Option<Tls>,
    h2: Http2Limits,
    service: S,
    shutdown: impl Future<Output = ()>,
) where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new());
    // a timer turns on hyper's header read timeout (slowloris)
    builder.http1().timer(TokioTimer::new());
    builder.http2().timer(TokioTimer::new());
    h2.apply(&mut builder);
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    // ponytail: fixed back-off so EMFILE does not spin a core
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let svc = service.clone();
        let hyper_svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(PeerAddr(peer));
            let mut svc = svc.clone();
            async move {
                poll_fn(|cx| svc.poll_ready(cx)).await?;
                svc.call(req).await
            }
        });
        let (builder, watcher, tls) = (builder.clone(), graceful.watcher(), tls.clone());
        tokio::spawn(async move {
            match tls {
                None => {
                    let conn =
                        builder.serve_connection_with_upgrades(TokioIo::new(stream), hyper_svc);
                    if let Err(e) = watcher.watch(conn.into_owned()).await {
                        http2::closed(&*e, peer);
                    }
                }
                #[cfg(feature = "tls")]
                Some(tls) => {
                    let Some(stream) = tls.accept(stream).await else {
                        return;
                    };
                    let conn =
                        builder.serve_connection_with_upgrades(TokioIo::new(stream), hyper_svc);
                    if let Err(e) = watcher.watch(conn.into_owned()).await {
                        http2::closed(&*e, peer);
                    }
                }
                #[cfg(not(feature = "tls"))]
                Some(never) => match never {},
            }
        });
    }
    drop(listener);
    if tokio::time::timeout(DRAIN, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("connections still open after drain timeout");
    }
}
