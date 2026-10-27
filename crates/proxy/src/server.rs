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

use crate::ProxyBody;

/// How long open connections get to finish after shutdown starts.
const DRAIN: Duration = Duration::from_secs(30);

/// Serves `service` on `listener` (HTTP/1.1 and HTTP/2) until `shutdown`
/// resolves, then waits for open connections to finish. Every request gets
/// a [`dvarapala_l7::PeerAddr`] extension.
pub async fn serve<S>(listener: TcpListener, service: S, shutdown: impl Future<Output = ()>)
where
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
        let conn = builder
            .serve_connection_with_upgrades(TokioIo::new(stream), hyper_svc)
            .into_owned();
        tokio::spawn(graceful.watch(conn));
    }
    drop(listener);
    if tokio::time::timeout(DRAIN, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!("connections still open after drain timeout");
    }
}
