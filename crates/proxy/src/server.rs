use std::convert::Infallible;
use std::future::{Future, poll_fn};
use std::time::Duration;

use dvarapala_l4::{BodyRate, Listener};
use dvarapala_l7::{Ja4, PeerAddr};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::sync::watch;
use tower_service::Service;

use crate::upgrade::Drain;
use crate::{Http2Limits, ProxyBody, http2};

/// How long open connections and tunnels get to finish after shutdown
/// starts.
const DRAIN: Duration = Duration::from_secs(30);

/// Serves `service` on `listener` (HTTP/1.1 and HTTP/2) until `shutdown`
/// resolves, then waits for open connections to finish. Every request gets
/// a [`dvarapala_l7::PeerAddr`] extension, and a [`BodyRate`] when
/// `min_body_rate` is set. HTTP/2 connections are bounded by `h2` (RFC
/// 0004); connections by the listener's limits and timeouts (RFC 0009). A
/// bare `TcpListener` gets [`dvarapala_l4::L4Config::timeouts_only`].
pub async fn serve<S>(
    listener: impl Into<Listener>,
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
    run(listener.into(), None, h2, service, shutdown).await;
}

/// Like [`serve`], with TLS on every connection (RFC 0003). The handshake
/// runs in the connection's task, bounded by the [`crate::tls::Tls`] limits.
#[cfg(feature = "tls")]
pub async fn serve_tls<S>(
    listener: impl Into<Listener>,
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
    run(listener.into(), Some(tls), h2, service, shutdown).await;
}

#[cfg(feature = "tls")]
type Tls = crate::tls::Tls;
/// Never built without the `tls` feature.
#[cfg(not(feature = "tls"))]
#[derive(Clone)]
enum Tls {}

async fn run<S>(
    listener: Listener,
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
    let l4 = listener.config();
    let (idle, rate) = (l4.idle_timeout, l4.min_body_rate);
    let mut builder = Builder::new(TokioExecutor::new());
    // restarted for every request head on the connection (slowloris)
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(l4.header_timeout);
    builder.http2().timer(TokioTimer::new());
    h2.apply(&mut builder);
    let graceful = GracefulShutdown::new();
    // tunnels outlive their connection: they close on the signal, and the
    // drain waits for every receiver (RFC 0005)
    let (drain_tx, drain_rx) = watch::channel(());
    tokio::pin!(shutdown);
    loop {
        let (conn, peer) = tokio::select! {
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
        let (svc, drain) = (service.clone(), Drain(drain_rx.clone()));
        let activity = conn.activity();
        let act = activity.clone();
        // RFC 0012: the JA4 is known after the handshake
        let make = move |ja4: Option<Ja4>| {
            hyper::service::service_fn(move |mut req: Request<Incoming>| {
                // in flight until the response body ends, for the idle timeout
                let busy = act.begin();
                req.extensions_mut().insert(PeerAddr(peer));
                if let Some(f) = ja4 {
                    req.extensions_mut().insert(f);
                }
                req.extensions_mut().insert(drain.clone());
                if rate > 0 {
                    req.extensions_mut().insert(BodyRate(rate));
                }
                let mut svc = svc.clone();
                async move {
                    poll_fn(|cx| svc.poll_ready(cx)).await?;
                    let res = svc.call(req).await?;
                    Ok::<_, Infallible>(res.map(|b| {
                        b.map_frame(move |f| {
                            let _ = &busy;
                            f
                        })
                        .boxed()
                    }))
                }
            })
        };
        let (builder, watcher, tls) = (builder.clone(), graceful.watcher(), tls.clone());
        tokio::spawn(async move {
            let served = async {
                let res = match tls {
                    None => {
                        let c =
                            builder.serve_connection_with_upgrades(TokioIo::new(conn), make(None));
                        watcher.watch(c.into_owned()).await
                    }
                    #[cfg(feature = "tls")]
                    Some(tls) => {
                        let Some((stream, ja4)) = tls.accept(conn).await else {
                            return;
                        };
                        let c =
                            builder.serve_connection_with_upgrades(TokioIo::new(stream), make(ja4));
                        watcher.watch(c.into_owned()).await
                    }
                    #[cfg(not(feature = "tls"))]
                    Some(never) => match never {},
                };
                if let Err(e) = res {
                    if header_timeout(&*e) {
                        timed_out("header");
                    }
                    http2::closed(&*e, peer);
                }
            };
            match idle {
                // an upgrade ends `served`: tunnels keep their own idle limit
                Some(t) => tokio::select! {
                    () = served => {}
                    () = activity.idle(t) => timed_out("idle"),
                },
                None => served.await,
            }
        });
    }
    drop((listener, drain_rx));
    let _ = drain_tx.send(());
    let drained = async {
        graceful.shutdown().await;
        drain_tx.closed().await;
    };
    if tokio::time::timeout(DRAIN, drained).await.is_err() {
        tracing::warn!("connections still open after drain timeout");
    }
}

/// Whether hyper gave up waiting for a request head. On the server side
/// only the header read timeout is a hyper timeout.
fn header_timeout(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(e);
    while let Some(e) = cur {
        if let Some(h) = e.downcast_ref::<hyper::Error>() {
            return h.is_timeout();
        }
        cur = e.source();
    }
    false
}

fn timed_out(kind: &'static str) {
    metrics::counter!("dvarapala_l4_timeouts_total", "kind" => kind).increment(1);
}
