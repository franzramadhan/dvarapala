//! RFC 0005 test helpers: a WebSocket upstream on hyper, the proxy in front
//! of it, a WebSocket client, and the counter recorder.
#![allow(dead_code)]

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Limit, TrustedProxies};
use dvarapala_l7::{RateLimitConfig, RateLimitLayer};
use dvarapala_proxy::{Http2Limits, ReverseProxy, UpgradeConfig, UpstreamConfig, serve};
use futures_util::{SinkExt, StreamExt};
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Error, Message};
use tower_layer::Layer;

pub type Ws = WebSocketStream<TcpStream>;

/// What the upstream saw: requests, and close frames from clients.
#[derive(Default)]
pub struct Seen {
    pub hits: AtomicUsize,
    pub closes: AtomicUsize,
}

/// HTTP/1.1 upstream, routed by path:
///
/// - `/forbidden`: `403`
/// - an upgrade to `websocket`: `101`, then `/close` closes at once and any
///   other path echoes text and binary messages
/// - anything else: `200` with the `Upgrade` header it got, or `none`
pub async fn upstream() -> (SocketAddr, Arc<Seen>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = l.accept().await.unwrap();
            let s = s.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| route(req, s.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    (addr, seen)
}

async fn route(
    mut req: Request<Incoming>,
    seen: Arc<Seen>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    seen.hits.fetch_add(1, Ordering::SeqCst);
    if req.uri().path() == "/forbidden" {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::default())
            .unwrap());
    }
    let upgrade = req.headers().get("upgrade").cloned();
    let key = req.headers().get("sec-websocket-key").cloned();
    let (Some(upgrade), Some(key)) = (upgrade.clone(), key) else {
        let got = upgrade.map_or(Bytes::from_static(b"none"), |u| {
            Bytes::copy_from_slice(u.as_bytes())
        });
        return Ok(Response::new(Full::new(got)));
    };
    let close = req.uri().path() == "/close";
    let on = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let io = TokioIo::new(on.await.unwrap());
        let mut ws = WebSocketStream::from_raw_socket(io, Role::Server, None).await;
        if close {
            let _ = ws.close(None).await;
            return;
        }
        while let Some(Ok(m)) = ws.next().await {
            if m.is_close() {
                seen.closes.fetch_add(1, Ordering::SeqCst);
            } else if (m.is_text() || m.is_binary()) && ws.send(m).await.is_err() {
                return;
            }
        }
        // hold the connection until the proxy drops it: closing here would
        // race the client's own close in the `end` label (case 2)
        let mut sink = [0u8; 64];
        while matches!(ws.get_mut().read(&mut sink).await, Ok(n) if n > 0) {}
    });
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", upgrade)
        .header("sec-websocket-accept", derive_accept_key(key.as_bytes()))
        .body(Full::default())
        .unwrap())
}

/// The proxy in front of `upstream`, behind `limiter` when given; drop the
/// sender to shut it down.
pub async fn proxy(
    upstream: SocketAddr,
    upgrade: UpgradeConfig,
    limiter: Option<RateLimitLayer>,
) -> (SocketAddr, oneshot::Sender<()>) {
    let config = UpstreamConfig {
        upgrade,
        ..UpstreamConfig::default()
    };
    let p = ReverseProxy::<Incoming>::with_config(&format!("http://{upstream}"), &config).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let stop = async {
        let _ = rx.await;
    };
    let h2 = Http2Limits::default();
    match limiter {
        None => tokio::spawn(serve(l, h2, p, stop)),
        Some(layer) => tokio::spawn(serve(l, h2, layer.layer(p), stop)),
    };
    (addr, tx)
}

/// One request per second per client, no burst.
pub fn limiter() -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(1, 1).unwrap(),
        max_clients: NonZeroUsize::new(64).unwrap(),
        trusted: TrustedProxies::default(),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
    })
    .unwrap()
}

/// A WebSocket handshake to `path` through the proxy at `addr`.
pub async fn connect(addr: SocketAddr, path: &str) -> Result<Ws, Error> {
    let s = TcpStream::connect(addr).await.unwrap();
    tokio_tungstenite::client_async(format!("ws://{addr}{path}"), s)
        .await
        .map(|(ws, _)| ws)
}

/// The status of a handshake the proxy or upstream refused.
pub fn refused(r: Result<Ws, Error>) -> StatusCode {
    match r {
        Err(Error::Http(res)) => res.status(),
        Err(e) => panic!("handshake failed: {e}"),
        Ok(_) => panic!("handshake succeeded"),
    }
}

/// Sends `m` and waits for its echo.
pub async fn echo(ws: &mut Ws, m: Message) {
    ws.send(m.clone()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("no echo within 5s")
        .unwrap()
        .unwrap();
    assert_eq!(got, m);
}

/// Waits until `f` holds, 5 seconds at most.
pub async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..250 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{what}: not within 5s");
}

/// Waits for `fut` 5 seconds at most.
pub async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("{what}: not within 5s"))
}

#[path = "../counters/mod.rs"]
mod counters;
#[allow(unused_imports)]
pub use counters::{counter, record};
