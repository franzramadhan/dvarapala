//! RFC 0007 test helpers: an upstream that records what it saw, the forward
//! proxy, and clients for absolute-form requests and `CONNECT`.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::ScheduleConfig;
use dvarapala_proxy::{Destination, ForwardConfig, ForwardProxy, Http2Limits, serve};
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

#[path = "../counters/mod.rs"]
mod counters;
#[allow(unused_imports)]
pub use counters::{counter, record};

/// How the upstream answers.
#[derive(Clone, Default)]
pub struct Behave {
    /// Sleep before answering.
    pub delay: Duration,
    /// Answer the first request with this status and `Retry-After`.
    pub first: Option<(StatusCode, &'static str)>,
}

/// What the upstream saw.
#[derive(Default)]
pub struct Seen {
    pub times: Mutex<Vec<Instant>>,
    pub in_flight: AtomicUsize,
    pub max_in_flight: AtomicUsize,
}

impl Seen {
    pub fn hits(&self) -> usize {
        self.times.lock().unwrap().len()
    }
}

/// HTTP/1.1 upstream answering `200` with `METHOD URI`, then one
/// `name=value` line per header it got.
pub async fn upstream(behave: Behave) -> (SocketAddr, Arc<Seen>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = l.accept().await.unwrap();
            let (s, behave) = (s.clone(), behave.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req| answer(req, s.clone(), behave.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, seen)
}

async fn answer(
    req: Request<Incoming>,
    seen: Arc<Seen>,
    behave: Behave,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let nth = {
        let mut t = seen.times.lock().unwrap();
        t.push(Instant::now());
        t.len()
    };
    let now = seen.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    seen.max_in_flight.fetch_max(now, Ordering::SeqCst);
    tokio::time::sleep(behave.delay).await;
    seen.in_flight.fetch_sub(1, Ordering::SeqCst);
    if let (1, Some((status, retry_after))) = (nth, behave.first) {
        return Ok(Response::builder()
            .status(status)
            .header("retry-after", retry_after)
            .body(Full::default())
            .unwrap());
    }
    let mut out = format!("{} {}\n", req.method(), req.uri());
    for (k, v) in req.headers() {
        out += &format!("{k}={}\n", v.to_str().unwrap_or("?"));
    }
    Ok(Response::new(Full::new(Bytes::from(out))))
}

/// A destination for `origin` with the default schedule at `rate`, `burst`.
pub fn dest(name: &str, origin: &str, rate: f64, burst: u32) -> Destination {
    Destination {
        name: name.to_owned(),
        origin: origin.to_owned(),
        schedule: ScheduleConfig {
            rate,
            burst,
            ..ScheduleConfig::default()
        },
        max_concurrent: 0,
    }
}

/// The forward proxy for `destinations`; drop the sender to stop it.
pub async fn proxy(config: ForwardConfig) -> (SocketAddr, oneshot::Sender<()>) {
    let p = ForwardProxy::<Incoming>::new(&config).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, Http2Limits::default(), p, async {
        let _ = rx.await;
    }));
    (addr, tx)
}

pub fn config(destinations: Vec<Destination>) -> ForwardConfig {
    ForwardConfig {
        destinations,
        ..ForwardConfig::default()
    }
}

/// Sends `req` (absolute form) on a new connection to the proxy.
pub async fn send(
    proxy: SocketAddr,
    req: Request<Empty<Bytes>>,
) -> (StatusCode, HeaderMap, String) {
    let io = TokioIo::new(TcpStream::connect(proxy).await.unwrap());
    let (mut tx, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(conn);
    let res = tx.send_request(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

/// `GET {url}` through the proxy.
pub async fn get(proxy: SocketAddr, url: &str) -> (StatusCode, HeaderMap, String) {
    send(proxy, Request::get(url).body(Empty::new()).unwrap()).await
}

/// `CONNECT target`: the open stream after a `200`, or the status.
pub async fn connect(proxy: SocketAddr, target: &str) -> Result<TcpStream, StatusCode> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let head = format!("CONNECT {target} HTTP/1.1\r\nhost: {target}\r\n\r\n");
    s.write_all(head.as_bytes()).await.unwrap();
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut byte).await.unwrap(), 1, "proxy closed");
        got.push(byte[0]);
    }
    let line = String::from_utf8_lossy(&got);
    let code: u16 = line.split(' ').nth(1).unwrap().parse().unwrap();
    match StatusCode::from_u16(code).unwrap() {
        StatusCode::OK => Ok(s),
        other => Err(other),
    }
}

/// Plain HTTP/1.1 `GET /` over a `CONNECT` tunnel; the response body.
pub async fn get_over(tunnel: TcpStream) -> String {
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tunnel))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::get("/")
        .header("host", "x")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let body = tx.send_request(req).await.unwrap().into_body();
    String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap()
}
