//! RFC 0004 test helpers: an upstream that speaks HTTP/1.1 and h2c, gRPC
//! framing by hand, and a channel body for streaming.
#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, Bytes, BytesMut};
use dvarapala_proxy::{Http2Limits, ReverseProxy, UpstreamConfig, UpstreamProtocol, serve};
use http::{HeaderMap, Request, Response};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::http2::SendRequest;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

pub type TestBody = BoxBody<Bytes, Infallible>;

/// A body fed from a channel: send frames, drop the sender to end it.
pub struct ChanBody(pub mpsc::Receiver<Frame<Bytes>>);

impl Body for ChanBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|f| f.map(Ok))
    }
}

pub fn chan() -> (mpsc::Sender<Frame<Bytes>>, TestBody) {
    let (tx, rx) = mpsc::channel(16);
    (tx, ChanBody(rx).boxed())
}

pub fn full(b: impl Into<Bytes>) -> TestBody {
    Full::new(b.into()).boxed()
}

/// One gRPC length-prefixed message, uncompressed.
pub fn grpc_frame(msg: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(5 + msg.len());
    b.put_u8(0);
    b.put_u32(msg.len() as u32);
    b.put_slice(msg);
    b.freeze()
}

/// Splits complete messages off the front of `buf`.
pub fn grpc_messages(buf: &mut BytesMut) -> Vec<Bytes> {
    let mut out = Vec::new();
    while buf.len() >= 5 {
        let n = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if buf.len() < 5 + n {
            break;
        }
        let m = buf.split_to(5 + n);
        out.push(m.freeze().slice(5..));
    }
    out
}

fn grpc_ok() -> HeaderMap {
    let mut t = HeaderMap::new();
    t.insert("grpc-status", "0".parse().unwrap());
    t
}

/// Upstream on HTTP/1.1 and h2c (prior knowledge), routed by path:
///
/// - `/version`: answers `<version> <te> <request body>`
/// - `/trailers`: body `ok`, trailer `x-trailer: yes`
/// - `/test.Echo/Unary`: echoes the one message, `grpc-status: 0`
/// - `/test.Echo/Stream`: 1000 messages, `0` to `999` as text
/// - `/test.Echo/Bidi`: echoes every message as it arrives
pub async fn upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(s), service_fn(route))
                    .await;
            });
        }
    });
    addr
}

/// An upstream that only speaks HTTP/1.1.
pub async fn http1_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(route))
                    .await;
            });
        }
    });
    addr
}

async fn route(req: Request<Incoming>) -> Result<Response<TestBody>, Infallible> {
    let grpc = |body: TestBody| {
        Response::builder()
            .header("content-type", "application/grpc")
            .body(body)
            .unwrap()
    };
    Ok(match req.uri().path() {
        "/version" => {
            let te = req
                .headers()
                .get("te")
                .map(|v| v.to_str().unwrap().to_owned())
                .unwrap_or_default();
            let v = format!("{:?} {te} ", req.version());
            let body = req.into_body().collect().await.unwrap().to_bytes();
            Response::new(full([v.as_bytes(), &body[..]].concat()))
        }
        "/trailers" => {
            let (tx, body) = chan();
            tokio::spawn(async move {
                tx.send(Frame::data(Bytes::from_static(b"ok")))
                    .await
                    .unwrap();
                let mut t = HeaderMap::new();
                t.insert("x-trailer", "yes".parse().unwrap());
                tx.send(Frame::trailers(t)).await.unwrap();
            });
            Response::new(body)
        }
        "/test.Echo/Unary" => {
            let mut buf = BytesMut::from(&req.into_body().collect().await.unwrap().to_bytes()[..]);
            let msg = grpc_messages(&mut buf).pop().unwrap_or_default();
            let (tx, body) = chan();
            tokio::spawn(async move {
                tx.send(Frame::data(grpc_frame(&msg))).await.unwrap();
                tx.send(Frame::trailers(grpc_ok())).await.unwrap();
            });
            grpc(body)
        }
        "/test.Echo/Stream" => {
            let (tx, body) = chan();
            tokio::spawn(async move {
                for i in 0..1000 {
                    let m = grpc_frame(i.to_string().as_bytes());
                    tx.send(Frame::data(m)).await.unwrap();
                }
                tx.send(Frame::trailers(grpc_ok())).await.unwrap();
            });
            grpc(body)
        }
        "/test.Echo/Bidi" => {
            let (tx, body) = chan();
            let mut incoming = req.into_body();
            tokio::spawn(async move {
                let mut buf = BytesMut::new();
                while let Some(Ok(f)) = incoming.frame().await {
                    if let Ok(d) = f.into_data() {
                        buf.extend_from_slice(&d);
                        for m in grpc_messages(&mut buf) {
                            tx.send(Frame::data(grpc_frame(&m))).await.unwrap();
                        }
                    }
                }
                tx.send(Frame::trailers(grpc_ok())).await.unwrap();
            });
            grpc(body)
        }
        _ => Response::builder().status(404).body(full("")).unwrap(),
    })
}

/// The proxy in front of `upstream`; drop the sender to stop it.
pub async fn proxy(
    upstream: &str,
    protocol: UpstreamProtocol,
    h2: Http2Limits,
) -> (SocketAddr, oneshot::Sender<()>) {
    // the update fills `tls` when the feature is on
    #[allow(clippy::needless_update)]
    let config = UpstreamConfig {
        protocol,
        ..UpstreamConfig::default()
    };
    let p = ReverseProxy::<Incoming>::with_config(upstream, &config).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, h2, p, async {
        let _ = rx.await;
    }));
    (addr, tx)
}

/// An h2c (prior knowledge) client connection to `addr`.
pub async fn h2(addr: SocketAddr) -> SendRequest<TestBody> {
    let s = TcpStream::connect(addr).await.unwrap();
    let (tx, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(s))
        .await
        .unwrap();
    tokio::spawn(conn);
    tx
}

/// An HTTP/1.1 client connection to `addr`.
pub async fn h1(addr: SocketAddr) -> hyper::client::conn::http1::SendRequest<TestBody> {
    let s = TcpStream::connect(addr).await.unwrap();
    let (tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
        .await
        .unwrap();
    tokio::spawn(conn);
    tx
}

/// A gRPC request to `path` on the proxy at `addr`.
pub fn grpc_request(addr: SocketAddr, path: &str, body: TestBody) -> Request<TestBody> {
    Request::post(format!("http://{addr}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(body)
        .unwrap()
}
