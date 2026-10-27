use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use dvarapala_proxy::{ReverseProxy, serve};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Upstream that answers with what it received: method, path, selected
/// headers and the body, one per line.
async fn echo_upstream() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<Incoming>| async move {
                    let h = |n: &str| {
                        req.headers()
                            .get(n)
                            .map(|v| v.to_str().unwrap().to_owned())
                            .unwrap_or_default()
                    };
                    let head = format!(
                        "{} {}\nx-custom={}\nx-secret-hop={}\nx-forwarded-for={}\n",
                        req.method(),
                        req.uri(),
                        h("x-custom"),
                        h("x-secret-hop"),
                        h("x-forwarded-for"),
                    );
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    let out = [head.as_bytes(), &body[..]].concat();
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(out))))
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    addr
}

/// Starts the proxy in front of `upstream`; drop the sender to stop it.
async fn proxy(upstream: &str) -> (SocketAddr, oneshot::Sender<()>) {
    let p = ReverseProxy::<Incoming>::new(upstream).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, p, async {
        let _ = rx.await;
    }));
    (addr, tx)
}

async fn send(addr: SocketAddr, req: Request<Full<Bytes>>) -> (StatusCode, String) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let (parts, body) = req.into_parts();
    let mut parts = parts;
    parts.uri = format!("http://{addr}{}", parts.uri).parse().unwrap();
    let res = client
        .request(Request::from_parts(parts, body))
        .await
        .unwrap();
    let status = res.status();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_request_and_strips_hop_headers() {
    let up = echo_upstream().await;
    let (addr, _stop) = proxy(&format!("http://{up}/base")).await;
    let req = Request::post("/items?id=7")
        .header("x-custom", "kept")
        .header("connection", "x-secret-hop")
        .header("x-secret-hop", "dropped")
        .body(Full::new(Bytes::from_static(b"payload")))
        .unwrap();
    let (status, body) = send(addr, req).await;
    assert_eq!(status, StatusCode::OK);
    let mut lines = body.lines();
    assert_eq!(lines.next(), Some("POST /base/items?id=7"));
    assert_eq!(lines.next(), Some("x-custom=kept"));
    assert_eq!(lines.next(), Some("x-secret-hop="));
    assert_eq!(lines.next(), Some("x-forwarded-for=127.0.0.1"));
    assert_eq!(lines.next(), Some("payload"));
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_down_is_502() {
    // bind then drop: nothing listens on this port
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (addr, _stop) = proxy(&format!("http://{dead}")).await;
    let (status, _) = send(addr, Request::get("/").body(Full::default()).unwrap()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_stops_accepting() {
    let up = echo_upstream().await;
    let p = ReverseProxy::<Incoming>::new(&format!("http://{up}")).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let server = tokio::spawn(serve(l, p, async {
        let _ = rx.await;
    }));
    let (status, _) = send(addr, Request::get("/").body(Full::default()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}
