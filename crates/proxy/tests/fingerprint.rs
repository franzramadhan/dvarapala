//! RFC 0012 cases 16 and 17: JA4 on the TLS listener, to the upstream and
//! in the rules.
#![cfg(feature = "tls")]

mod support;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Limit, TrustedProxies};
use dvarapala_l7::{Fingerprints, RateLimitConfig, RateLimitLayer};
use dvarapala_proxy::tls::{Tls, TlsConfig};
use dvarapala_proxy::{Http2Limits, ReverseProxy, serve_tls};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use support::{Ca, NAME, client_config, connect, tempdir, write};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_layer::Layer;

/// Upstream answering with every `x-ja4` value it got, joined by `|`.
async fn echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let svc = service_fn(|req: Request<Incoming>| async move {
                let seen: Vec<_> = req
                    .headers()
                    .get_all("x-ja4")
                    .iter()
                    .map(|v| v.to_str().unwrap().to_owned())
                    .collect();
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(seen.join("|")))))
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc),
            );
        }
    });
    addr
}

async fn proxy(rules: Fingerprints) -> (SocketAddr, Ca, oneshot::Sender<()>) {
    let ca = Ca::new();
    let (cert_pem, key_pem) = ca.leaf(&[NAME]);
    let dir = tempdir();
    let tls = Tls::new(TlsConfig {
        cert: write(&dir, "cert.pem", &cert_pem),
        key: write(&dir, "key.pem", &key_pem),
        handshake_timeout: Duration::from_secs(10),
        max_handshakes: 64,
        fingerprint: rules.enabled(),
    })
    .unwrap();
    let layer = RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(100, 100).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: rules,
    })
    .unwrap();
    let p = ReverseProxy::<Incoming>::new(&format!("http://{}", echo().await)).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve_tls(
        l,
        tls,
        Http2Limits::default(),
        layer.layer(p),
        async {
            let _ = rx.await;
        },
    ));
    (addr, ca, tx)
}

/// One HTTP/1.1 GET with a spoofed `x-ja4`: `(status, connection, body)`.
async fn get(addr: SocketAddr, ca: &Ca) -> (StatusCode, Option<String>, String) {
    let s = connect(addr, client_config(&ca.pem, &[b"http/1.1"]))
        .await
        .unwrap();
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::get("/")
        .header("host", NAME)
        .header("x-ja4", "spoofed")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = tx.send_request(req).await.unwrap();
    let status = res.status();
    let conn = res
        .headers()
        .get("connection")
        .map(|v| v.to_str().unwrap().to_owned());
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, conn, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_sees_the_computed_ja4_only() {
    let (addr, ca, _stop) = proxy(Fingerprints::new(&[], &[], "x-ja4").unwrap()).await;
    let (status, _, body) = get(addr, &ca).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.len(), 36, "{body}");
    // rustls offers TLS 1.3, sends SNI and ALPN http/1.1
    assert!(body.starts_with("t13d") && body[8..10] == *"h1", "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn denied_fingerprint_is_dropped() {
    let (addr, ca, _stop) = proxy(Fingerprints::new(&["t13d*".into()], &[], "").unwrap()).await;
    let (status, conn, _) = get(addr, &ca).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(conn.as_deref(), Some("close"));
}

#[tokio::test(flavor = "multi_thread")]
async fn other_fingerprints_pass() {
    let (addr, ca, _stop) = proxy(Fingerprints::new(&["t12*".into()], &[], "").unwrap()).await;
    assert_eq!(get(addr, &ca).await.0, StatusCode::OK);
}
