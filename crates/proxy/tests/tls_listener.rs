//! RFC 0003: the TLS listener.
#![cfg(feature = "tls")]

mod support;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use dvarapala_proxy::tls::{Tls, TlsConfig};
use dvarapala_proxy::{ReverseProxy, serve_tls};
use http::{StatusCode, Version};
use hyper::body::Incoming;
use rustls::HandshakeKind;
use support::{Ca, NAME, client_config, connect, der, get, tempdir, upstream, write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

struct Proxy {
    addr: SocketAddr,
    tls: Tls,
    ca: Ca,
    cert: PathBuf,
    key: PathBuf,
    _stop: oneshot::Sender<()>,
}

async fn proxy(handshake_timeout: Duration, max_handshakes: usize) -> Proxy {
    let ca = Ca::new();
    let (cert_pem, key_pem) = ca.leaf(&[NAME]);
    let dir = tempdir();
    let cert = write(&dir, "cert.pem", &cert_pem);
    let key = write(&dir, "key.pem", &key_pem);
    let tls = Tls::new(TlsConfig {
        cert: cert.clone(),
        key: key.clone(),
        handshake_timeout,
        max_handshakes,
    })
    .unwrap();
    let up = upstream("ok").await;
    let p = ReverseProxy::<Incoming>::new(&format!("http://{up}")).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve_tls(l, tls.clone(), p, async {
        let _ = rx.await;
    }));
    Proxy {
        addr,
        tls,
        ca,
        cert,
        key,
        _stop: tx,
    }
}

async fn defaults() -> Proxy {
    proxy(Duration::from_secs(10), 1024).await
}

/// Reads until the server closes; `true` if it did within `within`.
async fn closed_within(s: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 1024];
    let read = async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(within, read).await.is_ok()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn alpn_http1() {
    let p = defaults().await;
    let s = connect(p.addr, client_config(&p.ca.pem, &[b"http/1.1"]))
        .await
        .unwrap();
    assert_eq!(
        get(s).await,
        (Version::HTTP_11, StatusCode::OK, "ok".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn alpn_h2() {
    let p = defaults().await;
    let s = connect(p.addr, client_config(&p.ca.pem, &[b"h2", b"http/1.1"]))
        .await
        .unwrap();
    assert_eq!(get(s).await, (Version::HTTP_2, StatusCode::OK, "ok".into()));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn no_alpn_is_http1() {
    let p = defaults().await;
    let s = connect(p.addr, client_config(&p.ca.pem, &[]))
        .await
        .unwrap();
    assert_eq!(get(s).await.0, Version::HTTP_11);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn plaintext_on_tls_port_is_closed() {
    let p = defaults().await;
    let mut s = TcpStream::connect(p.addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(closed_within(&mut s, Duration::from_secs(2)).await);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn stalled_handshake_times_out() {
    let p = proxy(Duration::from_millis(200), 1024).await;
    let mut s = TcpStream::connect(p.addr).await.unwrap();
    let start = Instant::now();
    assert!(closed_within(&mut s, Duration::from_secs(3)).await);
    assert!(start.elapsed() >= Duration::from_millis(150));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn handshake_limit_rejects_then_recovers() {
    let p = proxy(Duration::from_secs(10), 2).await;
    let a = TcpStream::connect(p.addr).await.unwrap();
    let _b = TcpStream::connect(p.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // over the limit: closed at once, long before the 10 s timeout
    let mut c = TcpStream::connect(p.addr).await.unwrap();
    assert!(closed_within(&mut c, Duration::from_secs(1)).await);
    // one stalled handshake ends, its slot frees up
    drop(a);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s = connect(p.addr, client_config(&p.ca.pem, &[]))
        .await
        .unwrap();
    assert_eq!(get(s).await.1, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn reload_swaps_the_certificate() {
    let p = defaults().await;
    let old = std::fs::read_to_string(&p.cert).unwrap();
    let cfg = client_config(&p.ca.pem, &[]);
    let before = connect(p.addr, cfg.clone()).await.unwrap();
    assert_eq!(
        before.get_ref().1.peer_certificates().unwrap()[0],
        der(&old)
    );

    let (cert_pem, key_pem) = p.ca.leaf(&[NAME]);
    std::fs::write(&p.cert, &cert_pem).unwrap();
    std::fs::write(&p.key, &key_pem).unwrap();
    p.tls.reload().unwrap();

    let after = connect(p.addr, cfg).await.unwrap();
    assert_eq!(
        after.get_ref().1.peer_certificates().unwrap()[0],
        der(&cert_pem)
    );
    // the connection opened before the reload still works
    assert_eq!(get(before).await.1, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn failed_reload_keeps_the_old_certificate() {
    let p = defaults().await;
    let old = std::fs::read_to_string(&p.cert).unwrap();
    std::fs::write(&p.cert, "not a certificate").unwrap();
    assert!(p.tls.reload().is_err());
    let s = connect(p.addr, client_config(&p.ca.pem, &[]))
        .await
        .unwrap();
    assert_eq!(s.get_ref().1.peer_certificates().unwrap()[0], der(&old));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0003"]
async fn returning_client_resumes() {
    let p = defaults().await;
    let cfg = client_config(&p.ca.pem, &[]);
    // a full request lets the client read the session tickets
    let first = connect(p.addr, cfg.clone()).await.unwrap();
    assert_eq!(
        first.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Full)
    );
    get(first).await;
    let second = connect(p.addr, cfg).await.unwrap();
    assert_eq!(
        second.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );
}
