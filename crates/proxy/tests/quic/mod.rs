//! RFC 0006 test helpers: the proxy on a QUIC listener, an HTTP/3 client on
//! `quinn` and `h3`, a counting upstream and a UDP relay that misbehaves on
//! purpose.
#![allow(dead_code)]

use std::convert::Infallible;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Buf, Bytes};
use dvarapala_l7::RateLimitLayer;
use dvarapala_proxy::ReverseProxy;
use dvarapala_proxy::quic::{H3Body, QuicConfig, QuicListener};
use dvarapala_proxy::tls::{Tls, TlsConfig};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use quinn::crypto::rustls::QuicClientConfig;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{MutexGuard, Semaphore, oneshot};
use tower_layer::Layer;

#[path = "../support/mod.rs"]
mod support;
pub use support::{Ca, NAME, client_config, tempdir, write};

/// What the upstream saw, and a gate that holds its answers when closed.
pub struct Upstream {
    pub addr: SocketAddr,
    pub hits: Arc<AtomicUsize>,
    pub gate: Arc<Semaphore>,
}

/// HTTP/1.1 upstream answering `len=<request body bytes>`. Each answer
/// takes a permit from `gate`, which starts open.
pub async fn upstream() -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(Semaphore::new(Semaphore::MAX_PERMITS));
    let (h, g) = (hits.clone(), gate.clone());
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let (h, g) = (h.clone(), g.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (h, g) = (h.clone(), g.clone());
                    async move {
                        h.fetch_add(1, Ordering::SeqCst);
                        let n = req.into_body().collect().await.unwrap().to_bytes().len();
                        let _permit = g.acquire().await.unwrap();
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                            "len={n}"
                        )))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    Upstream { addr, hits, gate }
}

pub struct Proxy {
    pub addr: SocketAddr,
    pub ca: Ca,
    pub upstream: Upstream,
    _stop: oneshot::Sender<()>,
}

/// The reverse proxy on a QUIC listener at 127.0.0.1, `tune` applied to
/// the defaults, behind `limiter` when given.
pub async fn proxy(tune: impl FnOnce(&mut QuicConfig), limiter: Option<RateLimitLayer>) -> Proxy {
    let ca = Ca::new();
    let (cert_pem, key_pem) = ca.leaf(&[NAME]);
    let dir = tempdir();
    let tls = Tls::new(TlsConfig {
        cert: write(&dir, "cert.pem", &cert_pem),
        key: write(&dir, "key.pem", &key_pem),
        handshake_timeout: Duration::from_secs(5),
        max_handshakes: 64,
    })
    .unwrap();
    let up = upstream().await;
    let p = ReverseProxy::<H3Body>::new(&format!("http://{}", up.addr)).unwrap();
    let mut cfg = QuicConfig::new("127.0.0.1:0".parse().unwrap());
    tune(&mut cfg);
    let l = QuicListener::bind(cfg, &tls).unwrap();
    let addr = l.local_addr();
    let (tx, rx) = oneshot::channel::<()>();
    let stop = async {
        let _ = rx.await;
    };
    match limiter {
        None => tokio::spawn(l.serve(p, stop)),
        Some(layer) => tokio::spawn(l.serve(layer.layer(p), stop)),
    };
    Proxy {
        addr,
        ca,
        upstream: up,
        _stop: tx,
    }
}

/// A client endpoint trusting `ca`, ALPN `h3`; `early` offers 0-RTT.
pub fn client(ca: &Ca, early: bool) -> quinn::Endpoint {
    let mut tls = (*client_config(&ca.pem, &[b"h3"])).clone();
    tls.enable_early_data = early;
    let mut c = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(5).try_into().unwrap()));
    c.transport_config(Arc::new(t));
    let mut e = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    e.set_default_client_config(c);
    e
}

/// A QUIC connection to `addr`, 5 seconds at most.
pub async fn connect(e: &quinn::Endpoint, addr: SocketAddr) -> Result<quinn::Connection, String> {
    let c = e.connect(addr, NAME).map_err(|e| e.to_string())?;
    tokio::time::timeout(Duration::from_secs(5), c)
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())
}

pub type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// HTTP/3 on `conn`; the driver runs in the background.
pub async fn h3(conn: quinn::Connection) -> Sender {
    let (mut driver, tx) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .unwrap();
    tokio::spawn(async move { poll_fn(|cx| driver.poll_close(cx)).await });
    tx
}

/// One request with `body`: `(status, response headers, body)`.
pub async fn send(
    tx: &mut Sender,
    method: &str,
    path: &str,
    body: Bytes,
) -> (StatusCode, http::HeaderMap, String) {
    let req = Request::builder()
        .method(method)
        .uri(format!("https://{NAME}{path}"))
        .body(())
        .unwrap();
    let mut s = tx.send_request(req).await.unwrap();
    if !body.is_empty() {
        s.send_data(body).await.unwrap();
    }
    s.finish().await.unwrap();
    let res = s.recv_response().await.unwrap();
    let mut out = Vec::new();
    while let Some(mut chunk) = s.recv_data().await.unwrap() {
        out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (
        res.status(),
        res.headers().clone(),
        String::from_utf8(out).unwrap(),
    )
}

/// How a [`relay`] misbehaves.
#[derive(Clone, Copy)]
pub enum Mode {
    /// Forwards to the server, drops every reply: a handshake that stalls.
    Blackhole,
    /// After the server's first reply (the Retry), sends from a new port:
    /// the token is for another address.
    Switch,
    /// After the server's first reply, holds client datagrams this long.
    Delay(Duration),
}

/// A UDP relay in front of `server` for one client; connect to the
/// returned address.
pub async fn relay(server: SocketAddr, mode: Mode) -> SocketAddr {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap();
    let backs = [
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
    ];
    let replied = Arc::new(AtomicBool::new(false));
    let client = Arc::new(Mutex::new(None::<SocketAddr>));
    for back in &backs {
        let (back, front, replied, client) =
            (back.clone(), front.clone(), replied.clone(), client.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = back.recv(&mut buf).await {
                replied.store(true, Ordering::SeqCst);
                let to = *client.lock().unwrap();
                if let (false, Some(to)) = (matches!(mode, Mode::Blackhole), to) {
                    let _ = front.send_to(&buf[..n], to).await;
                }
            }
        });
    }
    for back in &backs {
        back.connect(server).await.unwrap();
    }
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = front.recv_from(&mut buf).await {
            *client.lock().unwrap() = Some(from);
            let after = replied.load(Ordering::SeqCst);
            let back = backs[usize::from(after && matches!(mode, Mode::Switch))].clone();
            let data = buf[..n].to_vec();
            match mode {
                Mode::Delay(d) if after => {
                    tokio::spawn(async move {
                        tokio::time::sleep(d).await;
                        let _ = back.send(&data).await;
                    });
                }
                _ => {
                    let _ = back.send(&data).await;
                }
            }
        }
    });
    addr
}

/// Serializes the tests: the counters are global, and any handshake moves
/// them.
pub async fn serial() -> MutexGuard<'static, ()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    LOCK.lock().await
}

#[path = "../counters/mod.rs"]
mod counters;
pub use counters::{counter, record};
