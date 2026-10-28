//! RFC 0005 case 13: memory of idle tunnels. Opens `DVARAPALA_TUNNELS`
//! (default 10000) upgrades straight to the upstream, then as many through
//! the proxy, and reports the difference in RSS growth per tunnel: the
//! proxy's share, since client and upstream run in this process too.
//!
//! `cargo bench -p dvarapala-proxy --bench tunnels`. Needs about 4 file
//! descriptors and 2 ephemeral ports per tunnel; on macOS (16k ports) use
//! `DVARAPALA_TUNNELS=5000`.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use dvarapala_proxy::{Http2Limits, ReverseProxy, UpgradeConfig, UpstreamConfig, serve};
use http::{Request, Response, StatusCode};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// RFC 0005 budget: about 200 MB for the default 10000 tunnels.
const BUDGET_PER_TUNNEL: u64 = 20 * 1024;

const UPGRADE: &[u8] =
    b"GET / HTTP/1.1\r\nhost: bench\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n";

async fn hold(mut req: Request<Incoming>) -> Result<Response<Empty<Bytes>>, Infallible> {
    let on = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        // keep the upgraded connection open and idle
        if let Ok(io) = on.await {
            let _io = io;
            std::future::pending::<()>().await;
        }
    });
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Empty::new())
        .unwrap())
}

/// Peak RSS in bytes. Memory only grows here, so the peak is the current
/// size; `ps` cannot be spawned with thousands of descriptors open.
fn rss() -> u64 {
    let mut u = unsafe { std::mem::zeroed::<libc::rusage>() };
    // SAFETY: `u` is a valid rusage for getrusage to fill
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) }, 0);
    let max = u.ru_maxrss as u64;
    // kilobytes on Linux, bytes on macOS
    if cfg!(target_os = "macos") {
        max
    } else {
        max * 1024
    }
}

#[tokio::main]
async fn main() {
    let n: u64 = std::env::var("DVARAPALA_TUNNELS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = up.accept().await.unwrap();
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(hold))
                    .with_upgrades(),
            );
        }
    });
    let config = UpstreamConfig {
        upgrade: UpgradeConfig {
            max_tunnels: n as usize,
            ..UpgradeConfig::default()
        },
        ..UpstreamConfig::default()
    };
    let p = ReverseProxy::<Incoming>::with_config(&format!("http://{up_addr}"), &config).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(l, Http2Limits::default(), p, std::future::pending()));

    let (direct, _d) = open(up_addr, n).await;
    let (proxied, _p) = open(addr, n).await;
    let per = proxied.saturating_sub(direct) / n;
    println!("{n} idle tunnels: {per} bytes each in the proxy (budget {BUDGET_PER_TUNNEL})");
    assert!(per <= BUDGET_PER_TUNNEL, "over the RFC 0005 budget");
}

/// Opens `n` idle upgraded connections to `addr`: the RSS growth in bytes,
/// and the connections to keep open.
async fn open(addr: std::net::SocketAddr, n: u64) -> (u64, Vec<TcpStream>) {
    let before = rss();
    let mut conns = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(UPGRADE).await.unwrap();
        let mut head = [0u8; 12];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
        conns.push(s);
    }
    // let the tunnel tasks reach their copy loops
    tokio::time::sleep(Duration::from_secs(1)).await;
    (rss() - before, conns)
}
