//! RFC 0007 case 16: memory of waiting requests. Sends `DVARAPALA_WAITERS`
//! (default 1000) requests straight to an upstream that never answers, then
//! as many through the forward proxy, where all but the first wait for a
//! slot. Reports the difference in RSS growth per request: the proxy's
//! share, since client and upstream run in this process too.
//!
//! `cargo bench -p dvarapala-proxy --bench forward_wait`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::ScheduleConfig;
use dvarapala_proxy::{Destination, ForwardConfig, ForwardProxy, Http2Limits, serve};
use http::{Request, Response};
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// RFC 0007 implementation notes: measured about 5.5 KB (the request head,
/// its connection and the wait), budget 8 KB.
const BUDGET_PER_WAITER: u64 = 8 * 1024;

async fn never(_req: Request<Incoming>) -> Result<Response<Empty<Bytes>>, Infallible> {
    std::future::pending().await
}

/// Peak RSS in bytes. Memory only grows here, so the peak is the current
/// size.
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
    let n: u64 = std::env::var("DVARAPALA_WAITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = up.accept().await.unwrap();
            tokio::spawn(
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), service_fn(never)),
            );
        }
    });
    let config = ForwardConfig {
        destinations: vec![Destination {
            name: "bench".into(),
            origin: format!("http://{up_addr}"),
            schedule: ScheduleConfig {
                rate: 0.001,
                burst: 1,
                max_queue: n as usize,
                max_wait: Duration::from_secs(3600 * 1000),
                max_pause: Duration::ZERO,
            },
            max_concurrent: 0,
        }],
        ..ForwardConfig::default()
    };
    let p = ForwardProxy::<Incoming>::new(&config).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(l, Http2Limits::default(), p, std::future::pending()));

    let target = format!("http://{up_addr}/");
    let (direct, _d) = open(up_addr, "/", n).await;
    let (proxied, _p) = open(addr, &target, n).await;
    let per = proxied.saturating_sub(direct) / n;
    println!("{n} waiting requests: {per} bytes each in the proxy (budget {BUDGET_PER_WAITER})");
    assert!(per <= BUDGET_PER_WAITER, "over the RFC 0007 budget");
}

/// Sends `n` requests for `target` to `addr` that stay unanswered: the RSS
/// growth in bytes, and the connections to keep open.
async fn open(addr: SocketAddr, target: &str, n: u64) -> (u64, Vec<TcpStream>) {
    let before = rss();
    let head = format!("GET {target} HTTP/1.1\r\nhost: bench\r\nuser-agent: bench\r\n\r\n");
    let mut conns = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(head.as_bytes()).await.unwrap();
        conns.push(s);
    }
    // let every request reach its wait
    tokio::time::sleep(Duration::from_secs(1)).await;
    (rss() - before, conns)
}
