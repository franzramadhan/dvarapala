//! RFC 0009 cases 9 to 11 and 13: timeouts and limits through `serve`.

mod ws;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::ConnsConfig;
use dvarapala_l4::{L4Config, Listener};
use dvarapala_proxy::{Http2Limits, ReverseProxy, UpstreamConfig, serve};
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use ws::{counter, record};

const GET: &[u8] = b"GET / HTTP/1.1\r\nhost: x\r\n\r\n";

/// Upstream that reads the whole body, then answers `ok`.
async fn reader() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let svc = service_fn(|req: Request<Incoming>| async move {
                let _ = req.into_body().collect().await;
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            });
            tokio::spawn(
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc),
            );
        }
    });
    addr
}

/// The proxy in front of `upstream` on a listener with `l4`.
async fn proxy(upstream: SocketAddr, l4: L4Config) -> (SocketAddr, oneshot::Sender<()>) {
    let p = ReverseProxy::<Incoming>::with_config(
        &format!("http://{upstream}"),
        &UpstreamConfig::default(),
    )
    .unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    let l = Listener::new(tcp, l4).unwrap();
    tokio::spawn(serve(l, Http2Limits::default(), p, async {
        let _ = rx.await;
    }));
    (addr, tx)
}

/// Reads one response head and its short body.
async fn response(s: &mut TcpStream) -> String {
    let mut buf = vec![0u8; 1024];
    let n = ws::within("response", s.read(&mut buf)).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Time until the proxy closes `s`, reading and dropping what it sends.
async fn until_closed(s: &mut TcpStream) -> Duration {
    let start = Instant::now();
    let mut buf = [0u8; 256];
    ws::within("close", async {
        while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
    })
    .await;
    start.elapsed()
}

/// RFC 0009 case 9
#[tokio::test]
async fn slow_second_head_times_out() {
    record();
    let (addr, _stop) = proxy(
        reader().await,
        L4Config {
            header_timeout: Duration::from_secs(1),
            ..L4Config::default()
        },
    )
    .await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(GET).await.unwrap();
    assert!(response(&mut s).await.starts_with("HTTP/1.1 200"));
    s.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
    let took = until_closed(&mut s).await;
    assert!(
        took >= Duration::from_millis(800) && took < Duration::from_secs(3),
        "{took:?}"
    );
    ws::eventually("header counted", || {
        counter("dvarapala_l4_timeouts_total{kind=header}") >= 1
    })
    .await;
}

/// RFC 0009 case 10
#[tokio::test]
async fn idle_keep_alive_is_closed() {
    record();
    let (addr, _stop) = proxy(
        reader().await,
        L4Config {
            idle_timeout: Some(Duration::from_secs(1)),
            ..L4Config::default()
        },
    )
    .await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(GET).await.unwrap();
    assert!(response(&mut s).await.starts_with("HTTP/1.1 200"));
    let took = until_closed(&mut s).await;
    assert!(
        took >= Duration::from_millis(800) && took < Duration::from_secs(3),
        "{took:?}"
    );
    assert!(counter("dvarapala_l4_timeouts_total{kind=idle}") >= 1);
}

/// RFC 0009 case 11: 10 bytes a second against 1000, over the 10 s window
#[tokio::test]
async fn slow_body_gets_408() {
    record();
    let (addr, _stop) = proxy(
        reader().await,
        L4Config {
            min_body_rate: 1000,
            ..L4Config::default()
        },
    )
    .await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nhost: x\r\ncontent-length: 1000\r\n\r\n")
        .await
        .unwrap();
    let (mut r, mut w) = s.into_split();
    tokio::spawn(async move {
        while w.write_all(&[b'x'; 10]).await.is_ok() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(15), r.read(&mut buf))
        .await
        .expect("no answer within 15 s")
        .unwrap();
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 408"), "{head}");
    assert!(counter("dvarapala_l4_timeouts_total{kind=body}") >= 1);
}

/// RFC 0009 case 13
#[tokio::test]
async fn tunnel_holds_its_place_until_closed() {
    let (up, _) = ws::upstream().await;
    let one = L4Config {
        conns: ConnsConfig {
            max_per_client: 1,
            ..ConnsConfig::default()
        },
        ..L4Config::default()
    };
    let (addr, _stop) = proxy(up, one).await;
    let mut tunnel = ws::connect(addr, "/").await.unwrap();
    ws::echo(&mut tunnel, "hi".into()).await;
    let mut second = TcpStream::connect(addr).await.unwrap();
    let mut b = [0u8; 1];
    assert!(matches!(
        ws::within("refused", second.read(&mut b)).await,
        Ok(0) | Err(_)
    ));
    drop(tunnel);
    // the place frees once the proxy sees the tunnel end
    let mut served = false;
    for _ in 0..50 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(GET).await.unwrap();
        let mut buf = [0u8; 64];
        if matches!(s.read(&mut buf).await, Ok(n) if n > 0) {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(served, "place not freed after the tunnel closed");
}
