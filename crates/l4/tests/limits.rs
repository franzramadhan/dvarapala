//! RFC 0009 cases 6 to 8: the listener closes connections over the limits
//! before anything is read.

#[path = "../../proxy/tests/counters/mod.rs"]
mod counters;

use std::net::SocketAddr;
use std::time::Duration;

use counters::{counter, record};
use dvarapala_engine::ConnsConfig;
use dvarapala_l4::{Conn, L4Config, Listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// A listener with `config`; accepted connections arrive on the channel and
/// stay open until dropped there.
async fn listen(config: L4Config) -> (SocketAddr, mpsc::UnboundedReceiver<Conn>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let l = Listener::new(tcp, config).unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((conn, _)) = l.accept().await {
            if tx.send(conn).is_err() {
                return;
            }
        }
    });
    (addr, rx)
}

fn limits(max_per_client: u32, max_connections: usize) -> L4Config {
    L4Config {
        max_connections,
        conns: ConnsConfig {
            max_per_client,
            ..ConnsConfig::default()
        },
        ..L4Config::default()
    }
}

/// Whether the proxy closed `s` without sending a byte.
async fn closed(mut s: TcpStream) -> bool {
    let mut b = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await {
        Ok(Ok(0) | Err(_)) => true,
        Ok(Ok(_)) => false,
        Err(_) => panic!("still open after 5 s"),
    }
}

/// Accepted connections answer one byte with `!`.
async fn served(mut conn: Conn, mut s: TcpStream) {
    s.write_all(b"?").await.unwrap();
    let mut b = [0u8; 1];
    conn.read_exact(&mut b).await.unwrap();
    conn.write_all(b"!").await.unwrap();
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"!");
}

/// RFC 0009 case 6
#[tokio::test]
async fn third_from_one_client_is_closed() {
    record();
    let (addr, mut rx) = listen(limits(2, 0)).await;
    let a = TcpStream::connect(addr).await.unwrap();
    let _b = TcpStream::connect(addr).await.unwrap();
    let (ca, _cb) = (rx.recv().await.unwrap(), rx.recv().await.unwrap());
    let c = TcpStream::connect(addr).await.unwrap();
    assert!(closed(c).await);
    assert_eq!(counter("dvarapala_l4_rejected_total{reason=per_client}"), 1);
    served(ca, a).await;
}

/// RFC 0009 cases 7 and 8
#[tokio::test]
async fn total_cap_and_freed_places() {
    record();
    let (addr, mut rx) = listen(limits(0, 2)).await;
    let _a = TcpStream::connect(addr).await.unwrap();
    let _b = TcpStream::connect(addr).await.unwrap();
    let (ca, _cb) = (rx.recv().await.unwrap(), rx.recv().await.unwrap());
    let c = TcpStream::connect(addr).await.unwrap();
    assert!(closed(c).await);
    assert_eq!(counter("dvarapala_l4_rejected_total{reason=total}"), 1);
    // case 8: a closed connection frees its place
    drop(ca);
    let d = TcpStream::connect(addr).await.unwrap();
    let cd = rx.recv().await.unwrap();
    served(cd, d).await;
}

#[tokio::test]
async fn off_accepts_everything() {
    let (addr, mut rx) = listen(L4Config {
        enabled: false,
        ..limits(1, 1)
    })
    .await;
    let streams = connect_n(addr, 5).await;
    for s in streams {
        served(rx.recv().await.unwrap(), s).await;
    }
}

async fn connect_n(addr: SocketAddr, n: usize) -> Vec<TcpStream> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(TcpStream::connect(addr).await.unwrap());
    }
    v
}
