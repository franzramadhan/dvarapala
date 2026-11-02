//! RFC 0030 cases 7 to 10 and 12: the PROXY protocol header of a trusted
//! balancer at the listener.

#[path = "../../proxy/tests/counters/mod.rs"]
mod counters;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use counters::{counter, record};
use dvarapala_engine::{BlockSink, Cidr, ConnsConfig, Limit};
use dvarapala_l4::proxy_protocol::Version;
use dvarapala_l4::{Conn, L4Config, Listener, ProxyProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

fn config(from: &str, conns: ConnsConfig) -> L4Config {
    L4Config {
        conns,
        proxy_protocol: Some(ProxyProtocol {
            version: Version::Any,
            from: vec![from.parse().unwrap()],
            timeout: Duration::from_millis(300),
        }),
        ..L4Config::default()
    }
}

/// Ready connections and their clients arrive on the channel; each header
/// is read in its own task, as the server does.
async fn listen(
    config: L4Config,
    block: Option<BlockSink>,
) -> (SocketAddr, mpsc::UnboundedReceiver<(Conn, SocketAddr)>) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let mut l = Listener::new(tcp, config).unwrap();
    if let Some(b) = block {
        l = l.with_block(b);
    }
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok(a) = l.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Some(c) = a.ready().await {
                    let _ = tx.send(c);
                }
            });
        }
    });
    (addr, rx)
}

/// A connection that opens with a v1 header for `client`.
async fn proxied(addr: SocketAddr, client: &str) -> TcpStream {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let c: SocketAddr = client.parse().unwrap();
    let line = format!("PROXY TCP4 {} 198.51.100.1 {} 443\r\n", c.ip(), c.port());
    s.write_all(line.as_bytes()).await.unwrap();
    s
}

/// Time until the listener closes `s`, which must get no byte.
async fn closed(mut s: TcpStream) -> Duration {
    let start = Instant::now();
    let mut b = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(5), s.read(&mut b)).await {
        Ok(Ok(0) | Err(_)) => start.elapsed(),
        other => panic!("not closed: {other:?}"),
    }
}

/// RFC 0030 case 7
#[tokio::test]
#[ignore = "rfc 0030"]
async fn trusted_peer_without_a_header_is_closed() {
    record();
    let (addr, _rx) = listen(config("127.0.0.0/8", ConnsConfig::default()), None).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    closed(s).await;
    assert_eq!(counter("dvarapala_proxy_protocol_total{result=invalid}"), 1);
}

/// RFC 0030 case 8
#[tokio::test]
#[ignore = "rfc 0030"]
async fn half_a_header_times_out() {
    record();
    let (addr, _rx) = listen(config("127.0.0.0/8", ConnsConfig::default()), None).await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(b"PROXY TCP4 192.0.2.").await.unwrap();
    let took = closed(s).await;
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert_eq!(counter("dvarapala_proxy_protocol_total{result=timeout}"), 1);
}

/// RFC 0030 case 9
#[tokio::test]
#[ignore = "rfc 0030"]
async fn untrusted_peer_header_is_not_honored() {
    let (addr, mut rx) = listen(config("192.0.2.0/24", ConnsConfig::default()), None).await;
    let _s = proxied(addr, "192.0.2.10:4000").await;
    let (mut conn, client) = rx.recv().await.unwrap();
    assert_eq!(client.ip().to_string(), "127.0.0.1");
    // the header is left for the HTTP layer, which refuses it
    let mut b = [0u8; 6];
    conn.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"PROXY ");
}

/// The bytes after the header reach the connection, the client is carried
#[tokio::test]
#[ignore = "rfc 0030"]
async fn header_sets_the_client_and_keeps_the_rest() {
    let (addr, mut rx) = listen(config("127.0.0.0/8", ConnsConfig::default()), None).await;
    let mut s = proxied(addr, "192.0.2.10:4000").await;
    s.write_all(b"hello").await.unwrap();
    let (mut conn, client) = rx.recv().await.unwrap();
    assert_eq!(client, "192.0.2.10:4000".parse().unwrap());
    let mut b = [0u8; 5];
    conn.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"hello");
}

/// RFC 0030 case 10
#[tokio::test]
#[ignore = "rfc 0030"]
async fn per_client_cap_keys_on_the_carried_client() {
    record();
    let conns = ConnsConfig {
        max_per_client: 2,
        ..ConnsConfig::default()
    };
    let (addr, mut rx) = listen(config("127.0.0.0/8", conns), None).await;
    let (mut streams, mut conns) = (Vec::new(), Vec::new());
    for c in ["192.0.2.1:1", "192.0.2.2:1", "192.0.2.3:1"] {
        for _ in 0..2 {
            streams.push(proxied(addr, c).await);
            conns.push(rx.recv().await.unwrap().0);
        }
    }
    let third = proxied(addr, "192.0.2.1:2").await;
    closed(third).await;
    assert_eq!(counter("dvarapala_l4_rejected_total{reason=per_client}"), 1);
}

/// RFC 0030 case 12
#[tokio::test]
#[ignore = "rfc 0030"]
async fn carried_clients_never_reach_the_block_sink() {
    record();
    let seen: Arc<Mutex<Vec<Cidr>>> = Arc::default();
    let s = seen.clone();
    let conns = ConnsConfig {
        accept: Some(Limit::new(1, 1).unwrap()),
        ..ConnsConfig::default()
    };
    let sink = BlockSink::new(move |c| s.lock().unwrap().push(c));
    let (addr, mut rx) = listen(config("127.0.0.0/8", conns), Some(sink)).await;
    let _first = proxied(addr, "192.0.2.10:1").await;
    let _c = rx.recv().await.unwrap();
    closed(proxied(addr, "192.0.2.10:2").await).await;
    assert_eq!(counter("dvarapala_l4_rejected_total{reason=rate}"), 1);
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
#[ignore = "rfc 0030"]
fn empty_from_is_refused() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut c = config("127.0.0.0/8", ConnsConfig::default());
        c.proxy_protocol.as_mut().unwrap().from.clear();
        assert!(Listener::new(tcp, c).is_err());
    });
}
