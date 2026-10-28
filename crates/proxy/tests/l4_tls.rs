//! RFC 0009 case 12: a refused connection never reaches the TLS handshake.
#![cfg(feature = "tls")]

#[path = "counters/mod.rs"]
mod counters;
mod support;

use std::time::Duration;

use counters::{counter, record};
use dvarapala_engine::ConnsConfig;
use dvarapala_l4::{L4Config, Listener};
use dvarapala_proxy::tls::{Tls, TlsConfig};
use dvarapala_proxy::{Http2Limits, ReverseProxy, serve_tls};
use hyper::body::Incoming;
use support::{Ca, NAME, client_config, connect, tempdir, upstream, write};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread")]
async fn second_connect_closed_before_handshake() {
    record();
    let ca = Ca::new();
    let (cert_pem, key_pem) = ca.leaf(&[NAME]);
    let dir = tempdir();
    let tls = Tls::new(TlsConfig {
        cert: write(&dir, "cert.pem", &cert_pem),
        key: write(&dir, "key.pem", &key_pem),
        handshake_timeout: Duration::from_secs(10),
        max_handshakes: 1024,
    })
    .unwrap();
    let up = upstream("ok").await;
    let p = ReverseProxy::<Incoming>::new(&format!("http://{up}")).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let l4 = L4Config {
        conns: ConnsConfig {
            max_per_client: 1,
            ..ConnsConfig::default()
        },
        ..L4Config::default()
    };
    let l = Listener::new(tcp, l4).unwrap();
    tokio::spawn(serve_tls(
        l,
        tls,
        Http2Limits::default(),
        p,
        std::future::pending(),
    ));
    let _first = connect(addr, client_config(&ca.pem, &[b"http/1.1"]))
        .await
        .unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    let mut b = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), second.read(&mut b)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))), "{read:?}");
    assert_eq!(counter("dvarapala_l4_rejected_total{reason=per_client}"), 1);
    for result in ["ok", "rejected", "failed", "timeout"] {
        // only the first connection's handshake
        let want = u64::from(result == "ok");
        let key = format!("dvarapala_tls_handshakes_total{{result={result}}}");
        assert_eq!(counter(&key), want, "{key}");
    }
}
