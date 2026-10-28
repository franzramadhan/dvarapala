//! RFC 0005 cases 1, 4, 6, 7, 8 and 12: WebSocket upgrades through the
//! proxy, and the limits in front of them.

mod ws;

use std::sync::atomic::Ordering;

use bytes::Bytes;
use dvarapala_proxy::UpgradeConfig;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use ws::{connect, counter, echo, eventually, limiter, proxy, record, refused, upstream};

/// RFC 0005 case 1
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn text_and_binary_echo() {
    record();
    let (up, _) = upstream().await;
    let (addr, _stop) = proxy(up, UpgradeConfig::default(), None).await;
    let mut ws = connect(addr, "/echo").await.unwrap();
    echo(&mut ws, Message::text("hello")).await;
    echo(&mut ws, Message::binary(vec![0u8, 1, 2, 255])).await;
}

/// RFC 0005 case 4
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn refused_upgrade_is_a_normal_response() {
    record();
    let (up, _) = upstream().await;
    let (addr, _stop) = proxy(up, UpgradeConfig::default(), None).await;
    assert_eq!(
        refused(connect(addr, "/forbidden").await),
        StatusCode::FORBIDDEN
    );
    // the slot went back: the proxy still upgrades with max_tunnels = 1
    let one = UpgradeConfig {
        max_tunnels: 1,
        ..UpgradeConfig::default()
    };
    let (addr, _stop) = proxy(up, one, None).await;
    assert_eq!(
        refused(connect(addr, "/forbidden").await),
        StatusCode::FORBIDDEN
    );
    connect(addr, "/echo").await.unwrap();
}

/// RFC 0005 case 6
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn empty_protocols_strip_the_upgrade() {
    record();
    let (up, seen) = upstream().await;
    let off = UpgradeConfig {
        protocols: Vec::new(),
        ..UpgradeConfig::default()
    };
    let (addr, _stop) = proxy(up, off, None).await;
    let s = TcpStream::connect(addr).await.unwrap();
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::get(format!("http://{addr}/echo"))
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA==")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = tx.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "none");
    assert_eq!(seen.hits.load(Ordering::SeqCst), 1);
}

/// RFC 0005 case 7
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn rate_limited_upgrade_never_reaches_the_upstream() {
    record();
    let (up, seen) = upstream().await;
    let (addr, _stop) = proxy(up, UpgradeConfig::default(), Some(limiter())).await;
    let _first = connect(addr, "/echo").await.unwrap();
    assert_eq!(
        refused(connect(addr, "/echo").await),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(seen.hits.load(Ordering::SeqCst), 1);
}

/// RFC 0005 case 8
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn third_tunnel_over_the_limit_is_503() {
    record();
    let (up, seen) = upstream().await;
    let two = UpgradeConfig {
        max_tunnels: 2,
        ..UpgradeConfig::default()
    };
    let (addr, _stop) = proxy(up, two, None).await;
    let _a = connect(addr, "/echo").await.unwrap();
    let _b = connect(addr, "/echo").await.unwrap();
    assert_eq!(
        refused(connect(addr, "/echo").await),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(seen.hits.load(Ordering::SeqCst), 2);
    assert_eq!(counter("dvarapala_tunnels_rejected_total{}"), 1);
}

/// RFC 0005 case 12
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn megabyte_each_way_is_counted() {
    record();
    let (up, _) = upstream().await;
    let (addr, _stop) = proxy(up, UpgradeConfig::default(), None).await;
    let bytes_in = || counter("dvarapala_tunnel_bytes_total{direction=in}");
    let bytes_out = || counter("dvarapala_tunnel_bytes_total{direction=out}");
    let (in0, out0) = (bytes_in(), bytes_out());
    let mut ws = connect(addr, "/echo").await.unwrap();
    echo(&mut ws, Message::binary(vec![7u8; 1 << 20])).await;
    drop(ws);
    eventually("1 MB counted each way", || {
        bytes_in() >= in0 + (1 << 20) && bytes_out() >= out0 + (1 << 20)
    })
    .await;
}
