//! RFC 0005 cases 2, 3, 9, 10 and 11: how tunnels end. One test per `end`
//! label, so the counters of parallel tests do not mix.

mod ws;

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use dvarapala_proxy::UpgradeConfig;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;
use ws::{connect, counter, echo, eventually, proxy, record, upstream, within};

fn ended(how: &str) -> u64 {
    counter(&format!(
        "dvarapala_tunnels_total{{protocol=websocket,end={how}}}"
    ))
}

/// RFC 0005 case 2: the client's side of the connection ends first.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn client_close() {
    record();
    let (up, seen) = upstream().await;
    let (addr, _stop) = proxy(up, UpgradeConfig::default(), None).await;
    let mut ws = connect(addr, "/echo").await.unwrap();
    echo(&mut ws, Message::text("hi")).await;
    ws.close(None).await.unwrap();
    drop(ws);
    eventually("upstream saw the close", || {
        seen.closes.load(Ordering::SeqCst) == 1
    })
    .await;
    eventually("end=client counted", || ended("client") == 1).await;
}

/// RFC 0005 case 3
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn upstream_close() {
    record();
    let (up, _) = upstream().await;
    let (addr, _stop) = proxy(up, UpgradeConfig::default(), None).await;
    let mut ws = connect(addr, "/close").await.unwrap();
    let got = within("client sees the close", ws.next()).await;
    assert!(matches!(got, Some(Ok(Message::Close(_)))), "{got:?}");
    eventually("end=upstream counted", || ended("upstream") == 1).await;
}

/// RFC 0005 case 9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn idle_tunnel_is_closed() {
    record();
    let (up, _) = upstream().await;
    let idle = UpgradeConfig {
        idle_timeout: Duration::from_millis(200),
        ..UpgradeConfig::default()
    };
    let (addr, _stop) = proxy(up, idle, None).await;
    let mut ws = connect(addr, "/echo").await.unwrap();
    let start = Instant::now();
    // the proxy closes the sockets without a close frame: an error or the end
    let got = within("idle close", ws.next()).await;
    assert!(!matches!(got, Some(Ok(Message::Text(_)))), "{got:?}");
    assert!(start.elapsed() >= Duration::from_millis(200));
    eventually("end=idle counted", || ended("idle") == 1).await;
}

/// RFC 0005 case 10: steady traffic does not keep a tunnel past its lifetime.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn lifetime_closes_a_busy_tunnel() {
    record();
    let (up, _) = upstream().await;
    let short = UpgradeConfig {
        max_lifetime: Some(Duration::from_secs(1)),
        ..UpgradeConfig::default()
    };
    let (addr, _stop) = proxy(up, short, None).await;
    let mut ws = connect(addr, "/echo").await.unwrap();
    let start = Instant::now();
    within("lifetime close", async {
        loop {
            if ws.send(Message::text("tick")).await.is_err() {
                return;
            }
            match ws.next().await {
                Some(Ok(Message::Text(_))) => {}
                _ => return,
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let t = start.elapsed();
    assert!(
        t >= Duration::from_secs(1) && t < Duration::from_secs(3),
        "{t:?}"
    );
    eventually("end=lifetime counted", || ended("lifetime") == 1).await;
}

/// RFC 0005 case 11
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0005"]
async fn shutdown_closes_open_tunnels() {
    record();
    let (up, _) = upstream().await;
    let (addr, stop) = proxy(up, UpgradeConfig::default(), None).await;
    let mut ws = connect(addr, "/echo").await.unwrap();
    echo(&mut ws, Message::text("hi")).await;
    drop(stop);
    // well before the 30 s drain timeout
    let got = within("shutdown close", ws.next()).await;
    assert!(!matches!(got, Some(Ok(Message::Text(_)))), "{got:?}");
    eventually("end=shutdown counted", || ended("shutdown") == 1).await;
}
