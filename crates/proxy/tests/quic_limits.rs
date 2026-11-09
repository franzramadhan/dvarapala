//! RFC 0036: per-client QUIC connection limits, over a real QUIC endpoint.
//! Clients send from addresses of 127.0.0.0/8.
#![cfg(feature = "http3")]

mod quic;

use std::net::UdpSocket;
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::Limit;
use dvarapala_proxy::quic::Retry;
use http::StatusCode;
use quic::{Proxy, client_at, connect, counter, h3, proxy, record, send, serial};

const PER_CLIENT: &str = "dvarapala_quic_rejected_total{reason=per_client}";
const RATE: &str = "dvarapala_quic_rejected_total{reason=rate}";
const EXCESSIVE_LOAD: u64 = 0x0107;

async fn limited(retry: Retry, max: u32) -> Proxy {
    proxy(
        |c| {
            c.retry = retry;
            c.conns.max_per_client = max;
        },
        None,
    )
    .await
}

/// Waits until `connect` works, for the server to see a close.
async fn connects_soon(p: &Proxy, e: &quinn::Endpoint) -> bool {
    for _ in 0..20 {
        if connect(e, p.addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// case 1
#[tokio::test]
#[ignore = "rfc 0036"]
async fn validated_client_over_the_cap_is_refused_before_the_handshake() {
    record();
    let _s = serial().await;
    let p = limited(Retry::Always, 2).await;
    let e = client_at(&p.ca, "127.0.0.2");
    let before = counter(PER_CLIENT);
    let _a = connect(&e, p.addr).await.unwrap();
    let _b = connect(&e, p.addr).await.unwrap();
    assert!(connect(&e, p.addr).await.is_err());
    assert_eq!(counter(PER_CLIENT) - before, 1);
}

// case 2
#[tokio::test]
#[ignore = "rfc 0036"]
async fn another_address_is_accepted() {
    record();
    let _s = serial().await;
    let p = limited(Retry::Always, 2).await;
    let e = client_at(&p.ca, "127.0.0.2");
    let _a = connect(&e, p.addr).await.unwrap();
    let _b = connect(&e, p.addr).await.unwrap();
    let other = client_at(&p.ca, "127.0.0.3");
    let mut tx = h3(connect(&other, p.addr).await.unwrap()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
}

// case 3
#[tokio::test]
#[ignore = "rfc 0036"]
async fn without_retry_the_third_is_closed_after_its_handshake() {
    record();
    let _s = serial().await;
    let p = limited(Retry::Never, 2).await;
    let e = client_at(&p.ca, "127.0.0.2");
    let before = counter(PER_CLIENT);
    let _a = connect(&e, p.addr).await.unwrap();
    let _b = connect(&e, p.addr).await.unwrap();
    let third = connect(&e, p.addr).await.unwrap();
    let err = tokio::time::timeout(Duration::from_secs(3), third.closed())
        .await
        .expect("closed by the server");
    match err {
        quinn::ConnectionError::ApplicationClosed(c) => {
            assert_eq!(c.error_code.into_inner(), EXCESSIVE_LOAD);
        }
        other => panic!("{other}"),
    }
    assert_eq!(counter(PER_CLIENT) - before, 1);
    assert_eq!(p.upstream.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

// case 4
#[tokio::test]
#[ignore = "rfc 0036"]
async fn a_closed_connection_frees_its_place() {
    record();
    let _s = serial().await;
    let p = limited(Retry::Always, 2).await;
    let e = client_at(&p.ca, "127.0.0.2");
    let a = connect(&e, p.addr).await.unwrap();
    let _b = connect(&e, p.addr).await.unwrap();
    assert!(connect(&e, p.addr).await.is_err());
    a.close(0u32.into(), b"done");
    assert!(connects_soon(&p, &e).await);
}

// case 5
#[tokio::test]
#[ignore = "rfc 0036"]
async fn accept_rate_refuses_the_third_in_a_second() {
    record();
    let _s = serial().await;
    let p = proxy(
        |c| {
            c.retry = Retry::Always;
            c.conns.accept = Some(Limit::new(1, 2).unwrap());
        },
        None,
    )
    .await;
    let e = client_at(&p.ca, "127.0.0.2");
    let before = counter(RATE);
    let _a = connect(&e, p.addr).await.unwrap();
    let _b = connect(&e, p.addr).await.unwrap();
    assert!(connect(&e, p.addr).await.is_err());
    assert_eq!(counter(RATE) - before, 1);
}

// case 7
#[tokio::test]
#[ignore = "rfc 0036"]
async fn both_off_only_the_total_applies() {
    record();
    let _s = serial().await;
    let p = limited(Retry::Always, 0).await;
    let e = client_at(&p.ca, "127.0.0.2");
    let (a, b) = (counter(PER_CLIENT), counter(RATE));
    let mut open = Vec::new();
    for _ in 0..6 {
        open.push(connect(&e, p.addr).await.unwrap());
    }
    assert_eq!((counter(PER_CLIENT), counter(RATE)), (a, b));
}

// case 10
#[tokio::test]
#[ignore = "rfc 0036"]
async fn a_migrated_connection_keeps_the_place_of_its_first_address() {
    record();
    let _s = serial().await;
    let p = limited(Retry::Always, 1).await;
    let e = client_at(&p.ca, "127.0.0.2");
    let a = connect(&e, p.addr).await.unwrap();
    e.rebind(UdpSocket::bind("127.0.0.4:0").unwrap()).unwrap();
    let mut tx = h3(a.clone()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
    // still counted on 127.0.0.2
    let again = client_at(&p.ca, "127.0.0.2");
    assert!(connect(&again, p.addr).await.is_err());
    a.close(0u32.into(), b"done");
    assert!(connects_soon(&p, &again).await);
}
