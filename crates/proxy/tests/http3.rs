//! RFC 0006: HTTP/3 over QUIC.
#![cfg(feature = "http3")]

mod quic;

use std::num::NonZeroUsize;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Limit, TrustedProxies};
use dvarapala_l7::{RateLimitConfig, RateLimitLayer};
use dvarapala_proxy::quic::Retry;
use dvarapala_proxy::{AltSvc, Http2Limits, ReverseProxy, serve};
use http::StatusCode;
use hyper::body::Incoming;
use quic::{Mode, client, connect, counter, h3, proxy, record, relay, send, serial};
use tokio::net::TcpListener;

const RETRIES: &str = "dvarapala_quic_retries_total{}";
const OK: &str = "dvarapala_quic_handshakes_total{result=ok}";
const REFUSED: &str = "dvarapala_quic_handshakes_total{result=refused}";

// case 1
#[tokio::test]
#[ignore = "rfc 0006"]
async fn get_reaches_the_upstream() {
    let p = proxy(|_| {}, None).await;
    let mut tx = h3(connect(&client(&p.ca, false), p.addr).await.unwrap()).await;
    let (status, _, body) = send(&mut tx, "GET", "/", Bytes::new()).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "len=0"));
    assert_eq!(p.upstream.hits.load(Ordering::SeqCst), 1);
}

// case 2
#[tokio::test]
#[ignore = "rfc 0006"]
async fn post_body_arrives_whole() {
    let p = proxy(|_| {}, None).await;
    let mut tx = h3(connect(&client(&p.ca, false), p.addr).await.unwrap()).await;
    let body = Bytes::from(vec![7u8; 1 << 20]);
    let (status, _, got) = send(&mut tx, "POST", "/upload", body).await;
    assert_eq!((status, got.as_str()), (StatusCode::OK, "len=1048576"));
}

// case 3
#[tokio::test]
#[ignore = "rfc 0006"]
async fn tcp_responses_advertise_h3() {
    let up = quic::upstream().await;
    let p = ReverseProxy::<Incoming>::new(&format!("http://{}", up.addr)).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(serve(
        l,
        Http2Limits::default(),
        AltSvc::new(p, 8443),
        std::future::pending(),
    ));
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut res = String::new();
    s.read_to_string(&mut res).await.unwrap();
    assert!(
        res.to_ascii_lowercase()
            .contains("alt-svc: h3=\":8443\"; ma=86400"),
        "{res}"
    );
}

// case 6
#[tokio::test]
#[ignore = "rfc 0006"]
async fn rate_limit_applies() {
    let limiter = RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(1, 1).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::default(),
        detection: None,
        scoring: None,
        now: Instant::now,
    })
    .unwrap();
    let p = proxy(|_| {}, Some(limiter)).await;
    let mut tx = h3(connect(&client(&p.ca, false), p.addr).await.unwrap()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
    let (status, headers, _) = send(&mut tx, "GET", "/", Bytes::new()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.contains_key("retry-after"));
    assert_eq!(p.upstream.hits.load(Ordering::SeqCst), 1);
}

// case 7
#[tokio::test]
#[ignore = "rfc 0006"]
async fn always_retry_costs_one_round_trip() {
    record();
    let _s = serial().await;
    let p = proxy(|c| c.retry = Retry::Always, None).await;
    let (retries, ok) = (counter(RETRIES), counter(OK));
    let mut tx = h3(connect(&client(&p.ca, false), p.addr).await.unwrap()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
    assert_eq!(counter(RETRIES) - retries, 1);
    assert_eq!(counter(OK) - ok, 1);
}

// case 8
#[tokio::test]
#[ignore = "rfc 0006"]
async fn retry_starts_under_load() {
    record();
    let _s = serial().await;
    let p = proxy(
        |c| {
            c.retry = Retry::UnderLoad;
            c.retry_threshold = 2;
        },
        None,
    )
    .await;
    // two handshakes that never finish: the client never hears back
    for _ in 0..2 {
        let r = relay(p.addr, Mode::Blackhole).await;
        let e = client(&p.ca, false);
        tokio::spawn(async move {
            let _ = connect(&e, r).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let retries = counter(RETRIES);
    connect(&client(&p.ca, false), p.addr).await.unwrap();
    assert_eq!(counter(RETRIES) - retries, 1);
}

// case 9
#[tokio::test]
#[ignore = "rfc 0006"]
async fn token_for_another_address_is_rejected() {
    record();
    let _s = serial().await;
    let p = proxy(|c| c.retry = Retry::Always, None).await;
    let ok = counter(OK);
    let r = relay(p.addr, Mode::Switch).await;
    assert!(connect(&client(&p.ca, false), r).await.is_err());
    assert_eq!(counter(OK) - ok, 0);
}

// case 10
#[tokio::test]
#[ignore = "rfc 0006"]
async fn expired_token_is_rejected() {
    record();
    let _s = serial().await;
    let p = proxy(
        |c| {
            c.retry = Retry::Always;
            c.retry_token_lifetime = Duration::from_secs(1);
        },
        None,
    )
    .await;
    let ok = counter(OK);
    // tokens carry whole seconds: 2.5 s is past a 1 s lifetime either way
    let r = relay(p.addr, Mode::Delay(Duration::from_millis(2500))).await;
    assert!(connect(&client(&p.ca, false), r).await.is_err());
    assert_eq!(counter(OK) - ok, 0);
}

// case 11
#[tokio::test]
#[ignore = "rfc 0006"]
async fn over_max_connections_is_refused() {
    record();
    let _s = serial().await;
    let p = proxy(|c| c.max_connections = 2, None).await;
    let e = client(&p.ca, false);
    let _a = connect(&e, p.addr).await.unwrap();
    let _b = connect(&e, p.addr).await.unwrap();
    let (refused, ok) = (counter(REFUSED), counter(OK));
    let err = connect(&e, p.addr).await.unwrap_err();
    assert!(err.to_lowercase().contains("refused"), "{err}");
    assert_eq!((counter(REFUSED) - refused, counter(OK) - ok), (1, 0));
}

// case 12
#[tokio::test]
#[ignore = "rfc 0006"]
async fn third_stream_waits_for_credit() {
    let p = proxy(|c| c.max_streams = 2, None).await;
    // hold every upstream answer
    let held = p
        .upstream
        .gate
        .forget_permits(tokio::sync::Semaphore::MAX_PERMITS);
    let tx = h3(connect(&client(&p.ca, false), p.addr).await.unwrap()).await;
    let reqs: Vec<_> = (0..3)
        .map(|_| {
            let mut tx = tx.clone();
            tokio::spawn(async move { send(&mut tx, "GET", "/", Bytes::new()).await.0 })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(p.upstream.hits.load(Ordering::SeqCst), 2);
    p.upstream.gate.add_permits(held);
    for r in reqs {
        assert_eq!(r.await.unwrap(), StatusCode::OK);
    }
    assert_eq!(p.upstream.hits.load(Ordering::SeqCst), 3);
}

// case 13
#[tokio::test]
#[ignore = "rfc 0006"]
async fn zero_rtt_is_refused() {
    let p = proxy(|_| {}, None).await;
    let e = client(&p.ca, true);
    // a first connection leaves a session ticket
    let mut tx = h3(connect(&e, p.addr).await.unwrap()).await;
    send(&mut tx, "GET", "/", Bytes::new()).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let connecting = e.connect(p.addr, quic::NAME).unwrap();
    let connecting = match connecting.into_0rtt() {
        Ok(_) => panic!("0-RTT accepted"),
        Err(c) => c,
    };
    let mut tx = h3(connecting.await.unwrap()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
}
