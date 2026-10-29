//! RFC 0006: how the QUIC listener starts, fails handshakes and stops, and
//! how a broken upstream body reaches an HTTP/3 client.
#![cfg(feature = "http3")]

mod quic;

use std::time::Duration;

use bytes::{Buf, Bytes};
use dvarapala_proxy::ReverseProxy;
use dvarapala_proxy::quic::{H3Body, QuicConfig, QuicListener, Retry};
use http::{Request, StatusCode};
use quic::{
    Ca, Mode, NAME, client, client_alpn, connect, counter, h3, listen, listen_task, proxy, record,
    relay, send, serial, tls,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const RETRIES: &str = "dvarapala_quic_retries_total{}";
const FAILED: &str = "dvarapala_quic_handshakes_total{result=failed}";
const TIMEOUT: &str = "dvarapala_quic_handshakes_total{result=timeout}";

#[tokio::test]
async fn bind_errors_name_the_setting() {
    let ca = Ca::new();
    let tls = tls(&ca);
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let e = QuicListener::bind(QuicConfig::new(taken.local_addr().unwrap()), &tls)
        .err()
        .expect("port in use");
    assert!(e.to_string().starts_with("quic.listen: "), "{e}");
    let mut cfg = QuicConfig::new("127.0.0.1:0".parse().unwrap());
    cfg.idle_timeout = Duration::MAX;
    let e = QuicListener::bind(cfg, &tls).err().expect("idle timeout");
    assert!(e.to_string().starts_with("quic tls: "), "{e}");
}

#[tokio::test]
async fn wrong_alpn_fails_the_handshake_without_retry() {
    record();
    let _s = serial().await;
    let p = proxy(|c| c.retry = Retry::Never, None).await;
    let (failed, retries) = (counter(FAILED), counter(RETRIES));
    assert!(
        connect(&client_alpn(&p.ca, false, b"h2"), p.addr)
            .await
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(counter(FAILED) - failed, 1);
    // never retries, whatever the load
    let mut tx = h3(connect(&client(&p.ca, false), p.addr).await.unwrap()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
    assert_eq!(counter(RETRIES) - retries, 0);
}

#[tokio::test]
async fn stalled_handshake_times_out_and_retry_stops() {
    record();
    let _s = serial().await;
    let p = proxy(
        |c| {
            c.retry = Retry::UnderLoad;
            c.retry_threshold = 1;
            c.handshake_timeout = Duration::from_millis(300);
        },
        None,
    )
    .await;
    let timeouts = counter(TIMEOUT);
    let r = relay(p.addr, Mode::Blackhole).await;
    let e = client(&p.ca, false);
    let stalled = tokio::spawn(async move {
        let _ = connect(&e, r).await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // one handshake in progress: a new client is sent a Retry
    let retries = counter(RETRIES);
    connect(&client(&p.ca, false), p.addr).await.unwrap();
    assert_eq!(counter(RETRIES) - retries, 1);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(counter(TIMEOUT) - timeouts >= 1);
    stalled.abort();
    tokio::time::sleep(Duration::from_millis(400)).await;
    // none in progress: no Retry any more
    let retries = counter(RETRIES);
    connect(&client(&p.ca, false), p.addr).await.unwrap();
    assert_eq!(counter(RETRIES) - retries, 0);
}

#[tokio::test]
async fn shutdown_drains_then_returns() {
    let _s = serial().await;
    let up = quic::upstream().await;
    let p = ReverseProxy::<H3Body>::new(&format!("http://{}", up.addr)).unwrap();
    let (addr, ca, stop, task) = listen_task(p, |_| {}, None);
    let conn = connect(&client(&ca, false), addr).await.unwrap();
    let mut tx = h3(conn.clone()).await;
    assert_eq!(
        send(&mut tx, "GET", "/", Bytes::new()).await.0,
        StatusCode::OK
    );
    stop.send(()).unwrap();
    // the open connection is waited for, then the listener returns
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!task.is_finished());
    conn.close(0u32.into(), b"bye");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("drained")
        .unwrap();
}

/// An upstream that answers every request with `answer`, then closes.
async fn raw_upstream(answer: &'static [u8]) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let mut got = Vec::new();
            let mut buf = [0u8; 1024];
            while !got.ends_with(b"\r\n\r\n") {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            let _ = s.write_all(answer).await;
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn upstream_breaking_off_resets_the_stream() {
    let _s = serial().await;
    let up = raw_upstream(b"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort").await;
    let p = ReverseProxy::<H3Body>::new(&up).unwrap();
    let (addr, ca, _stop) = listen(p, |_| {}, None);
    let mut tx = h3(connect(&client(&ca, false), addr).await.unwrap()).await;
    let req = Request::get(format!("https://{NAME}/")).body(()).unwrap();
    let mut s = tx.send_request(req).await.unwrap();
    s.finish().await.unwrap();
    // The reset can arrive before the headers do: either way the client
    // never sees a clean end of a short body.
    let Ok(r) = s.recv_response().await else {
        return;
    };
    assert_eq!(r.status(), StatusCode::OK);
    let mut got = Vec::new();
    let end = loop {
        match s.recv_data().await {
            Ok(Some(mut c)) => got.extend_from_slice(&c.copy_to_bytes(c.remaining())),
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    assert!(end.is_err(), "finished after {} bytes", got.len());
    assert!(got.len() < 100);
}

#[tokio::test]
async fn upstream_trailers_reach_the_client() {
    let _s = serial().await;
    let up = raw_upstream(
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: x-sum\r\n\r\n\
          5\r\nhello\r\n0\r\nx-sum: 42\r\n\r\n",
    )
    .await;
    let p = ReverseProxy::<H3Body>::new(&up).unwrap();
    let (addr, ca, _stop) = listen(p, |_| {}, None);
    let mut tx = h3(connect(&client(&ca, false), addr).await.unwrap()).await;
    let req = Request::get(format!("https://{NAME}/"))
        .header("te", "trailers")
        .body(())
        .unwrap();
    let mut s = tx.send_request(req).await.unwrap();
    s.finish().await.unwrap();
    assert_eq!(s.recv_response().await.unwrap().status(), StatusCode::OK);
    let mut got = Vec::new();
    while let Some(mut c) = s.recv_data().await.unwrap() {
        got.extend_from_slice(&c.copy_to_bytes(c.remaining()));
    }
    assert_eq!(got, b"hello");
    let trailers = s.recv_trailers().await.unwrap().expect("trailers");
    assert_eq!(trailers["x-sum"], "42");
}
