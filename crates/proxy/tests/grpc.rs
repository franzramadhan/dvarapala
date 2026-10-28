//! RFC 0004 cases 8 to 10: gRPC calls through the proxy. The framing is
//! written by hand (5-byte prefix), so no gRPC library is needed.

mod h2;

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dvarapala_proxy::{Http2Limits, UpstreamProtocol};
use h2::{chan, full, grpc_frame, grpc_messages, grpc_request, h2, proxy, upstream};
use http_body_util::BodyExt;
use hyper::body::Frame;

async fn grpc_proxy() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let up = upstream().await;
    proxy(
        &format!("http://{up}"),
        UpstreamProtocol::Http2,
        Http2Limits::default(),
    )
    .await
}

/// RFC 0004 case 8
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn unary_call() {
    let (addr, _stop) = grpc_proxy().await;
    let req = grpc_request(addr, "/test.Echo/Unary", full(grpc_frame(b"hello")));
    let res = h2(addr).await.send_request(req).await.unwrap();
    assert_eq!(res.status(), 200);
    let c = res.into_body().collect().await.unwrap();
    assert_eq!(c.trailers().unwrap()["grpc-status"], "0");
    let mut buf = BytesMut::from(&c.to_bytes()[..]);
    assert_eq!(grpc_messages(&mut buf), [Bytes::from_static(b"hello")]);
}

/// RFC 0004 case 9
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn server_streaming_keeps_order() {
    let (addr, _stop) = grpc_proxy().await;
    let req = grpc_request(addr, "/test.Echo/Stream", full(grpc_frame(b"")));
    let res = h2(addr).await.send_request(req).await.unwrap();
    let c = res.into_body().collect().await.unwrap();
    assert_eq!(c.trailers().unwrap()["grpc-status"], "0");
    let mut buf = BytesMut::from(&c.to_bytes()[..]);
    let got = grpc_messages(&mut buf);
    let want: Vec<Bytes> = (0..1000).map(|i| Bytes::from(i.to_string())).collect();
    assert_eq!(got, want);
}

/// RFC 0004 case 10: each message is echoed before the next is sent, so
/// the proxy must stream both directions at once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn bidirectional_stream() {
    let (addr, _stop) = grpc_proxy().await;
    let (tx, body) = chan();
    let res = h2(addr)
        .await
        .send_request(grpc_request(addr, "/test.Echo/Bidi", body))
        .await
        .unwrap();
    let mut res = res.into_body();
    let mut buf = BytesMut::new();
    for i in 0..10 {
        let msg = format!("m{i}");
        tx.send(Frame::data(grpc_frame(msg.as_bytes())))
            .await
            .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(m) = grpc_messages(&mut buf).pop() {
                    return m;
                }
                let f = res.frame().await.unwrap().unwrap();
                buf.extend_from_slice(&f.into_data().unwrap());
            }
        })
        .await
        .expect("echo did not come back while the request was open");
        assert_eq!(echoed, msg);
    }
    drop(tx);
    let mut trailers = None;
    while let Some(f) = res.frame().await {
        if let Ok(t) = f.unwrap().into_trailers() {
            trailers = Some(t);
        }
    }
    assert_eq!(trailers.unwrap()["grpc-status"], "0");
}
