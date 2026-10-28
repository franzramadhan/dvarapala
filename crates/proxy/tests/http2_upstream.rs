//! RFC 0004 cases 1 to 4, 7 and 13: the upstream protocol and trailers.

mod h2;

use dvarapala_proxy::{Http2Limits, UpstreamProtocol};
use h2::{full, grpc_request, h1, h2, http1_upstream, proxy, upstream};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use tokio::net::TcpListener;

async fn text(res: http::Response<hyper::body::Incoming>) -> String {
    let b = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(b.to_vec()).unwrap()
}

fn post(addr: std::net::SocketAddr, body: &'static str) -> Request<h2::TestBody> {
    Request::post(format!("http://{addr}/version"))
        .header("host", addr.to_string())
        .body(full(body))
        .unwrap()
}

/// RFC 0004 case 1
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn http1_client_reaches_http2_upstream() {
    let up = upstream().await;
    let (addr, _stop) = proxy(
        &format!("http://{up}"),
        UpstreamProtocol::Http2,
        Http2Limits::default(),
    )
    .await;
    let res = h1(addr)
        .await
        .send_request(post(addr, "payload"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(text(res).await, "HTTP/2.0  payload");
}

/// RFC 0004 case 2
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn http2_client_reaches_http2_upstream() {
    let up = upstream().await;
    let (addr, _stop) = proxy(
        &format!("http://{up}"),
        UpstreamProtocol::Http2,
        Http2Limits::default(),
    )
    .await;
    let res = h2(addr)
        .await
        .send_request(post(addr, "payload"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(text(res).await, "HTTP/2.0  payload");
}

/// RFC 0004 case 3
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn http2_to_http1_only_upstream_is_502() {
    let up = http1_upstream().await;
    let (addr, _stop) = proxy(
        &format!("http://{up}"),
        UpstreamProtocol::Http2,
        Http2Limits::default(),
    )
    .await;
    let res = h1(addr).await.send_request(post(addr, "")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
}

/// RFC 0004 case 4
#[tokio::test(flavor = "multi_thread")]
async fn default_downgrades_to_http1() {
    let up = upstream().await;
    let (addr, _stop) = proxy(
        &format!("http://{up}"),
        UpstreamProtocol::default(),
        Http2Limits::default(),
    )
    .await;
    let res = h2(addr)
        .await
        .send_request(post(addr, "payload"))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(text(res).await, "HTTP/1.1  payload");
}

/// RFC 0004 case 7, plus `te: trailers` reaching an HTTP/2 upstream
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn trailers_pass_through() {
    let up = upstream().await;
    let (addr, _stop) = proxy(
        &format!("http://{up}"),
        UpstreamProtocol::Http2,
        Http2Limits::default(),
    )
    .await;
    let mut c = h2(addr).await;
    let req = Request::get(format!("http://{addr}/trailers"))
        .body(full(""))
        .unwrap();
    let res = c.send_request(req).await.unwrap();
    let collected = res.into_body().collect().await.unwrap();
    assert_eq!(collected.trailers().unwrap()["x-trailer"], "yes");
    assert_eq!(collected.to_bytes(), "ok");
    let mut req = post(addr, "");
    req.headers_mut().insert("te", "trailers".parse().unwrap());
    let res = c.send_request(req).await.unwrap();
    assert_eq!(text(res).await, "HTTP/2.0 trailers ");
}

/// RFC 0004 case 13
#[tokio::test(flavor = "multi_thread")]
#[ignore = "rfc 0004"]
async fn grpc_to_dead_upstream_is_unavailable() {
    // bind then drop: nothing listens on this port
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (addr, _stop) = proxy(
        &format!("http://{dead}"),
        UpstreamProtocol::Http2,
        Http2Limits::default(),
    )
    .await;
    let req = grpc_request(addr, "/test.Echo/Unary", full(h2::grpc_frame(b"hi")));
    let res = h2(addr).await.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()["grpc-status"], "14");
    assert_eq!(res.headers()["content-type"], "application/grpc");
}
