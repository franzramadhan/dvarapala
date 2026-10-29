//! RFC 0017: agent errors, reloads, HTTP versions and gRPC answers of the
//! WAF layer against the fake agent.
#![cfg(feature = "waf")]

#[allow(dead_code)]
mod fake_agent;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::TrustedProxies;
use dvarapala_l7::{Endpoint, PeerAddr, WafBody, WafConfig, WafLayer};
use fake_agent::{Arg, Behavior, Reply, spawn};
use http::{Request, Response, StatusCode, Version};
use http_body::{Body, Frame};
use http_body_util::Full;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tower::{Layer, Service, ServiceExt, service_fn};

fn metrics() -> &'static PrometheusHandle {
    static H: OnceLock<PrometheusHandle> = OnceLock::new();
    H.get_or_init(|| PrometheusBuilder::new().install_recorder().unwrap())
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn counter(series: &str) -> u64 {
    metrics()
        .render()
        .lines()
        .find(|l| l.starts_with(series))
        .and_then(|l| l.rsplit(' ').next())
        .map_or(0, |v| v.parse().unwrap())
}

fn reason(r: &str) -> u64 {
    counter(&format!("dvarapala_waf_errors_total{{reason=\"{r}\"}}"))
}

fn config(endpoint: Endpoint) -> WafConfig {
    WafConfig {
        enforce: true,
        endpoint,
        app: "app".into(),
        timeout: Duration::from_millis(500),
        fail_open: false,
        max_body: 1024,
        reject_over_limit: true,
        max_concurrent: 4,
        trusted: TrustedProxies::default(),
        listen: "192.0.2.1:443".parse().unwrap(),
    }
}

fn tcp(a: SocketAddr) -> WafConfig {
    config(Endpoint::Tcp(a.to_string()))
}

/// The upstream answers `200` without reading the body.
fn upstream<B: Send + 'static>() -> impl Service<
    Request<WafBody<B>>,
    Response = Response<Full<Bytes>>,
    Error = Infallible,
    Future = impl Send,
> + Clone
+ Send
+ 'static {
    service_fn(|_: Request<WafBody<B>>| async {
        Ok::<_, Infallible>(Response::new(Full::default()))
    })
}

fn request<B>(body: B) -> Request<B> {
    let mut r = Request::post("/a?b=1")
        .header("host", "app.example")
        .body(body)
        .unwrap();
    r.extensions_mut()
        .insert(PeerAddr("192.0.2.7:50000".parse().unwrap()));
    r
}

fn empty() -> Request<Full<Bytes>> {
    request(Full::default())
}

async fn send<S, B>(svc: &mut S, req: Request<B>) -> Response<Full<Bytes>>
where
    S: Service<Request<B>, Response = Response<Full<Bytes>>, Error = Infallible>,
{
    svc.ready().await.unwrap().call(req).await.unwrap()
}

async fn status<S>(svc: &mut S) -> StatusCode
where
    S: Service<Request<Full<Bytes>>, Response = Response<Full<Bytes>>, Error = Infallible>,
{
    send(svc, empty()).await.status()
}

#[tokio::test]
async fn agent_errors_fail_closed_with_their_reason() {
    let _g = SERIAL.lock().await;
    metrics();
    for (reply, why) in [
        (Reply::OldHello, "protocol"),
        (Reply::Disconnect, "disconnect"),
        (Reply::WrongStream, "protocol"),
        (Reply::Oversize, "protocol"),
    ] {
        let (addr, _) = spawn(Behavior::reply(reply.clone())).await;
        let mut svc = WafLayer::new(Some(tcp(addr))).layer(upstream());
        let before = reason(why);
        assert_eq!(
            status(&mut svc).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{reply:?}"
        );
        assert_eq!(reason(why), before + 1, "{reply:?}");
    }
    let gone = std::env::temp_dir().join("dvarapala-no-such-dir/agent.sock");
    let mut svc = WafLayer::new(Some(config(Endpoint::Unix(gone)))).layer(upstream());
    let before = reason("connect");
    assert_eq!(status(&mut svc).await, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(reason("connect"), before + 1);
}

#[tokio::test]
async fn closed_idle_connection_is_dialed_again() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Once)).await;
    let mut svc = WafLayer::new(Some(tcp(addr))).layer(upstream());
    for _ in 0..3 {
        assert_eq!(status(&mut svc).await, StatusCode::OK);
    }
    assert_eq!(seen.notifies(), 3);
    assert_eq!(seen.connections.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn reload_keeps_the_pool_unless_its_keys_change() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Pass)).await;
    let layer = WafLayer::new(Some(tcp(addr)));
    let mut svc = layer.layer(upstream());
    assert_eq!(status(&mut svc).await, StatusCode::OK);
    layer.reload(Some(WafConfig {
        app: "other".into(),
        ..tcp(addr)
    }));
    assert_eq!(status(&mut svc).await, StatusCode::OK);
    assert_eq!(seen.last()[0].1, Arg::Bytes(b"other".to_vec()));
    assert_eq!(seen.connections.load(Ordering::SeqCst), 1);
    layer.reload(Some(WafConfig {
        max_body: 2048,
        ..tcp(addr)
    }));
    assert_eq!(status(&mut svc).await, StatusCode::OK);
    assert_eq!(seen.connections.load(Ordering::SeqCst), 2);
    // no config: passes untouched
    layer.reload(None);
    assert_eq!(status(&mut svc).await, StatusCode::OK);
    assert_eq!(seen.notifies(), 3);
}

#[tokio::test]
async fn http_version_reaches_the_agent() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Pass)).await;
    let mut svc = WafLayer::new(Some(tcp(addr))).layer(upstream());
    for (v, name) in [
        (Version::HTTP_10, "1.0"),
        (Version::HTTP_2, "2.0"),
        (Version::HTTP_3, "3.0"),
    ] {
        let mut r = empty();
        *r.version_mut() = v;
        assert_eq!(send(&mut svc, r).await.status(), StatusCode::OK);
        let version = seen.last().into_iter().find(|(k, _)| k == "version");
        assert_eq!(version.unwrap().1, Arg::Bytes(name.into()));
    }
}

#[tokio::test]
async fn grpc_gets_grpc_answers() {
    let _g = SERIAL.lock().await;
    metrics();
    let grpc = || {
        let mut r = empty();
        r.headers_mut()
            .insert("content-type", "application/grpc".parse().unwrap());
        r
    };
    let (deny, _) = spawn(Behavior::reply(Reply::Deny(403, 1))).await;
    let (bye, _) = spawn(Behavior::reply(Reply::Disconnect)).await;
    for (addr, code) in [(deny, "7"), (bye, "14")] {
        let mut svc = WafLayer::new(Some(tcp(addr))).layer(upstream());
        let res = send(&mut svc, grpc()).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()["grpc-status"], code);
    }
}

/// A body whose first frame is an error.
struct Broken;

impl Body for Broken {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        Poll::Ready(Some(Err(std::io::ErrorKind::ConnectionReset.into())))
    }
}

#[tokio::test]
async fn broken_body_is_a_bad_request() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Pass)).await;
    let mut svc = WafLayer::new(Some(tcp(addr))).layer(upstream());
    let res = send(&mut svc, request(Broken)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(seen.notifies(), 0);
}

#[tokio::test]
async fn rule_labels_are_bounded() {
    let _g = SERIAL.lock().await;
    metrics();
    let other = "dvarapala_waf_rule_matches_total{rule=\"other\"}";
    let before = counter(other);
    // 256 labels at most, whatever the other tests counted
    for rule in 0..260 {
        let (addr, _) = spawn(Behavior::reply(Reply::Deny(403, 900_000 + rule))).await;
        let mut svc = WafLayer::new(Some(tcp(addr))).layer(upstream());
        assert_eq!(status(&mut svc).await, StatusCode::FORBIDDEN);
    }
    assert!(counter(other) >= before + 4);
}
