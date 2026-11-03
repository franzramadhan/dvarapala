//! RFC 0017: size limits of the WAF layer against the fake agent. A
//! request over the agent's frame size is a size limit, not an agent
//! error, and gRPC-typed bodies are inspected unless they are an
//! open-ended HTTP/2 or HTTP/3 stream.
#![cfg(feature = "waf")]

#[allow(dead_code)]
mod fake_agent;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dvarapala_engine::TrustedProxies;
use dvarapala_l7::{Endpoint, PeerAddr, WafBody, WafConfig, WafLayer};
use fake_agent::{Arg, Behavior, Reply, Seen, spawn};
use http::{Request, Response, StatusCode, Version};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tower::{Layer, Service, ServiceExt, service_fn};

/// A body in chunks; `exact` announces its length like `Content-Length`.
struct Chunks {
    chunks: VecDeque<Bytes>,
    exact: bool,
}

impl Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        Poll::Ready(self.chunks.pop_front().map(|c| Ok(Frame::data(c))))
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        let n = self.chunks.iter().map(|c| c.len() as u64).sum();
        if self.exact {
            SizeHint::with_exact(n)
        } else {
            SizeHint::new()
        }
    }
}

fn body(len: usize, exact: bool) -> Chunks {
    let all = Bytes::from(vec![b'a'; len]);
    Chunks {
        chunks: all.chunks(512).map(Bytes::copy_from_slice).collect(),
        exact,
    }
}

fn request(uri: &str, b: Chunks) -> Request<Chunks> {
    let mut r = Request::post(uri)
        .header("host", "app.example")
        .body(b)
        .unwrap();
    r.extensions_mut()
        .insert(PeerAddr("192.0.2.7:50000".parse().unwrap()));
    r
}

fn grpc(version: Version, b: Chunks) -> Request<Chunks> {
    let mut r = request("/pkg.Service/Call", b);
    *r.version_mut() = version;
    r.headers_mut()
        .insert("content-type", "application/grpc".parse().unwrap());
    r
}

fn config(agent: SocketAddr, enforce: bool) -> WafConfig {
    WafConfig {
        enforce,
        endpoint: Endpoint::Tcp(agent.to_string()),
        app: "app".into(),
        timeout: Duration::from_millis(500),
        fail_open: true,
        max_body: 1024,
        reject_over_limit: true,
        max_concurrent: 4,
        trusted: TrustedProxies::default(),
        listen: "192.0.2.1:443".parse().unwrap(),
    }
}

type Got = Arc<Mutex<Vec<Bytes>>>;

/// The upstream: records each body, answers `200`.
fn upstream(
    got: Got,
) -> impl Service<
    Request<WafBody<Chunks>>,
    Response = Response<Full<Bytes>>,
    Error = Infallible,
    Future = impl Send,
> + Clone
+ Send
+ 'static {
    service_fn(move |req: Request<WafBody<Chunks>>| {
        let got = got.clone();
        async move {
            let b = req.into_body().collect().await.unwrap().to_bytes();
            got.lock().unwrap().push(b);
            Ok::<_, Infallible>(Response::new(Full::default()))
        }
    })
}

async fn send<S>(svc: &mut S, req: Request<Chunks>) -> Response<Full<Bytes>>
where
    S: Service<Request<Chunks>, Response = Response<Full<Bytes>>, Error = Infallible>,
{
    svc.ready().await.unwrap().call(req).await.unwrap()
}

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

fn verdict(v: &str) -> u64 {
    counter(&format!("dvarapala_waf_requests_total{{verdict=\"{v}\"}}"))
}

fn errors() -> u64 {
    ["connect", "timeout", "protocol", "disconnect"]
        .iter()
        .map(|r| counter(&format!("dvarapala_waf_errors_total{{reason=\"{r}\"}}")))
        .sum()
}

fn sent_body(seen: &Seen) -> Arg {
    seen.last()
        .into_iter()
        .find(|(k, _)| k == "body")
        .unwrap()
        .1
}

#[tokio::test]
async fn head_over_the_frame_is_refused_in_enforce_whatever_on_error() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Deny(403, 942_100))).await;
    let got = Got::default();
    // the frame is max_body + 16 KiB: a 20 KiB query does not fit
    let uri = format!("/search?q={}", "a".repeat(20 * 1024));
    let (head, error) = (verdict("head_over_limit"), verdict("error"));
    let errs = errors();
    let mut svc = WafLayer::new(Some(config(addr, true))).layer(upstream(got.clone()));
    let res = send(&mut svc, request(&uri, body(0, true))).await;
    assert_eq!(res.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(seen.notifies(), 0);
    assert_eq!(verdict("head_over_limit"), head + 1);
    assert_eq!((verdict("error"), errors()), (error, errs));
    // observe forwards
    let mut svc = WafLayer::new(Some(config(addr, false))).layer(upstream(got.clone()));
    let res = send(&mut svc, request(&uri, body(0, true))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(got.lock().unwrap().len(), 1);
    assert_eq!(verdict("head_over_limit"), head + 2);
}

#[tokio::test]
async fn smaller_agreed_frame_applies_the_body_limit_action() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior {
        max_frame: Some(1024),
        ..Behavior::reply(Reply::Pass)
    })
    .await;
    let got = Got::default();
    let mut c = config(addr, true);
    c.max_body = 16 * 1024;
    let (over, error) = (verdict("body_over_limit"), verdict("error"));
    let errs = errors();
    // a 2 KiB body is under max_body but not under the 1 KiB the agent agreed to
    let mut svc = WafLayer::new(Some(c.clone())).layer(upstream(got.clone()));
    let res = send(&mut svc, request("/", body(2048, true))).await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(seen.notifies(), 0);
    assert_eq!(verdict("body_over_limit"), over + 1);
    // `pass`: the agent gets the head without the body, the upstream all of it
    c.reject_over_limit = false;
    let mut svc = WafLayer::new(Some(c.clone())).layer(upstream(got.clone()));
    let res = send(&mut svc, request("/", body(2048, true))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(seen.notifies(), 1);
    assert_eq!(sent_body(&seen), Arg::Bytes(vec![]));
    assert_eq!(got.lock().unwrap().last().unwrap().len(), 2048);
    assert_eq!(verdict("body_over_limit"), over + 2);
    // a head over the 1 KiB frame: refused, not an agent error
    let mut r = request("/", body(0, true));
    r.headers_mut()
        .insert("x-pad", "a".repeat(2048).parse().unwrap());
    assert_eq!(
        send(&mut svc, r).await.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert_eq!((verdict("error"), errors()), (error, errs));
}

#[tokio::test]
async fn grpc_typed_body_on_http1_is_inspected() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Pass)).await;
    let got = Got::default();
    let mut c = config(addr, true);
    c.max_body = 16 * 1024;
    let mut svc = WafLayer::new(Some(c)).layer(upstream(got.clone()));
    let res = send(&mut svc, grpc(Version::HTTP_11, body(2048, false))).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(sent_body(&seen), Arg::Bytes(vec![b'a'; 2048]));
    assert_eq!(got.lock().unwrap().last().unwrap().len(), 2048);
}

#[tokio::test]
async fn grpc_typed_body_on_http1_over_max_body_is_rejected() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Pass)).await;
    let got = Got::default();
    let mut svc = WafLayer::new(Some(config(addr, true))).layer(upstream(got.clone()));
    let over = verdict("body_over_limit");
    for exact in [true, false] {
        let res = send(&mut svc, grpc(Version::HTTP_11, body(2048, exact))).await;
        // refused in gRPC form, like every local answer to a gRPC type
        assert_eq!(res.headers()["grpc-status"], "7");
    }
    assert_eq!(seen.notifies(), 0);
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(verdict("body_over_limit"), over + 2);
}

#[tokio::test]
async fn grpc_streams_on_http2_skip_the_body_unless_its_length_is_known() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior::reply(Reply::Pass)).await;
    let got = Got::default();
    let mut svc = WafLayer::new(Some(config(addr, true))).layer(upstream(got.clone()));
    for v in [Version::HTTP_2, Version::HTTP_3] {
        // a known length within max_body: buffered and sent
        let skipped = verdict("skipped");
        let res = send(&mut svc, grpc(v, body(512, true))).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(sent_body(&seen), Arg::Bytes(vec![b'a'; 512]));
        assert_eq!(verdict("skipped"), skipped);
        // an open-ended stream: headers only, counted
        let res = send(&mut svc, grpc(v, body(4096, false))).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(sent_body(&seen), Arg::Bytes(vec![]));
        assert_eq!(got.lock().unwrap().last().unwrap().len(), 4096);
        assert_eq!(verdict("skipped"), skipped + 1);
    }
    assert_eq!(seen.notifies(), 4);
}
