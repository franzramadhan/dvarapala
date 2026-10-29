//! RFC 0017 cases 3 to 10: the WAF layer against a fake agent.
#![cfg(feature = "waf")]

mod fake_agent;

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Cidr, Limit, TrustedProxies};
use dvarapala_l7::{
    Endpoint, Matcher, PathMatch, PeerAddr, RateLimitConfig, RateLimitLayer, RouteConfig, RouteKey,
    WafBody, WafConfig, WafLayer,
};
use fake_agent::{Arg, Behavior, Reply, Seen, spawn};
use http::{Request, Response, StatusCode};
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

fn request(path: &str, b: Chunks) -> Request<Chunks> {
    let mut r = Request::builder()
        .method(if b.chunks.is_empty() { "GET" } else { "POST" })
        .uri(path)
        .header("host", "app.example")
        .body(b)
        .unwrap();
    r.extensions_mut()
        .insert(PeerAddr("192.0.2.7:50000".parse().unwrap()));
    r
}

fn config(agent: SocketAddr, enforce: bool) -> WafConfig {
    WafConfig {
        enforce,
        endpoint: Endpoint::Tcp(agent.to_string()),
        app: "app".into(),
        timeout: Duration::from_millis(500),
        fail_open: false,
        max_body: 16 * 1024,
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

async fn send<S>(svc: &mut S, req: Request<Chunks>) -> StatusCode
where
    S: Service<Request<Chunks>, Response = Response<Full<Bytes>>, Error = Infallible>,
{
    svc.ready().await.unwrap().call(req).await.unwrap().status()
}

/// One recorder for the process; the tests run one at a time and read
/// deltas.
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

fn reason(r: &str) -> u64 {
    counter(&format!("dvarapala_waf_errors_total{{reason=\"{r}\"}}"))
}

async fn agent(reply: Reply) -> (SocketAddr, Seen) {
    spawn(Behavior::reply(reply)).await
}

// RFC 0017 case 3
#[tokio::test]
async fn hello_frame_size_and_refusal() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior {
        max_frame: Some(1024),
        ..Behavior::reply(Reply::Pass)
    })
    .await;
    let got = Got::default();
    let mut svc = WafLayer::new(Some(config(addr, true))).layer(upstream(got.clone()));
    assert_eq!(
        send(&mut svc, request("/", body(0, true))).await,
        StatusCode::OK
    );
    assert_eq!(*seen.frame_sizes.lock().unwrap(), [1024]);
    // a 2 KiB body does not fit the 1 KiB the agent agreed to
    let protocol = reason("protocol");
    assert_eq!(
        send(&mut svc, request("/", body(2048, true))).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(reason("protocol"), protocol + 1);

    let (addr, _) = agent(Reply::RefuseHello).await;
    let mut svc = WafLayer::new(Some(config(addr, true))).layer(upstream(got));
    let disconnect = reason("disconnect");
    assert_eq!(
        send(&mut svc, request("/", body(0, true))).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(reason("disconnect"), disconnect + 1);
}

// RFC 0017 case 4
#[tokio::test]
async fn observe_forwards_and_counts() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = agent(Reply::Deny(403, 942_100)).await;
    let got = Got::default();
    let mut svc = WafLayer::new(Some(config(addr, false))).layer(upstream(got.clone()));
    let would = verdict("would_block");
    assert_eq!(
        send(&mut svc, request("/?q=1", body(0, true))).await,
        StatusCode::OK
    );
    assert_eq!(verdict("would_block"), would + 1);
    assert_eq!((seen.notifies(), got.lock().unwrap().len()), (1, 1));
}

// RFC 0017 case 5
#[tokio::test]
async fn enforce_blocks_and_sends_the_request() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = agent(Reply::Deny(406, 942_100)).await;
    let got = Got::default();
    let mut c = config(addr, true);
    c.trusted = TrustedProxies::new(vec!["192.0.2.7/32".parse::<Cidr>().unwrap()]);
    let mut svc = WafLayer::new(Some(c)).layer(upstream(got.clone()));
    let mut req = request("/login?next=%2F", body(4096, false));
    req.headers_mut()
        .insert("x-forwarded-for", "198.51.100.9".parse().unwrap());
    let rule = counter("dvarapala_waf_rule_matches_total{rule=\"942100\"}");
    assert_eq!(send(&mut svc, req).await, StatusCode::NOT_ACCEPTABLE);
    assert!(got.lock().unwrap().is_empty());
    assert_eq!(
        counter("dvarapala_waf_rule_matches_total{rule=\"942100\"}"),
        rule + 1
    );
    let args = seen.last();
    let names: Vec<&str> = args.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        [
            "app",
            "src-ip",
            "src-port",
            "dst-ip",
            "dst-port",
            "method",
            "path",
            "query",
            "version",
            "headers",
            "body",
            "exportRuleIDs"
        ]
    );
    let get = |k: &str| args.iter().find(|(n, _)| n == k).unwrap().1.clone();
    let bytes = |s: &str| Arg::Bytes(s.as_bytes().to_vec());
    assert_eq!(get("app"), bytes("app"));
    assert_eq!(get("src-ip"), Arg::Ip("198.51.100.9".parse().unwrap()));
    assert_eq!(get("src-port"), Arg::Int(0));
    assert_eq!(get("dst-ip"), Arg::Ip("192.0.2.1".parse().unwrap()));
    assert_eq!(get("dst-port"), Arg::Int(443));
    assert_eq!(get("method"), bytes("POST"));
    assert_eq!(get("path"), bytes("/login"));
    assert_eq!(get("query"), bytes("next=%2F"));
    assert_eq!(get("version"), bytes("1.1"));
    assert_eq!(
        get("headers"),
        bytes("host: app.example\r\nx-forwarded-for: 198.51.100.9\r\n")
    );
    assert_eq!(get("body"), Arg::Bytes(vec![b'a'; 4096]));
    assert_eq!(get("exportRuleIDs"), Arg::Bool(true));
}

// RFC 0017 case 6
#[tokio::test]
async fn body_over_limit_rejects_or_passes() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = agent(Reply::Pass).await;
    let got = Got::default();
    let mut c = config(addr, true);
    c.max_body = 1024;
    let mut svc = WafLayer::new(Some(c.clone())).layer(upstream(got.clone()));
    let over = verdict("body_over_limit");
    for exact in [true, false] {
        assert_eq!(
            send(&mut svc, request("/", body(2048, exact))).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
    assert_eq!((seen.notifies(), verdict("body_over_limit")), (0, over + 2));
    // observe always forwards; `pass` likewise
    let observe = WafConfig {
        enforce: false,
        ..c.clone()
    };
    c.reject_over_limit = false;
    for c in [observe, c] {
        let mut svc = WafLayer::new(Some(c)).layer(upstream(got.clone()));
        for exact in [true, false] {
            assert_eq!(
                send(&mut svc, request("/", body(2048, exact))).await,
                StatusCode::OK
            );
            assert_eq!(
                seen.last().iter().find(|(k, _)| k == "body").unwrap().1,
                Arg::Bytes(vec![])
            );
            assert_eq!(got.lock().unwrap().last().unwrap().len(), 2048);
        }
    }
    assert_eq!(verdict("body_over_limit"), over + 6);
}

// RFC 0017 case 7
#[tokio::test]
async fn agent_failures_fail_closed() {
    let _g = SERIAL.lock().await;
    metrics();
    let got = Got::default();
    let gone = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let connect = reason("connect");
    let mut svc = WafLayer::new(Some(config(gone, true))).layer(upstream(got.clone()));
    assert_eq!(
        send(&mut svc, request("/", body(0, true))).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(reason("connect"), connect + 1);

    let (silent, _) = agent(Reply::Silent).await;
    let mut c = config(silent, true);
    c.timeout = Duration::from_millis(100);
    let timeout = reason("timeout");
    let mut svc = WafLayer::new(Some(c.clone())).layer(upstream(got.clone()));
    let t = Instant::now();
    assert_eq!(
        send(&mut svc, request("/", body(0, true))).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert_eq!(reason("timeout"), timeout + 1);

    for (enforce, fail_open) in [(true, true), (false, false)] {
        c.enforce = enforce;
        c.fail_open = fail_open;
        let mut svc = WafLayer::new(Some(c.clone())).layer(upstream(got.clone()));
        assert_eq!(
            send(&mut svc, request("/", body(0, true))).await,
            StatusCode::OK
        );
    }
}

fn limiter(rate: u32, routes: Vec<RouteConfig>) -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(rate, rate).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::default(),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes,
        max_blocks: 0,
    })
    .unwrap()
}

// RFC 0017 case 8
#[tokio::test]
async fn route_skips_the_waf() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = agent(Reply::Deny(403, 1)).await;
    let uploads = RouteConfig {
        name: "uploads".into(),
        matcher: Matcher {
            path: Some(PathMatch::parse("/upload/").unwrap()),
            ..Matcher::default()
        },
        deny: false,
        limit: None,
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::MIN,
        waf: false,
    };
    let waf = WafLayer::new(Some(config(addr, true))).layer(upstream(Got::default()));
    let mut svc = limiter(100, vec![uploads]).layer(waf);
    let skipped = verdict("skipped");
    assert_eq!(
        send(&mut svc, request("/upload/a", body(10, true))).await,
        StatusCode::OK
    );
    assert_eq!((seen.notifies(), verdict("skipped")), (0, skipped + 1));
    assert_eq!(
        send(&mut svc, request("/other", body(0, true))).await,
        StatusCode::FORBIDDEN
    );
}

// RFC 0017 case 9
#[tokio::test]
async fn rate_limit_runs_first() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = agent(Reply::Pass).await;
    let waf = WafLayer::new(Some(config(addr, true))).layer(upstream(Got::default()));
    let mut svc = limiter(1, Vec::new()).layer(waf);
    assert_eq!(
        send(&mut svc, request("/", body(0, true))).await,
        StatusCode::OK
    );
    assert_eq!(
        send(&mut svc, request("/", body(0, true))).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(seen.notifies(), 1);
}

// RFC 0017 case 10
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_are_reused_and_bounded() {
    let _g = SERIAL.lock().await;
    metrics();
    let (addr, seen) = spawn(Behavior {
        delay: Duration::from_millis(50),
        ..Behavior::reply(Reply::Pass)
    })
    .await;
    let mut c = config(addr, true);
    c.max_concurrent = 1;
    let layer = WafLayer::new(Some(c));
    let mut svc = layer.layer(upstream(Got::default()));
    for _ in 0..5 {
        assert_eq!(
            send(&mut svc, request("/", body(0, true))).await,
            StatusCode::OK
        );
    }
    let (mut a, mut b) = (svc.clone(), svc.clone());
    let (x, y) = tokio::join!(
        send(&mut a, request("/", body(0, true))),
        send(&mut b, request("/", body(0, true)))
    );
    assert_eq!((x, y), (StatusCode::OK, StatusCode::OK));
    assert_eq!(seen.notifies(), 7);
    assert_eq!(
        seen.connections.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}
