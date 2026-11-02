//! RFC 0032 cases 6 to 13: the upstream concurrency limit in front of a
//! real upstream. The rate limiter's priority is set from test headers.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{Class, ConcurrencyConfig, LimitMode, Priority};
use dvarapala_proxy::{
    Concurrency, Http2Limits, Pool, PoolConfig, ProxyBody, ReverseProxy, UpstreamConfig, serve,
};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tower_service::Service;

/// Requests in flight at the upstream now, and the most seen.
#[derive(Default)]
struct Load {
    now: AtomicUsize,
    peak: AtomicUsize,
    hits: AtomicUsize,
}

/// `/hold/<ms>` answers after `ms`; `/slow` after 20 ms, times the square
/// of the load over 50 in flight (far from timer jitter on a busy runner); `/stream` sends the head at once and the body after
/// 2 s; anything else at once.
async fn upstream() -> (SocketAddr, Arc<Load>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let load = Arc::new(Load::default());
    let ld = load.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let ld = ld.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let ld = ld.clone();
                    async move {
                        let n = ld.now.fetch_add(1, Ordering::SeqCst) + 1;
                        ld.peak.fetch_max(n, Ordering::SeqCst);
                        ld.hits.fetch_add(1, Ordering::SeqCst);
                        let path = req.uri().path().to_owned();
                        let wait = match path.strip_prefix("/hold/") {
                            Some(ms) => ms.parse().unwrap(),
                            None if path == "/slow" => 20 * (n as u64).max(50).pow(2) / 2500,
                            None => 0,
                        };
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                        ld.now.fetch_sub(1, Ordering::SeqCst);
                        let body = if path == "/stream" {
                            let s = futures_util::stream::once(async {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"late")))
                            });
                            StreamBody::new(s).boxed()
                        } else {
                            Full::new(Bytes::from_static(b"ok")).boxed()
                        };
                        Ok::<_, Infallible>(Response::new(body))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    (addr, load)
}

/// Puts the priority from `x-class` and `x-weight` on the request, as
/// the rate limiter would.
#[derive(Clone)]
struct Tag(ReverseProxy<Incoming>);

impl Service<Request<Incoming>> for Tag {
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = <ReverseProxy<Incoming> as Service<Request<Incoming>>>::Future;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: Request<Incoming>) -> Self::Future {
        let h = |k: &str| req.headers().get(k).and_then(|v| v.to_str().ok());
        let class = match h("x-class") {
            Some("trusted") => Class::Trusted,
            Some("suspect") => Class::Suspect,
            _ => Class::Normal,
        };
        let weight = h("x-weight").map_or(1, |w| w.parse().unwrap());
        req.extensions_mut().insert(Priority { class, weight });
        self.0.call(req)
    }
}

fn fixed(limit: u32, reserve: f64) -> ConcurrencyConfig {
    ConcurrencyConfig {
        mode: LimitMode::Fixed,
        limit,
        min: 1,
        max: 1,
        window: Duration::from_secs(1),
        reserve,
    }
}

async fn proxy(
    upstreams: &[SocketAddr],
    eject_after: u32,
    limit: Option<ConcurrencyConfig>,
) -> (SocketAddr, Arc<Pool>, oneshot::Sender<()>) {
    let mut c = PoolConfig::single("http://192.0.2.1");
    c.upstreams = upstreams.iter().map(|a| format!("http://{a}")).collect();
    c.eject_after = eject_after;
    c.eject_time = Duration::from_secs(60);
    let mut pool = Pool::new(c).unwrap();
    if let Some(l) = limit {
        pool = pool.with_concurrency(Arc::new(Concurrency::new(l).unwrap()));
    }
    let pool = Arc::new(pool);
    let p = ReverseProxy::<Incoming>::with_pool(pool.clone(), &UpstreamConfig::default()).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, Http2Limits::default(), Tag(p), async {
        let _ = rx.await;
    }));
    (addr, pool, tx)
}

/// The status, `Retry-After` and `grpc-status` of one request.
async fn send(addr: SocketAddr, path: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let mut b = Request::get(format!("http://{addr}{path}"));
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let res = client
        .request(b.body(Full::default()).unwrap())
        .await
        .unwrap();
    let h = |k: &str| res.headers().get(k).map_or("", |v| v.to_str().unwrap());
    let extra = format!("{}{}", h("retry-after"), h("grpc-status"));
    (res.status(), extra)
}

/// Starts `n` requests to `path` and waits until the upstream holds them.
async fn hold(
    addr: SocketAddr,
    load: &Load,
    n: usize,
    path: &'static str,
    h: &'static [(&str, &str)],
) {
    let start = load.now.load(Ordering::SeqCst);
    for _ in 0..n {
        tokio::spawn(send(addr, path, h));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while load.now.load(Ordering::SeqCst) < start + n {
        assert!(Instant::now() < deadline, "the upstream never held {n}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

const SHED: (StatusCode, &str) = (StatusCode::SERVICE_UNAVAILABLE, "1");

// RFC 0032 case 6
#[tokio::test(flavor = "multi_thread")]
async fn fixed_sheds_over_the_cap_with_retry_after() {
    let (up, load) = upstream().await;
    let (addr, _pool, _stop) = proxy(&[up], 0, Some(fixed(5, 0.0))).await;
    let all: Vec<_> = (0..10)
        .map(|_| tokio::spawn(send(addr, "/hold/500", &[])))
        .collect();
    let mut ok = 0;
    for r in all {
        match r.await.unwrap() {
            (StatusCode::OK, _) => ok += 1,
            (s, extra) => assert_eq!((s, extra.as_str()), SHED),
        }
    }
    assert_eq!(ok, 5);
    assert_eq!(load.peak.load(Ordering::SeqCst), 5);
    // gRPC gets status 8
    hold(addr, &load, 5, "/hold/500", &[]).await;
    let grpc = send(addr, "/", &[("content-type", "application/grpc")]).await;
    assert_eq!(grpc.0, StatusCode::OK);
    assert!(grpc.1.ends_with('8'), "{grpc:?}");
}

// RFC 0032 case 7
#[tokio::test(flavor = "multi_thread")]
async fn pass_holders_are_admitted_ahead_of_unknown_clients() {
    let (up, load) = upstream().await;
    let (addr, _pool, _stop) = proxy(&[up], 0, Some(fixed(10, 0.2))).await;
    hold(addr, &load, 8, "/hold/800", &[]).await;
    let normal = send(addr, "/", &[]).await;
    assert_eq!((normal.0, normal.1.as_str()), SHED);
    let trusted = [("x-class", "trusted")];
    for _ in 0..2 {
        assert_eq!(send(addr, "/", &trusted).await.0, StatusCode::OK);
    }
}

// RFC 0032 case 8
#[tokio::test(flavor = "multi_thread")]
async fn gradient_settles_under_the_knee() {
    let (up, load) = upstream().await;
    let config = ConcurrencyConfig {
        mode: LimitMode::Gradient,
        limit: 10,
        min: 10,
        max: 1000,
        window: Duration::from_millis(100),
        reserve: 0.0,
    };
    let (addr, pool, _stop) = proxy(&[up], 0, Some(config)).await;
    let end = Instant::now() + Duration::from_secs(4);
    let clients: Vec<_> = (0..200)
        .map(|i| {
            tokio::spawn(async move {
                // ramp: client i starts after i * 10 ms; 200 pass the knee
                // at 50 without running a laptop out of local ports
                tokio::time::sleep(Duration::from_millis(i * 10)).await;
                // one client each, so connections are kept alive
                let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
                let uri: http::Uri = format!("http://{addr}/slow").parse().unwrap();
                while Instant::now() < end {
                    let res = client.get(uri.clone()).await.unwrap();
                    let s = res.status();
                    let _ = res.into_body().collect().await;
                    if s != StatusCode::OK {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
            })
        })
        .collect();
    for c in clients {
        c.await.unwrap();
    }
    let limit = pool.concurrency().unwrap().limit();
    assert!((40..=80).contains(&limit), "limit {limit}");
    let peak = load.peak.load(Ordering::SeqCst);
    assert!(peak <= 120, "the upstream saw {peak} in flight");
}

// RFC 0032 case 9
#[tokio::test(flavor = "multi_thread")]
async fn shed_requests_eject_nothing() {
    let (a, la) = upstream().await;
    let (b, lb) = upstream().await;
    let (addr, _pool, _stop) = proxy(&[a, b], 1, Some(fixed(1, 0.0))).await;
    let held = tokio::spawn(send(addr, "/hold/300", &[]));
    while la.now.load(Ordering::SeqCst) + lb.now.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for _ in 0..3 {
        assert_eq!(
            send(addr, "/", &[]).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert_eq!(held.await.unwrap().0, StatusCode::OK);
    let before = (
        la.hits.load(Ordering::SeqCst),
        lb.hits.load(Ordering::SeqCst),
    );
    for _ in 0..4 {
        assert_eq!(send(addr, "/", &[]).await.0, StatusCode::OK);
    }
    // round robin over both: neither was ejected
    assert!(la.hits.load(Ordering::SeqCst) > before.0);
    assert!(lb.hits.load(Ordering::SeqCst) > before.1);
}

// RFC 0032 cases 10 and 11
#[tokio::test(flavor = "multi_thread")]
async fn weight_zero_bypasses_heavy_routes_take_more_slots() {
    let (up, load) = upstream().await;
    let (addr, _pool, _stop) = proxy(&[up], 0, Some(fixed(20, 0.0))).await;
    hold(addr, &load, 2, "/hold/800", &[("x-weight", "10")]).await;
    assert_eq!(
        send(addr, "/", &[]).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        send(addr, "/", &[("x-weight", "0")]).await.0,
        StatusCode::OK
    );
}

// RFC 0032 case 12: a stream after its head holds no slot
#[tokio::test(flavor = "multi_thread")]
async fn the_slot_is_released_at_the_response_head() {
    let (up, _load) = upstream().await;
    let (addr, _pool, _stop) = proxy(&[up], 0, Some(fixed(1, 0.0))).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let res = client
        .get(format!("http://{addr}/stream").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // the body is still coming
    assert_eq!(send(addr, "/", &[]).await.0, StatusCode::OK);
    drop(res);
}

// RFC 0032 case 13
#[tokio::test(flavor = "multi_thread")]
async fn off_sheds_nothing() {
    let (up, load) = upstream().await;
    let (addr, _pool, _stop) = proxy(&[up], 0, None).await;
    hold(addr, &load, 20, "/hold/500", &[]).await;
    assert_eq!(send(addr, "/", &[]).await.0, StatusCode::OK);
}
