//! RFC 0015: upstream pools, health checks and retries.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use dvarapala_proxy::{
    HealthConfig, Http2Limits, Pool, PoolConfig, ReverseProxy, UpstreamConfig, serve, spawn_health,
};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Upstream answering `ok`, and `health` on `/healthz`. Counts the other
/// requests.
async fn upstream(health: StatusCode) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = l.accept().await.unwrap();
            let h = h.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let h = h.clone();
                    async move {
                        let mut res = Response::new(Full::new(Bytes::from_static(b"ok")));
                        if req.uri().path() == "/healthz" {
                            *res.status_mut() = health;
                        } else {
                            h.fetch_add(1, Ordering::SeqCst);
                        }
                        Ok::<_, Infallible>(res)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(s), svc)
                    .await;
            });
        }
    });
    (addr, hits)
}

/// An address with nothing listening.
async fn dead() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(upstreams: &[SocketAddr]) -> PoolConfig {
    let mut c = PoolConfig::single("http://192.0.2.1");
    c.upstreams = upstreams.iter().map(|a| format!("http://{a}")).collect();
    c
}

async fn proxy(pool: &Arc<Pool>) -> (SocketAddr, oneshot::Sender<()>) {
    let p = ReverseProxy::<Incoming>::with_pool(pool.clone(), &UpstreamConfig::default()).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(serve(l, Http2Limits::default(), p, async {
        let _ = rx.await;
    }));
    (addr, tx)
}

async fn send(addr: SocketAddr, method: Method) -> StatusCode {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let body = if method == Method::GET { "" } else { "x" };
    let mut req = Request::new(Full::new(Bytes::from_static(body.as_bytes())));
    *req.method_mut() = method;
    *req.uri_mut() = format!("http://{addr}/").parse().unwrap();
    let res = client.request(req).await.unwrap();
    let status = res.status();
    let _ = res.into_body().collect().await;
    status
}

// case 7
#[tokio::test(flavor = "multi_thread")]
async fn connect_failures_are_retried_for_idempotent_requests_only() {
    let (live, hits) = upstream(StatusCode::OK).await;
    let mut c = config(&[dead().await, live]);
    // no ejection, so that requests keep going to the dead one
    c.eject_after = 0;
    c.retries = 1;
    c.retry_budget = 0.2;
    let pool = Arc::new(Pool::new(c).unwrap());
    let (addr, _stop) = proxy(&pool).await;
    for _ in 0..20 {
        assert_eq!(send(addr, Method::GET).await, StatusCode::OK);
    }
    assert_eq!(hits.load(Ordering::SeqCst), 20);
    // two in a row: one of them picks the dead one
    let mut posts = [
        send(addr, Method::POST).await,
        send(addr, Method::POST).await,
    ];
    posts.sort();
    assert_eq!(posts, [StatusCode::OK, StatusCode::BAD_GATEWAY]);
    assert_eq!(hits.load(Ordering::SeqCst), 21);
}

// case 8
#[tokio::test(flavor = "multi_thread")]
async fn failing_health_checks_take_an_endpoint_out() {
    let (sick, sick_hits) = upstream(StatusCode::INTERNAL_SERVER_ERROR).await;
    let (well, well_hits) = upstream(StatusCode::OK).await;
    let mut c = config(&[sick, well]);
    c.health = Some(HealthConfig {
        path: "/healthz".into(),
        interval: Duration::from_millis(50),
        timeout: Duration::from_secs(1),
        unhealthy_after: 3,
        healthy_after: 2,
    });
    let pool = Arc::new(Pool::new(c).unwrap());
    spawn_health(&pool, &UpstreamConfig::default()).unwrap();
    let (addr, _stop) = proxy(&pool).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..10 {
        assert_eq!(send(addr, Method::GET).await, StatusCode::OK);
    }
    assert_eq!(sick_hits.load(Ordering::SeqCst), 0);
    assert_eq!(well_hits.load(Ordering::SeqCst), 10);
}
