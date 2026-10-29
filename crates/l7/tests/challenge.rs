//! RFC 0012 cases 9 to 11: the challenge through the layer.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{ChallengeMode, Limit, TrustedProxies};
use dvarapala_l7::{ChallengeConfig, PeerAddr, RateLimitConfig, RateLimitLayer, unix_now};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use ring::digest;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

fn layer() -> RateLimitLayer {
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(100, 100).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: Some(ChallengeConfig {
            mode: ChallengeMode::Always,
            difficulty: 8,
            timeout: Duration::from_secs(60),
            pass_ttl: Duration::from_secs(3600),
            secret: vec![5; 32],
            cookie_secure: false,
            unix: unix_now,
        }),
        fingerprints: Default::default(),
        routes: Vec::new(),
    })
    .unwrap()
}

fn counting() -> (
    Arc<AtomicUsize>,
    impl Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let svc = service_fn(move |_req: Request<Body>| {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, Infallible>(Response::new(Body::default())) }
    });
    (calls, svc)
}

fn req(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut r = b.body(Body::default()).unwrap();
    r.extensions_mut()
        .insert(PeerAddr("192.0.2.10:4000".parse::<SocketAddr>().unwrap()));
    r
}

const HTML: (&str, &str) = ("accept", "text/html,application/xhtml+xml");

fn attr<'a>(html: &'a str, name: &str) -> &'a str {
    let start = html.find(&format!("{name}=\"")).unwrap() + name.len() + 2;
    &html[start..start + html[start..].find('"').unwrap()]
}

fn solve(seed: &str, bits: u32) -> u64 {
    (0u64..)
        .find(|n| {
            let h = digest::digest(&digest::SHA256, format!("{seed}:{n}").as_bytes());
            u32::from_be_bytes(h.as_ref()[..4].try_into().unwrap()).leading_zeros() >= bits
        })
        .unwrap()
}

#[tokio::test]
async fn browser_gets_the_page_not_the_upstream() {
    let (calls, inner) = counting();
    let mut svc = layer().layer(inner);
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req("/", &[HTML]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(res.headers()["content-type"], "text/html; charset=utf-8");
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn non_browsers_get_429_or_grpc_8() {
    let (calls, inner) = counting();
    let mut svc = layer().layer(inner);
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req("/", &[]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(!res.headers().contains_key("retry-after"));
    let grpc = [("content-type", "application/grpc"), HTML];
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req("/s/M", &grpc))
        .await
        .unwrap();
    assert_eq!(res.headers()["grpc-status"], "8");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn solved_page_gives_a_pass_that_opens_the_upstream() {
    let (calls, inner) = counting();
    let mut svc = layer().layer(inner);
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req("/a?b=1", &[HTML]))
        .await
        .unwrap();
    let html =
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    let (t, s, d) = (
        attr(&html, "data-t"),
        attr(&html, "data-s"),
        attr(&html, "data-d"),
    );
    assert_eq!(d, "8");
    let n = solve(s, 8);
    let verify = format!("/.well-known/dvarapala/verify?t={t}&s={s}&n={n}&r=%2Fa%3Fb%3D1");
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req(&verify, &[HTML]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers()["location"], "/a?b=1");
    let cookie = res.headers()["set-cookie"].to_str().unwrap();
    let pass = cookie.split(';').next().unwrap();
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req("/a?b=1", &[HTML, ("cookie", pass)]))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
