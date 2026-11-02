//! RFC 0032 cases 5, 10 and 11 at the rate limiter: the class and weight
//! it puts on each allowed request for the upstream concurrency limit.

use std::cell::Cell;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{DetectConfig, Features, Limit, Matcher, Scorer, TrustedProxies};
use dvarapala_l7::{
    Detection, PathMatch, PeerAddr, Priority, RateLimitConfig, RateLimitLayer, RouteConfig,
    RouteKey, Scoring,
};
use http::header::HeaderValue;
use http::{Request, Response};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

thread_local! {
    static MS: Cell<u64> = const { Cell::new(0) };
}

fn now() -> Instant {
    *BASE + Duration::from_millis(MS.get())
}

fn at(ms: u64) {
    MS.set(ms);
}

struct Fixed(f64);

impl Scorer for Fixed {
    fn score(&self, _: &Features) -> f64 {
        self.0
    }
}

fn route(name: &str, path: &str, concurrency: u32) -> RouteConfig {
    RouteConfig {
        name: name.into(),
        matcher: Matcher {
            path: Some(PathMatch::Prefix(path.into())),
            ..Matcher::default()
        },
        deny: false,
        limit: None,
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::new(16).unwrap(),
        waf: true,
        concurrency,
    }
}

fn config(priority: Option<f64>) -> RateLimitConfig {
    RateLimitConfig {
        limit: Limit::new(10_000, 10_000).unwrap(),
        max_clients: NonZeroUsize::new(4096).unwrap(),
        trusted: TrustedProxies::default(),
        detection: None,
        scoring: None,
        now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: vec![
            route("export", "/export", 10),
            route("health", "/healthz", 0),
        ],
        max_blocks: 0,
        priority,
    }
}

/// Answers with the request's priority in `x-priority`: `class/weight`.
fn inner() -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible> + Clone {
    service_fn(|r: Request<Body>| {
        let p = r.extensions().get::<Priority>().copied();
        async move {
            let mut res = Response::new(Body::default());
            if let Some(p) = p {
                let v = format!("{}/{}", p.class.name(), p.weight);
                res.headers_mut()
                    .insert("x-priority", HeaderValue::from_str(&v).unwrap());
            }
            Ok::<_, Infallible>(res)
        }
    })
}

async fn send<S>(svc: &mut S, peer: &str, path: &str) -> Option<String>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let mut r = Request::get(path).body(Body::default()).unwrap();
    r.extensions_mut().insert(PeerAddr(
        format!("{peer}:4000").parse::<SocketAddr>().unwrap(),
    ));
    let res = svc.ready().await.unwrap().call(r).await.unwrap();
    let v = res.headers().get("x-priority")?;
    Some(v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn off_puts_no_priority() {
    let mut svc = RateLimitLayer::new(config(None)).unwrap().layer(inner());
    assert_eq!(send(&mut svc, "192.0.2.1", "/").await, None);
}

// RFC 0032 cases 10 and 11: a route bypasses the limit or weighs more
#[tokio::test]
async fn normal_by_default_routes_set_the_weight() {
    let mut svc = RateLimitLayer::new(config(Some(0.2)))
        .unwrap()
        .layer(inner());
    for (path, want) in [
        ("/", "normal/1"),
        ("/export", "normal/10"),
        ("/healthz", "normal/0"),
    ] {
        let got = send(&mut svc, "192.0.2.1", path).await;
        assert_eq!(got.as_deref(), Some(want), "{path}");
    }
}

#[tokio::test]
async fn a_low_score_is_trusted() {
    for (score, want) in [(0.1, "trusted/1"), (0.5, "normal/1")] {
        let mut c = config(Some(0.2));
        c.scoring = Some(Scoring {
            scorer: Arc::new(Fixed(score)),
            threshold: 0.9,
        });
        let mut svc = RateLimitLayer::new(c).unwrap().layer(inner());
        let got = send(&mut svc, "192.0.2.1", "/").await;
        assert_eq!(got.as_deref(), Some(want), "{score}");
    }
}

// RFC 0032 case 5: the heavy hitter of an attack is a suspect
#[tokio::test]
async fn a_heavy_hitter_during_an_attack_is_a_suspect() {
    let mut c = config(Some(0.2));
    c.limit = Limit::new(4, 1).unwrap();
    c.detection = Some(Detection {
        detect: DetectConfig {
            warmup_windows: 1,
            trigger_windows: 1,
            ..DetectConfig::default()
        },
        enforce: false,
        attack_rate_factor: 0.25,
    });
    let mut svc = RateLimitLayer::new(c).unwrap().layer(inner());
    at(0);
    for i in 0..10 {
        send(&mut svc, &format!("198.51.100.{i}"), "/").await;
    }
    at(1000);
    for _ in 0..1000 {
        send(&mut svc, "192.0.2.10", "/").await;
    }
    at(2000);
    let heavy = send(&mut svc, "192.0.2.10", "/").await;
    assert_eq!(heavy.as_deref(), Some("suspect/1"));
    let other = send(&mut svc, "198.51.100.1", "/").await;
    assert_eq!(other.as_deref(), Some("normal/1"));
}
