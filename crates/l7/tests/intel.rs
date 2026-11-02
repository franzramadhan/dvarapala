//! RFC 0031 cases 4 to 7 and 10: feeds and the GeoIP database through
//! the rate limit layer.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{ChallengeMode, Limit, PrefixSet, TrustedProxies};
use dvarapala_l7::{
    Action, ChallengeConfig, Feed, FeedList, Intel, Matcher, PeerAddr, RateLimitConfig,
    RateLimitLayer, RouteConfig, RouteKey, unix_now,
};
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use ring::digest;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

const LISTED: &str = "192.0.2.7";
const OTHER: &str = "203.0.113.9";
const HTML: (&str, &str) = ("accept", "text/html");

fn metrics() -> &'static PrometheusHandle {
    static H: OnceLock<PrometheusHandle> = OnceLock::new();
    H.get_or_init(|| PrometheusBuilder::new().install_recorder().unwrap())
}

/// Each test names its feeds apart, so the counters never mix.
fn hits(feed: &str, action: &str, mode: &str) -> u64 {
    let series = format!(
        "dvarapala_intel_hits_total{{feed=\"{feed}\",action=\"{action}\",mode=\"{mode}\"}}"
    );
    metrics()
        .render()
        .lines()
        .find(|l| l.starts_with(&series))
        .and_then(|l| l.rsplit(' ').next())
        .map_or(0, |v| v.parse().unwrap())
}

fn feed(name: &str, action: Action, enforce: bool) -> Feed {
    Feed {
        name: name.into(),
        action,
        enforce,
        list: FeedList::new(PrefixSet::new(["192.0.2.0/24".parse().unwrap()])),
    }
}

fn layer(routes: Vec<RouteConfig>, challenge: bool, intel: Intel) -> RateLimitLayer {
    metrics();
    let l = RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(100, 100).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: challenge.then(|| ChallengeConfig {
            // no attack: only the feed asks for the challenge
            mode: ChallengeMode::Attack,
            difficulty: 8,
            timeout: Duration::from_secs(60),
            pass_ttl: Duration::from_secs(3600),
            secret: vec![5; 32],
            cookie_secure: false,
            unix: unix_now,
        }),
        fingerprints: Default::default(),
        routes,
        max_blocks: 0,
        priority: None,
    })
    .unwrap();
    l.set_intel(Arc::new(intel));
    l
}

fn route(name: &str, f: impl FnOnce(&mut Matcher)) -> RouteConfig {
    let mut matcher = Matcher::default();
    f(&mut matcher);
    RouteConfig {
        name: name.into(),
        matcher,
        deny: false,
        limit: Some(Limit::new(1, 1).unwrap()),
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::new(100).unwrap(),
        waf: true,
        concurrency: 1,
    }
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

async fn send<S>(svc: &mut S, uri: &str, peer: &str, headers: &[(&str, &str)]) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let mut b = Request::builder().uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let mut r = b.body(Body::default()).unwrap();
    let peer = format!("{peer}:4000").parse::<SocketAddr>().unwrap();
    r.extensions_mut().insert(PeerAddr(peer));
    svc.ready().await.unwrap().call(r).await.unwrap()
}

// case 4
#[tokio::test]
async fn an_enforced_deny_feed_closes_the_connection() {
    let (calls, inner) = counting();
    let intel = Intel::new(vec![feed("c4", Action::Deny, true)]);
    let mut svc = layer(Vec::new(), false, intel).layer(inner);
    let res = send(&mut svc, "/", LISTED, &[]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(res.headers()["connection"], "close");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(hits("c4", "deny", "enforce"), 1);
    let res = send(&mut svc, "/", OTHER, &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(hits("c4", "deny", "enforce"), 1);
}

// case 5
#[tokio::test]
async fn an_observed_deny_feed_only_counts() {
    let (calls, inner) = counting();
    let intel = Intel::new(vec![feed("c5", Action::Deny, false)]);
    let mut svc = layer(Vec::new(), false, intel).layer(inner);
    let res = send(&mut svc, "/", LISTED, &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(hits("c5", "deny", "observe"), 1);
    assert_eq!(hits("c5", "deny", "enforce"), 0);
}

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

// case 6
#[tokio::test]
async fn a_challenge_feed_challenges_until_a_pass() {
    let (calls, inner) = counting();
    let intel = Intel::new(vec![feed("c6", Action::Challenge, true)]);
    let mut svc = layer(Vec::new(), true, intel).layer(inner);
    // no attack: a client the feed does not list goes straight through
    let res = send(&mut svc, "/a", OTHER, &[HTML]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = send(&mut svc, "/a", LISTED, &[HTML]).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(res.headers()["content-type"], "text/html; charset=utf-8");
    let html = res.into_body().collect().await.unwrap().to_bytes();
    let html = String::from_utf8(html.to_vec()).unwrap();
    let (t, s) = (attr(&html, "data-t"), attr(&html, "data-s"));
    let n = solve(s, 8);
    let verify = format!("/.well-known/dvarapala/verify?t={t}&s={s}&n={n}&r=%2Fa");
    let res = send(&mut svc, &verify, LISTED, &[HTML]).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let cookie = res.headers()["set-cookie"].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();
    let res = send(&mut svc, "/a", LISTED, &[HTML, ("cookie", &cookie)]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

// case 7
#[tokio::test]
async fn a_route_matches_an_enforced_tag_feed() {
    let (_, inner) = counting();
    let intel = Intel::new(vec![
        feed("c7-other", Action::Tag, true),
        feed("c7", Action::Tag, true),
    ]);
    // bit 1: the second feed
    let tor = route("tor", |m| m.feeds = 0b10);
    let mut svc = layer(vec![tor], false, intel).layer(inner);
    for (peer, second) in [
        (LISTED, StatusCode::TOO_MANY_REQUESTS),
        (OTHER, StatusCode::OK),
    ] {
        assert_eq!(
            send(&mut svc, "/", peer, &[]).await.status(),
            StatusCode::OK
        );
        assert_eq!(send(&mut svc, "/", peer, &[]).await.status(), second);
    }
    assert_eq!(hits("c7", "tag", "enforce"), 2);
}

// case 10
#[cfg(feature = "geoip")]
#[tokio::test]
async fn routes_match_country_and_asn_from_the_database() {
    use dvarapala_engine::parse_country;
    use dvarapala_l7::{GeoIp, test_db};

    let db = test_db(&[("198.51.100.0/24".parse().unwrap(), "ZZ", 64500)]);
    let geo = Arc::new(GeoIp::from_bytes(db).unwrap());
    let routes = vec![
        route("country", |m| {
            m.countries = vec![parse_country("ZZ").unwrap()]
        }),
        route("asn", |m| m.asns = vec![64500]),
    ];
    for r in routes {
        let (_, inner) = counting();
        let intel = Intel::new(Vec::new()).with_geo(Some(geo.clone()));
        let mut svc = layer(vec![r], false, intel).layer(inner);
        // the route's bucket of one throttles the second request it matches
        for (peer, second) in [
            ("198.51.100.1", StatusCode::TOO_MANY_REQUESTS),
            ("203.0.113.1", StatusCode::OK),
        ] {
            assert_eq!(
                send(&mut svc, "/", peer, &[]).await.status(),
                StatusCode::OK
            );
            assert_eq!(send(&mut svc, "/", peer, &[]).await.status(), second);
        }
    }
}

// regression: GeoLite2 ships Country and ASN as separate files, and a
// route on each must match the same client
#[cfg(feature = "geoip")]
#[tokio::test]
async fn country_and_asn_come_from_separate_files() {
    use dvarapala_engine::parse_country;
    use dvarapala_l7::{GeoIp, test_db_fields};

    let net = "198.51.100.0/24".parse().unwrap();
    let country = test_db_fields(&[(net, Some("ZZ"), None)]);
    let asn = test_db_fields(&[(net, None, Some(64500))]);
    let geo = [country, asn].map(|db| Arc::new(GeoIp::from_bytes(db).unwrap()));
    let routes = vec![
        route("country", |m| {
            m.countries = vec![parse_country("ZZ").unwrap()]
        }),
        route("asn", |m| m.asns = vec![64500]),
    ];
    for r in routes {
        let (_, inner) = counting();
        let intel = Intel::new(Vec::new()).with_geo(geo.clone());
        let mut svc = layer(vec![r], false, intel).layer(inner);
        for (peer, second) in [
            ("198.51.100.1", StatusCode::TOO_MANY_REQUESTS),
            ("203.0.113.1", StatusCode::OK),
        ] {
            assert_eq!(
                send(&mut svc, "/", peer, &[]).await.status(),
                StatusCode::OK
            );
            assert_eq!(send(&mut svc, "/", peer, &[]).await.status(), second);
        }
    }
}
