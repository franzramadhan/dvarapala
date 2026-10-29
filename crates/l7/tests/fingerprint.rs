//! RFC 0012: JA4 fingerprint rules through the layer.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dvarapala_engine::{ChallengeMode, Limit, TrustedProxies};
use dvarapala_l7::{
    ChallengeConfig, Fingerprints, Ja4, PeerAddr, RateLimitConfig, RateLimitLayer, unix_now,
};
use http::{Request, Response, StatusCode, Version};
use http_body_util::Full;
use tower::{Layer, Service, ServiceExt, service_fn};

type Body = Full<Bytes>;

const DENY: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
const OTHER: &str = "t13d1516h2_8daaf6152771_000000000000";
const SUSPECT: &str = "t12d0909h1_000000000000_000000000000";

fn ja4(s: &str) -> Ja4 {
    Ja4::new(s.as_bytes().try_into().unwrap()).unwrap()
}

fn layer() -> RateLimitLayer {
    let rules = Fingerprints::new(&[DENY.into()], &["t12d*".into()], "").unwrap();
    RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(100, 100).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        // only the fingerprint rule asks for a challenge
        challenge: Some(ChallengeConfig {
            mode: ChallengeMode::Attack,
            difficulty: 8,
            timeout: Duration::from_secs(60),
            pass_ttl: Duration::from_secs(3600),
            secret: vec![5; 32],
            cookie_secure: false,
            unix: unix_now,
        }),
        fingerprints: rules,
        routes: Vec::new(),
        max_blocks: 0,
    })
    .unwrap()
}

async fn send<S>(svc: &mut S, fp: Option<&str>, version: Version) -> Response<Body>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    let mut r = Request::get("/")
        .version(version)
        .header("accept", "text/html")
        .body(Body::default())
        .unwrap();
    r.extensions_mut()
        .insert(PeerAddr("192.0.2.10:4000".parse::<SocketAddr>().unwrap()));
    if let Some(f) = fp {
        r.extensions_mut().insert(ja4(f));
    }
    svc.ready().await.unwrap().call(r).await.unwrap()
}

#[tokio::test]
async fn deny_challenge_or_pass_by_fingerprint() {
    let inner = service_fn(|_: Request<Body>| async {
        Ok::<_, Infallible>(Response::new(Body::default()))
    });
    let mut svc = layer().layer(inner);
    let v = Version::HTTP_11;
    let denied = send(&mut svc, Some(DENY), v).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(denied.headers()["connection"], "close");
    let page = send(&mut svc, Some(SUSPECT), v).await;
    assert_eq!(page.status(), StatusCode::FORBIDDEN);
    assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
    for fp in [Some(OTHER), None] {
        assert_eq!(send(&mut svc, fp, v).await.status(), StatusCode::OK);
    }
    let h3 = send(&mut svc, Some(OTHER), Version::HTTP_3).await;
    assert_eq!(h3.status(), StatusCode::OK);
}

#[test]
fn rules_and_formats() {
    let f = ja4(DENY);
    assert_eq!(f.to_string(), DENY);
    assert_eq!(format!("{f:?}"), format!("Ja4({DENY})"));
    let long = format!("{DENY}x*");
    for bad in ["t13d*x", "*", "short", long.as_str()] {
        let err = Fingerprints::new(&[bad.into()], &[], "").unwrap_err();
        assert!(err.contains("a 36-character JA4"), "{bad}: {err}");
    }
    assert!(Fingerprints::new(&[], &[], "bad header").is_err());
    assert!(!Fingerprints::default().enabled());
}
