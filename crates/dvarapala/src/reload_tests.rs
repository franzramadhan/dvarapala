// figment::Jail closures return figment::Error by value; not ours to box
#![allow(clippy::result_large_err)]

use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Instant;

use dvarapala_l7::RateLimitConfig;
use figment::Jail;

use super::*;

const BASE: &str = "upstream = \"http://127.0.0.1:8081\"\nlisten = \"127.0.0.1:8080\"\n";

fn reloader(path: &str) -> Reloader {
    let start = config::load(Some(Path::new(path))).unwrap();
    let layer = RateLimitLayer::new(RateLimitConfig {
        limit: Limit::new(10, 10).unwrap(),
        max_clients: NonZeroUsize::new(16).unwrap(),
        trusted: TrustedProxies::new(Vec::new()),
        detection: None,
        scoring: None,
        now: Instant::now,
        cluster: None,
        block: None,
        challenge: None,
        fingerprints: Default::default(),
        routes: Vec::new(),
        max_blocks: 4,
        priority: None,
    })
    .unwrap();
    Reloader::new(
        Some(path.into()),
        Some(layer),
        Default::default(),
        false,
        start,
        None,
    )
}

// RFC 0014 case 7
#[test]
fn rate_applied_listen_needs_a_restart() {
    Jail::expect_with(|j| {
        j.create_file("d.toml", &format!("{BASE}[rate_limit]\nrate = 10\n"))?;
        let r = reloader("d.toml");
        j.create_file(
            "d.toml",
            "upstream = \"http://127.0.0.1:8081\"\nlisten = \"127.0.0.1:9000\"\n[rate_limit]\nrate = 1\nburst = 1\n",
        )?;
        let out = r.reload();
        assert_eq!(out.result, Ok(vec!["listen"]));
        assert_eq!(r.last(), Some(out));
        Ok(())
    });
}

// RFC 0014 case 8
#[test]
fn invalid_route_refused_whole() {
    Jail::expect_with(|j| {
        j.create_file("d.toml", BASE)?;
        let r = reloader("d.toml");
        j.create_file(
            "d.toml",
            &format!("{BASE}[rate_limit]\nrate = 1\n[[routes]]\nname = \"x\"\npath = \"\"\n"),
        )?;
        let e = r.reload().result.unwrap_err();
        assert!(e.contains("routes \"x\""), "{e}");
        // the routes in force did not move
        assert!(lock(&r.routes).is_empty());
        j.create_file("d.toml", "not toml [")?;
        assert!(r.reload().result.is_err());
        Ok(())
    });
}

#[test]
fn ja4_needs_a_restart_bad_keys_refuse_the_file() {
    Jail::expect_with(|j| {
        j.create_file("d.toml", BASE)?;
        let r = reloader("d.toml");
        j.create_file(
            "d.toml",
            &format!("{BASE}[fingerprint]\ndeny = [\"t13d*\"]\n"),
        )?;
        assert_eq!(
            r.reload().result,
            Ok(vec!["fingerprint (JA4 at the TLS listener)"])
        );
        j.create_file("d.toml", &format!("{BASE}trusted_proxies = [\"nope\"]\n"))?;
        let e = r.reload().result.unwrap_err();
        assert!(e.contains("trusted_proxies"), "{e}");
        j.create_file(
            "d.toml",
            &format!("{BASE}[pool]\nupstreams = [\"http://192.0.2.1\"]\n"),
        )?;
        let e = r.reload().result.unwrap_err();
        assert!(e.contains("pool.upstreams"), "{e}");
        Ok(())
    });
}

#[test]
fn detection_mode_and_factor_reload_in_place() {
    // in a jail, so no `DVARAPALA__*` another test sets leaks in
    let mut defaults = None;
    Jail::expect_with(|_| {
        defaults = Some(config::load(None).map_err(|e| e.to_string())?);
        Ok(())
    });
    let start = Config {
        upstream: Some("http://127.0.0.1:8081".into()),
        ..defaults.unwrap()
    };
    let mut new = start.clone();
    new.detection.mode = config::Mode::Enforce;
    new.detection.attack_rate_factor = 0.5;
    new.rate_limit.rate = 1;
    assert!(restart(&start, &new).is_empty());
    new.detection.window = std::time::Duration::from_secs(9);
    new.store.backend = config::Backend::Redis;
    assert_eq!(restart(&start, &new), ["detection", "store"]);
}

// RFC 0032: the bounds reload in place, the mode needs a restart
#[test]
fn concurrency_bounds_reload_mode_restarts() {
    Jail::expect_with(|j| {
        let fixed =
            |limit: u32| format!("{BASE}[concurrency]\nmode = \"fixed\"\nlimit = {limit}\n");
        j.create_file("d.toml", &fixed(10))?;
        let r = reloader("d.toml");
        let c = Arc::new(
            dvarapala_proxy::Concurrency::new(r.start.concurrency.config()?.unwrap()).unwrap(),
        );
        let _ = r.concurrency.set(c.clone());
        j.create_file("d.toml", &fixed(30))?;
        assert_eq!(r.reload().result, Ok(vec![]));
        assert_eq!(c.limit(), 30);
        j.create_file(
            "d.toml",
            &format!("{BASE}[concurrency]\nmode = \"gradient\"\n"),
        )?;
        assert_eq!(r.reload().result, Ok(vec!["concurrency.mode"]));
        assert_eq!(c.limit(), 30);
        j.create_file("d.toml", &format!("{BASE}[concurrency]\nreserve = 0.9\n"))?;
        let e = r.reload().result.unwrap_err();
        assert!(e.contains("reserve"), "{e}");
        assert!(in_place("concurrency.limit", &r.start));
        assert!(!in_place("concurrency.mode", &r.start));
        Ok(())
    });
}
