//! RFC 0029 cases 1, 2, 4, 5, 7, 8, 9 and 11 through the reloader, and
//! the RFC 0002 load errors.
// figment::Jail closures return figment::Error by value; not ours to box
#![allow(clippy::result_large_err)]

use std::path::Path;
use std::time::Instant;

use dvarapala_l7::RateLimitLayer;
use figment::Jail;

use super::*;
use crate::reload::Reloader;
#[cfg(feature = "ml")]
use crate::reload::in_place;
use crate::{config, layer};

#[cfg(feature = "ml")]
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../engine/tests/fixtures/xgb_stumps.json"
);

fn toml(model: bool, threshold: f64) -> String {
    let m = if model { "model = \"m.json\"\n" } else { "" };
    format!(
        "upstream = \"http://127.0.0.1:8081\"\nlisten = \"127.0.0.1:8080\"\n[ml]\n{m}threshold = {threshold}\n"
    )
}

/// The reloader over `d.toml`, with the layer and model `serve` builds.
fn reloader() -> Reloader {
    let cfg = config::load(Some(Path::new("d.toml"))).unwrap();
    let model = cfg.ml.model.as_deref().map(|p| load(p, None).unwrap());
    let c = layer::config(&cfg, Instant::now, model.as_ref()).unwrap();
    let l = RateLimitLayer::new(c).unwrap();
    Reloader::new(
        Some("d.toml".into()),
        Some(l),
        Default::default(),
        false,
        cfg,
        model,
    )
}

#[cfg(feature = "ml")]
fn fixture() -> String {
    std::fs::read_to_string(FIXTURE).unwrap()
}

/// In a jail, so no `DVARAPALA__*` another test sets leaks in.
fn defaults() -> Config {
    let mut cfg = None;
    Jail::expect_with(|_| {
        cfg = Some(config::load(None).map_err(|e| e.to_string())?);
        Ok(())
    });
    cfg.unwrap()
}

#[cfg(feature = "ml")]
fn sha(r: &Reloader) -> Option<String> {
    r.model().map(|m| m.sha256)
}

// RFC 0029 cases 1 and 11
#[cfg(feature = "ml")]
#[test]
fn threshold_and_model_reload_in_place() {
    Jail::expect_with(|j| {
        j.create_file("m.json", &fixture())?;
        j.create_file("d.toml", &toml(true, 0.9))?;
        let r = reloader();
        j.create_file("d.toml", &toml(true, 0.1))?;
        assert_eq!(r.reload().result, Ok(vec![]));
        let (_, cur) = r.configs();
        assert_eq!(cur.ml.threshold, 0.1);
        assert!(in_place("ml.model", &cur) && in_place("ml.threshold", &cur));
        assert!(!in_place("ml.llm.endpoint", &cur));
        Ok(())
    });
}

// RFC 0029 cases 2 and 5
#[cfg(feature = "ml")]
#[test]
fn new_bytes_swap_the_same_bytes_keep_the_model() {
    Jail::expect_with(|j| {
        j.create_file("m.json", &fixture())?;
        j.create_file("d.toml", &toml(true, 0.9))?;
        let r = reloader();
        let first = r.model().unwrap();
        assert_eq!(r.reload().result, Ok(vec![]));
        let same = r.model().unwrap();
        assert!(Arc::ptr_eq(&first.scorer, &same.scorer));
        assert_eq!(first.loaded_at, same.loaded_at);
        j.create_file("m.json", &format!("{}\n", fixture()))?;
        assert_eq!(r.reload().result, Ok(vec![]));
        let new = r.model().unwrap();
        assert_ne!(new.sha256, first.sha256);
        assert!(!Arc::ptr_eq(&first.scorer, &new.scorer));
        Ok(())
    });
}

// RFC 0029 case 4
#[cfg(feature = "ml")]
#[test]
fn a_bad_model_refuses_the_reload_and_keeps_the_running_one() {
    Jail::expect_with(|j| {
        j.create_file("m.json", &fixture())?;
        j.create_file("d.toml", &toml(true, 0.9))?;
        let r = reloader();
        let running = sha(&r);
        let squared = fixture().replace("binary:logistic", "reg:squarederror");
        for bad in ["{", "[]", squared.as_str()] {
            j.create_file("m.json", bad)?;
            j.create_file("d.toml", &toml(true, 0.1))?;
            let e = r.reload().result.unwrap_err();
            assert!(e.contains("ml.model m.json"), "{e}");
            assert_eq!(sha(&r), running);
            assert_eq!(r.configs().1.ml.threshold, 0.9, "nothing applied");
        }
        Ok(())
    });
}

// RFC 0029 cases 7 and 8
#[cfg(feature = "ml")]
#[test]
fn a_model_set_then_removed_by_reloads() {
    Jail::expect_with(|j| {
        j.create_file("d.toml", &toml(false, 0.9))?;
        let r = reloader();
        assert!(r.model().is_none());
        j.create_file("m.json", &fixture())?;
        j.create_file("d.toml", &toml(true, 0.9))?;
        assert_eq!(r.reload().result, Ok(vec![]));
        assert!(r.model().is_some());
        j.create_file("d.toml", &toml(false, 0.9))?;
        assert_eq!(r.reload().result, Ok(vec![]));
        assert!(r.model().is_none());
        Ok(())
    });
}

// RFC 0029 case 9
#[cfg(not(feature = "ml"))]
#[test]
fn a_model_needs_the_ml_feature_on_reload() {
    Jail::expect_with(|j| {
        j.create_file("d.toml", &toml(false, 0.9))?;
        let r = reloader();
        j.create_file("d.toml", &toml(true, 0.9))?;
        let e = r.reload().result.unwrap_err();
        assert!(e.contains("needs a build with the ml feature"), "{e}");
        Ok(())
    });
}

// RFC 0002: the model's errors name the key and the file
#[test]
fn load_errors_name_the_file() {
    let e = load(Path::new("/nonexistent/dvarapala-model.json"), None).err();
    let e = e.unwrap();
    assert!(
        e.contains("ml.model") && e.contains("dvarapala-model.json"),
        "{e}"
    );
}

#[test]
fn no_model_no_scoring_unless_llm_samples() {
    let mut cfg = defaults();
    assert!(scoring(&cfg, None).is_none());
    assert_eq!(status(&cfg, None), "null");
    cfg.ml.llm.endpoint = Some("http://192.0.2.1:4000/v1".into());
    assert!(
        scoring(&cfg, None)
            .unwrap()
            .scorer
            .score(&[0.0; 10])
            .is_nan()
    );
}

#[cfg(feature = "ml")]
#[test]
fn the_model_carries_the_threshold_and_shows_in_status() {
    let mut cfg = defaults();
    cfg.ml.threshold = 0.7;
    let m = load(Path::new(FIXTURE), None).unwrap();
    assert_eq!(scoring(&cfg, Some(&m)).unwrap().threshold, 0.7);
    assert_eq!(m.sha256.len(), 64);
    assert_eq!(
        status(&cfg, Some(&m)),
        format!(
            "{{\"sha256\":\"{}\",\"threshold\":0.7,\"loaded_at\":{}}}",
            m.sha256, m.loaded_at
        )
    );
}
