//! RFC 0021: the running config for the console, secrets redacted, each
//! key marked as reloaded in place or not and as default or not.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serializer;
use serde_json::{Map, Value, json};

use super::Config;

/// What a set secret serializes as.
pub const REDACTED: &str = "<redacted>";

/// Durations in the form the file accepts: the largest exact unit.
pub fn ser_duration<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&duration(*d))
}

/// `""` for none, as the file takes it.
pub fn ser_opt_duration<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&d.map(duration).unwrap_or_default())
}

pub fn redact<S: Serializer>(v: &str, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(if v.is_empty() { "" } else { REDACTED })
}

pub fn redact_opt<S: Serializer>(v: &Option<String>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(_) => s.serialize_str(REDACTED),
        None => s.serialize_none(),
    }
}

fn duration(d: Duration) -> String {
    let ms = d.as_millis();
    let units = [("h", 3_600_000), ("m", 60_000), ("s", 1_000)];
    units
        .iter()
        .find(|(_, n)| ms > 0 && ms.is_multiple_of(*n))
        .map_or_else(|| format!("{ms}ms"), |(u, n)| format!("{}{u}", ms / n))
}

/// `GET /config`: one entry per key with its running value. A key that
/// needs a restart shows the value the process started with; `reload`
/// says whether a reload applies it in place, `default` whether it is
/// the default.
pub fn view(start: &Config, current: &Config) -> Value {
    let (s, c) = (flat(start), flat(current));
    let d = flat(&defaults());
    let keys: Vec<Value> = c
        .iter()
        .map(|(k, v)| {
            let reload = crate::reload::in_place(k, current);
            let v = if reload { v } else { s.get(k).unwrap_or(v) };
            json!({
                "key": k,
                "value": v,
                "reload": reload,
                "default": d.get(k) == Some(v),
            })
        })
        .collect();
    json!({ "keys": keys })
}

/// Every default, as an empty file gives them.
fn defaults() -> Config {
    figment::Figment::new()
        .extract()
        .expect("an empty config deserializes")
}

/// The config as dotted keys; tables are walked, arrays are values.
fn flat(cfg: &Config) -> BTreeMap<String, Value> {
    fn walk(prefix: &str, m: &Map<String, Value>, out: &mut BTreeMap<String, Value>) {
        for (k, v) in m {
            let key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            match v {
                Value::Object(m) => walk(&key, m, out),
                v => {
                    out.insert(key, v.clone());
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    if let Ok(Value::Object(m)) = serde_json::to_value(cfg) {
        walk("", &m, &mut out);
    }
    out
}

#[cfg(test)]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use figment::Jail;

    use super::*;

    /// Fields that hold a secret and serialize through `redact`.
    const SECRETS: [&str; 4] = [
        "admin.token",
        "admin.oidc.client_secret",
        "challenge.secret",
        "store.url",
    ];
    /// Names that look secret but are not (`tls.key` is a path).
    const NOT_SECRET: [&str; 3] = ["admin.public_url", "store.max_keys", "tls.key"];

    fn load(toml: &str) -> Config {
        let mut out = None;
        Jail::expect_with(|j| {
            j.create_file("d.toml", toml)?;
            out = Some(super::super::load(Some("d.toml".as_ref())).map_err(|e| e.to_string())?);
            Ok(())
        });
        out.unwrap()
    }

    // RFC 0021 case 2: a new secret-like key fails here until it is
    // listed as a secret (and redacted) or as not secret
    #[test]
    fn every_secret_like_key_is_listed() {
        let looks_secret = ["token", "secret", "password", "url", "key", "credential"];
        for k in flat(&defaults()).keys() {
            let last = k.rsplit('.').next().unwrap_or(k);
            if looks_secret.iter().any(|w| last.contains(w)) {
                assert!(
                    SECRETS.contains(&k.as_str()) || NOT_SECRET.contains(&k.as_str()),
                    "{k} looks secret: add it to SECRETS (and redact it) or NOT_SECRET"
                );
            }
        }
    }

    // RFC 0021 case 2: the listed secrets never serialize their value
    #[test]
    fn secrets_are_redacted() {
        let mut c = defaults();
        c.admin.token = "marker-token".into();
        c.admin.oidc.client_secret = "marker-client".into();
        c.challenge.secret = "marker-challenge".into();
        // built so the secret scanner does not flag a fixture
        c.store.url = Some(format!("redis://:{}@192.0.2.1:6379/0", "marker-store"));
        let body = serde_json::to_string(&view(&c, &c)).unwrap();
        assert!(!body.contains("marker"), "{body}");
        let f = flat(&c);
        for k in SECRETS {
            assert_eq!(f[k], REDACTED, "{k}");
        }
        let empty = flat(&defaults());
        assert_eq!(empty["admin.token"], "");
        assert_eq!(empty["store.url"], Value::Null);
    }

    // RFC 0021 case 4
    #[test]
    fn round_trips_through_toml() {
        let c = load(
            "upstream = \"http://127.0.0.1:8081\"\nconfig_watch = \"2s\"\n[rate_limit]\nrate = 5\n[detection]\nwindow = \"1500ms\"\n[l4]\nidle_timeout = \"2m\"\n",
        );
        let text = toml::to_string(&c).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), c, "{text}");
    }

    #[test]
    fn durations_use_the_largest_exact_unit() {
        let d = |ms| duration(Duration::from_millis(ms));
        assert_eq!(d(250), "250ms");
        assert_eq!(d(1500), "1500ms");
        assert_eq!(d(2000), "2s");
        assert_eq!(d(120_000), "2m");
        assert_eq!(d(86_400_000), "24h");
        assert_eq!(d(0), "0ms");
    }

    // RFC 0021 case 3 (flags; the environment part is in tests/admin.rs)
    #[test]
    fn keys_marked_reload_restart_and_default() {
        let start = load("upstream = \"http://127.0.0.1:8081\"\n");
        let cur = load(
            "upstream = \"http://127.0.0.1:8081\"\nlisten = \"127.0.0.1:9999\"\n[rate_limit]\nrate = 50\n",
        );
        let v = view(&start, &cur);
        let key = |k: &str| {
            v["keys"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["key"] == k)
                .unwrap_or_else(|| panic!("{k}"))
                .clone()
        };
        let rate = key("rate_limit.rate");
        assert_eq!(
            (
                rate["value"].clone(),
                rate["reload"].clone(),
                rate["default"].clone()
            ),
            (json!(50), json!(true), json!(false))
        );
        // a restart key shows what the process runs
        let listen = key("listen");
        assert_eq!(listen["value"], "0.0.0.0:8080");
        assert_eq!(listen["reload"], false);
        assert_eq!(listen["default"], true);
        assert_eq!(key("detection.mode")["reload"], true);
        assert_eq!(key("detection.window")["reload"], false);
        assert_eq!(key("waf.mode")["reload"], true);
    }
}
