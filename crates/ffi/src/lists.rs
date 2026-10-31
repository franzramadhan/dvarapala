//! RFC 0028: the list-shaped keys, `routes` and `forward.destinations`, as
//! JSON arrays with the `CONFIG.md` field names.

use std::collections::HashSet;
use std::num::NonZeroUsize;

use dvarapala_engine::{
    Cidr, Host, Limit, Matcher, PathMatch, RouteKey, Schedule, ScheduleConfig, parse_method,
    strip_port,
};
use serde::Deserialize;
use serde_json::Value;

use crate::config::duration;

/// One route, validated.
#[derive(Debug, Clone)]
pub(crate) struct RouteSpec {
    pub(crate) name: String,
    pub(crate) matcher: Matcher,
    pub(crate) deny: bool,
    pub(crate) limit: Option<Limit>,
    pub(crate) key: RouteKey,
    pub(crate) max_keys: NonZeroUsize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    name: String,
    host: Option<String>,
    path: Option<String>,
    #[serde(default)]
    methods: Vec<String>,
    #[serde(default)]
    clients: Vec<String>,
    #[serde(default)]
    deny: bool,
    #[serde(default)]
    rate: u32,
    #[serde(default)]
    burst: u32,
    key: Option<String>,
    max_keys: Option<usize>,
    // refused in process: read only to name them in the error
    challenge: Option<Value>,
    waf: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destination {
    origin: String,
    name: Option<String>,
    rate: f64,
    burst: Option<u32>,
    max_queue: Option<usize>,
    max_wait: Option<String>,
    max_pause: Option<String>,
    max_concurrent: Option<Value>,
}

/// `routes`: the gateway's checks, and the fields that need the gateway.
pub(crate) fn routes(json: &str) -> Result<Vec<RouteSpec>, String> {
    let list: Vec<Route> = serde_json::from_str(json).map_err(|e| format!("routes: {e}"))?;
    let mut names = HashSet::new();
    list.into_iter()
        .map(|r| {
            let err = |key: &str, e: String| format!("routes {:?}: {key}: {e}", r.name);
            if r.name.is_empty() {
                return Err("routes: every route needs a name".into());
            }
            if !names.insert(r.name.clone()) {
                return Err(err("name", "used by another route".into()));
            }
            let no_page = "does not apply in process (no challenge page or WAF)";
            if r.challenge.is_some() {
                return Err(err("challenge", no_page.into()));
            }
            if r.waf.is_some() {
                return Err(err("waf", no_page.into()));
            }
            let key =
                RouteKey::parse(r.key.as_deref().unwrap_or("client")).map_err(|e| err("key", e))?;
            if key == RouteKey::Ja4 {
                return Err(err(
                    "key",
                    "\"ja4\" needs the gateway's TLS listener".into(),
                ));
            }
            let limit = match r.rate {
                0 => None,
                rate => Some(
                    Limit::new(rate, if r.burst == 0 { rate } else { r.burst })
                        .map_err(|e| err("rate", e.to_string()))?,
                ),
            };
            let matcher = Matcher {
                host: r
                    .host
                    .as_deref()
                    .map(Host::parse)
                    .transpose()
                    .map_err(|e| err("host", e))?,
                path: (r.path.as_deref().map(PathMatch::parse).transpose())
                    .map_err(|e| err("path", e))?,
                methods: (r
                    .methods
                    .iter()
                    .map(|m| parse_method(m))
                    .collect::<Result<_, _>>())
                .map_err(|e| err("methods", e))?,
                clients: (r
                    .clients
                    .iter()
                    .map(|c| c.parse::<Cidr>())
                    .collect::<Result<_, _>>())
                .map_err(|e: dvarapala_engine::CidrError| err("clients", e.to_string()))?,
            };
            Ok(RouteSpec {
                matcher,
                deny: r.deny,
                limit,
                key,
                max_keys: NonZeroUsize::new(r.max_keys.unwrap_or(10_000))
                    .ok_or_else(|| err("max_keys", "must be above 0".into()))?,
                name: r.name,
            })
        })
        .collect()
}

/// `forward.destinations`: each destination's name and schedule.
pub(crate) fn destinations(json: &str) -> Result<Vec<(String, ScheduleConfig)>, String> {
    let k = "forward.destinations";
    let list: Vec<Destination> = serde_json::from_str(json).map_err(|e| format!("{k}: {e}"))?;
    let mut names = HashSet::new();
    list.into_iter()
        .map(|d| {
            let name = d.name.clone().unwrap_or_else(|| host(&d.origin));
            let err = |key: &str, e: String| format!("{k} {name:?}: {key}: {e}");
            if d.max_concurrent.is_some() {
                return Err(err(
                    "max_concurrent",
                    "does not apply in process; hold a semaphore of your language \
                     (a Go channel, asyncio.Semaphore) around the call instead"
                        .into(),
                ));
            }
            if name.is_empty() || !names.insert(name.clone()) {
                return Err(err("name", "empty or used by another destination".into()));
            }
            let time = |key: &str, v: Option<String>, default: &str| {
                duration(key, v.as_deref().unwrap_or(default)).map_err(|e| err(key, e))
            };
            let c = ScheduleConfig {
                rate: d.rate,
                burst: d.burst.unwrap_or(1),
                max_queue: d.max_queue.unwrap_or(100),
                max_wait: time("max_wait", d.max_wait, "2s")?,
                max_pause: time("max_pause", d.max_pause, "60s")?,
            };
            Schedule::new(c).map_err(|e| err("rate", e.0))?;
            Ok((name, c))
        })
        .collect()
}

/// The host of `origin` (`scheme://host[:port]/...`), as the gateway names
/// a destination without `name`.
fn host(origin: &str) -> String {
    let rest = origin.split_once("://").map_or(origin, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let h = strip_port(authority.as_bytes());
    String::from_utf8_lossy(h).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_name_is_the_host() {
        assert_eq!(host("https://api.example.com:8443/v1"), "api.example.com");
        assert_eq!(host("http://[2001:db8::1]:80"), "[2001:db8::1]");
        let d = destinations(r#"[{"origin": "https://api.example.com", "rate": 5}]"#).unwrap();
        assert_eq!(d[0].0, "api.example.com");
        assert_eq!(d[0].1.max_queue, 100);
    }

    #[test]
    fn bad_lists_name_the_entry_and_field() {
        let e = routes(r#"[{"name": "a", "path": "x"}]"#).unwrap_err();
        assert!(e.contains("\"a\": path"), "{e}");
        let e = routes(r#"[{"name": "a"}, {"name": "a"}]"#).unwrap_err();
        assert!(e.contains("\"a\": name"), "{e}");
        let e = routes(r#"[{"name": "a", "colour": 1}]"#).unwrap_err();
        assert!(e.contains("colour"), "{e}");
        let e = destinations(r#"[{"origin": "https://x.example", "rate": 0}]"#).unwrap_err();
        assert!(e.contains("\"x.example\": rate"), "{e}");
    }
}
