//! The `[[routes]]` list (RFC 0013).

use std::collections::HashSet;
use std::num::NonZeroUsize;

use dvarapala_engine::{Cidr, Limit};
use dvarapala_l7::{Host, Matcher, PathMatch, RouteConfig, RouteKey};
use http::Method;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub clients: Vec<String>,
    #[serde(default)]
    pub deny: bool,
    /// `0` adds no bucket.
    #[serde(default)]
    pub rate: u32,
    /// `0` means `rate`.
    #[serde(default)]
    pub burst: u32,
    #[serde(default = "client")]
    pub key: String,
    #[serde(default = "yes")]
    pub challenge: bool,
    #[serde(default = "max_keys")]
    pub max_keys: usize,
}

fn client() -> String {
    "client".into()
}

fn yes() -> bool {
    true
}

fn max_keys() -> usize {
    10_000
}

/// The layer's routes, in order. Errors name the route and the key.
pub fn routes(routes: &[Route]) -> Result<Vec<RouteConfig>, String> {
    let mut names = HashSet::new();
    routes
        .iter()
        .map(|r| {
            let err = |key: &str, e: String| format!("routes {:?}: {key}: {e}", r.name);
            if r.name.is_empty() {
                return Err("routes: every route needs a name".into());
            }
            if !names.insert(r.name.as_str()) {
                return Err(err("name", "used by another route".into()));
            }
            let host = r.host.as_deref().map(Host::parse).transpose();
            let path = r.path.as_deref().map(PathMatch::parse).transpose();
            let methods = r
                .methods
                .iter()
                .map(|m| Method::from_bytes(m.to_ascii_uppercase().as_bytes()))
                .collect::<Result<Vec<_>, _>>();
            let clients = r
                .clients
                .iter()
                .map(|c| c.parse::<Cidr>())
                .collect::<Result<Vec<_>, _>>();
            let limit = match r.rate {
                0 => None,
                rate => Some(
                    Limit::new(rate, if r.burst == 0 { rate } else { r.burst })
                        .map_err(|e| err("rate", e.to_string()))?,
                ),
            };
            Ok(RouteConfig {
                name: r.name.clone(),
                matcher: Matcher {
                    host: host.map_err(|e| err("host", e))?,
                    path: path.map_err(|e| err("path", e))?,
                    methods: methods.map_err(|e| err("methods", e.to_string()))?,
                    clients: clients.map_err(|e| err("clients", e.0))?,
                },
                deny: r.deny,
                limit,
                key: RouteKey::parse(&r.key).map_err(|e| err("key", e))?,
                challenge: r.challenge,
                max_keys: NonZeroUsize::new(r.max_keys)
                    .ok_or_else(|| err("max_keys", "must be above 0".into()))?,
                waf: true,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(name: &str) -> Route {
        Route {
            name: name.into(),
            host: None,
            path: Some("/".into()),
            methods: Vec::new(),
            clients: Vec::new(),
            deny: false,
            rate: 0,
            burst: 0,
            key: client(),
            challenge: true,
            max_keys: max_keys(),
        }
    }

    // RFC 0013 case 11
    #[test]
    fn bad_routes_name_the_route_and_key() {
        let err = |f: fn(&mut Route)| {
            let mut r = route("api");
            f(&mut r);
            routes(&[r]).unwrap_err()
        };
        let dup = routes(&[route("api"), route("api")]).unwrap_err();
        assert!(dup.contains("\"api\": name"), "{dup}");
        let e = err(|r| r.clients = vec!["192.0.2.0/33".into()]);
        assert!(e.contains("\"api\": clients"), "{e}");
        let e = err(|r| r.key = "header:".into());
        assert!(e.contains("\"api\": key"), "{e}");
        let e = err(|r| r.path = Some("api".into()));
        assert!(e.contains("\"api\": path"), "{e}");
        let e = err(|r| r.max_keys = 0);
        assert!(e.contains("\"api\": max_keys"), "{e}");
        assert!(routes(&[route("")]).unwrap_err().contains("name"));
    }

    #[test]
    fn burst_defaults_to_rate() {
        let mut r = route("login");
        r.rate = 5;
        r.methods = vec!["post".into()];
        let c = routes(&[r]).unwrap();
        assert_eq!(c[0].limit, Some(Limit::new(5, 5).unwrap()));
        assert_eq!(c[0].matcher.methods, vec![Method::POST]);
    }
}
