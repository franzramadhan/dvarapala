//! The `[[routes]]` list (RFC 0013).
#![allow(unused_variables, unused_imports, dead_code)]

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
    todo!("rfc 0013")
}

fn yes() -> bool {
    todo!("rfc 0013")
}

fn max_keys() -> usize {
    todo!("rfc 0013")
}

/// The layer's routes, in order. Errors name the route and the key.
pub fn routes(routes: &[Route]) -> Result<Vec<RouteConfig>, String> {
    todo!("rfc 0013")
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
    #[ignore = "rfc 0013"]
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
    #[ignore = "rfc 0013"]
    fn burst_defaults_to_rate() {
        let mut r = route("login");
        r.rate = 5;
        r.methods = vec!["post".into()];
        let c = routes(&[r]).unwrap();
        assert_eq!(c[0].limit, Some(Limit::new(5, 5).unwrap()));
        assert_eq!(c[0].matcher.methods, vec![Method::POST]);
    }
}
