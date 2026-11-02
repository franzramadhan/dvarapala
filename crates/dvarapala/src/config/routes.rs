//! The `[[routes]]` list (RFC 0013).

use std::collections::HashSet;
use std::num::NonZeroUsize;

use dvarapala_engine::{Cidr, Limit, parse_country, parse_method};
use dvarapala_l7::{Host, Matcher, PathMatch, RouteConfig, RouteKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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
    /// `false` skips the WAF (RFC 0017).
    #[serde(default = "yes")]
    pub waf: bool,
    /// `false` bypasses the upstream concurrency limit (RFC 0032).
    #[serde(default = "yes")]
    pub concurrency: bool,
    /// Slots a request takes in that limit, 1 to 100.
    #[serde(default = "one")]
    pub concurrency_weight: u32,
    /// RFC 0031: ISO 3166-1 alpha-2 codes, from `intel.geoip`.
    #[serde(default)]
    pub country: Vec<String>,
    #[serde(default)]
    pub asn: Vec<u32>,
    /// `[[intel.feed]]` names, in enforce mode.
    #[serde(default)]
    pub feeds: Vec<String>,
}

fn client() -> String {
    "client".into()
}

fn yes() -> bool {
    true
}

fn one() -> u32 {
    1
}

fn max_keys() -> usize {
    10_000
}

/// The layer's routes, in order. Errors name the route and the key.
pub fn routes(routes: &[Route], intel: &super::Intel) -> Result<Vec<RouteConfig>, String> {
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
                .map(|m| parse_method(m))
                .collect::<Result<Vec<_>, _>>();
            let clients = r
                .clients
                .iter()
                .map(|c| c.parse::<Cidr>())
                .collect::<Result<Vec<_>, _>>();
            let countries = r
                .country
                .iter()
                .map(|c| parse_country(c))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| err("country", e))?;
            if intel.geoip.is_none() {
                if !r.country.is_empty() {
                    return Err(err("country", "needs intel.geoip".into()));
                }
                if !r.asn.is_empty() {
                    return Err(err("asn", "needs intel.geoip".into()));
                }
            }
            let feeds = r.feeds.iter().try_fold(0u64, |bits, name| {
                let bit = intel
                    .bit(name)
                    .ok_or_else(|| err("feeds", format!("no [[intel.feed]] named {name:?}")))?;
                Ok::<_, String>(bits | 1 << bit)
            })?;
            if !(1..=100).contains(&r.concurrency_weight) {
                return Err(err("concurrency_weight", "must be 1 to 100".into()));
            }
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
                    methods: methods.map_err(|e| err("methods", e))?,
                    clients: clients.map_err(|e| err("clients", e.0))?,
                    countries,
                    asns: r.asn.clone(),
                    feeds,
                },
                deny: r.deny,
                limit,
                key: RouteKey::parse(&r.key).map_err(|e| err("key", e))?,
                challenge: r.challenge,
                max_keys: NonZeroUsize::new(r.max_keys)
                    .ok_or_else(|| err("max_keys", "must be above 0".into()))?,
                waf: r.waf,
                concurrency: if r.concurrency {
                    r.concurrency_weight
                } else {
                    0
                },
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
            waf: true,
            concurrency: true,
            concurrency_weight: 1,
            country: Vec::new(),
            asn: Vec::new(),
            feeds: Vec::new(),
        }
    }

    fn none() -> super::super::Intel {
        super::super::Intel::default()
    }

    // RFC 0013 case 11
    #[test]
    fn bad_routes_name_the_route_and_key() {
        let err = |f: fn(&mut Route)| {
            let mut r = route("api");
            f(&mut r);
            routes(&[r], &none()).unwrap_err()
        };
        let dup = routes(&[route("api"), route("api")], &none()).unwrap_err();
        assert!(dup.contains("\"api\": name"), "{dup}");
        let e = err(|r| r.clients = vec!["192.0.2.0/33".into()]);
        assert!(e.contains("\"api\": clients"), "{e}");
        let e = err(|r| r.key = "header:".into());
        assert!(e.contains("\"api\": key"), "{e}");
        let e = err(|r| r.path = Some("api".into()));
        assert!(e.contains("\"api\": path"), "{e}");
        let e = err(|r| r.max_keys = 0);
        assert!(e.contains("\"api\": max_keys"), "{e}");
        assert!(routes(&[route("")], &none()).unwrap_err().contains("name"));
        let e = err(|r| r.concurrency_weight = 101);
        assert!(e.contains("\"api\": concurrency_weight"), "{e}");
    }

    // RFC 0032 cases 10 and 11
    #[test]
    fn concurrency_false_bypasses_the_weight_counts_otherwise() {
        let mut r = route("export");
        r.concurrency_weight = 10;
        assert_eq!(routes(&[r.clone()], &none()).unwrap()[0].concurrency, 10);
        r.concurrency = false;
        assert_eq!(routes(&[r], &none()).unwrap()[0].concurrency, 0);
    }

    #[test]
    fn burst_defaults_to_rate() {
        let mut r = route("login");
        r.rate = 5;
        r.methods = vec!["post".into()];
        let c = routes(&[r], &none()).unwrap();
        assert_eq!(c[0].limit, Some(Limit::new(5, 5).unwrap()));
        assert_eq!(c[0].matcher.methods, vec!["POST"]);
    }

    // RFC 0031 case 11
    #[test]
    fn country_and_asn_need_the_database_feeds_a_known_name() {
        let mut r = route("eu");
        r.country = vec!["zz".into()];
        let e = routes(&[r.clone()], &none()).unwrap_err();
        assert!(e.contains("\"eu\": country: needs intel.geoip"), "{e}");
        let geo = super::super::Intel {
            geoip: Some("geo.mmdb".into()),
            feed: vec![
                toml::from_str("name = \"tor\"\npath = \"tor.txt\"\naction = \"tag\"").unwrap(),
            ],
            ..none()
        };
        r.feeds = vec!["tor".into()];
        let c = routes(&[r.clone()], &geo).unwrap();
        assert_eq!(c[0].matcher.countries, vec![*b"ZZ"]);
        assert_eq!(c[0].matcher.feeds, 1);
        r.country.clear();
        r.asn = vec![64500];
        let e = routes(&[r.clone()], &none()).unwrap_err();
        assert!(e.contains("\"eu\": asn"), "{e}");
        r.feeds = vec!["nope".into()];
        let e = routes(&[r], &geo).unwrap_err();
        assert!(e.contains("\"eu\": feeds"), "{e}");
    }
}
