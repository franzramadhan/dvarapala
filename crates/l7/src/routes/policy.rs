use std::num::NonZeroUsize;
use std::time::Instant;

use dvarapala_engine::{ClientKey, Limit, Verdict};
use http::Request;

use super::limits::{Limits, RouteKey};
use super::matcher::Matcher;
use crate::Ja4;

/// One `[[routes]]` entry (RFC 0013).
#[derive(Debug, Clone)]
pub struct RouteConfig {
    /// The `route` label in metrics.
    pub name: String,
    pub matcher: Matcher,
    /// `403` before any bucket.
    pub deny: bool,
    /// A second bucket on top of the global one; `None` adds none.
    pub limit: Option<Limit>,
    pub key: RouteKey,
    /// `false` exempts the route from the challenge.
    pub challenge: bool,
    pub max_keys: NonZeroUsize,
}

/// The routes in order; the first that matches applies.
#[derive(Default)]
pub struct Routes(Vec<Route>);

pub(crate) struct Route {
    name: String,
    matcher: Matcher,
    pub(crate) deny: bool,
    pub(crate) challenge: bool,
    limits: Option<Limits>,
}

impl Routes {
    pub fn new(routes: Vec<RouteConfig>) -> Self {
        Self(
            routes
                .into_iter()
                .map(|r| Route {
                    limits: r.limit.map(|l| Limits::new(l, r.key, r.max_keys)),
                    name: r.name,
                    matcher: r.matcher,
                    deny: r.deny,
                    challenge: r.challenge,
                })
                .collect(),
        )
    }

    /// The name of the route `req` from `client` gets, if any.
    pub fn matching<B>(&self, req: &Request<B>, client: ClientKey) -> Option<&str> {
        self.find(req, client).map(|r| r.name.as_str())
    }

    /// The first route matching `req` from `client`.
    pub(crate) fn find<B>(&self, req: &Request<B>, client: ClientKey) -> Option<&Route> {
        let ip = client.into();
        // ponytail: linear scan, about 20 ns a route; an index by host or
        // path prefix if configs grow to hundreds of routes
        self.0.iter().find(|r| {
            r.matcher
                .matches(req.uri(), req.headers(), req.method(), ip)
        })
    }
}

impl Route {
    /// The route's own bucket; `Allow` when it has none.
    pub(crate) fn take<B>(
        &self,
        req: &Request<B>,
        client: ClientKey,
        ja4: Option<Ja4>,
        now: Instant,
    ) -> Verdict {
        let Some(l) = &self.limits else {
            return Verdict::Allow;
        };
        let (v, keys) = l.take(req.headers(), client, ja4, now);
        metrics::gauge!("dvarapala_route_keys", "route" => self.name.clone()).set(keys as f64);
        v
    }

    /// `allow`, `throttle` (the route's bucket) or `deny`.
    pub(crate) fn count(&self, verdict: &'static str) {
        metrics::counter!(
            "dvarapala_route_requests_total",
            "route" => self.name.clone(),
            "verdict" => verdict
        )
        .increment(1);
    }
}

#[doc(hidden)]
/// Fuzzing entry point: parse a host and a path rule, then match a request
/// built from the remaining bytes.
pub fn fuzz_route_match(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.splitn(4, '\n');
    let (Some(host), Some(path), Some(uri), Some(rest)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    let matcher = Matcher {
        host: super::Host::parse(host).ok(),
        path: super::PathMatch::parse(path).ok(),
        ..Matcher::default()
    };
    let Ok(req) = Request::builder()
        .uri(uri)
        .method(rest.split(' ').next().unwrap_or("GET"))
        .header(http::header::HOST, rest)
        .body(())
    else {
        return;
    };
    let routes = Routes::new(vec![RouteConfig {
        name: "fuzz".into(),
        matcher,
        deny: false,
        limit: None,
        key: RouteKey::Client,
        challenge: true,
        max_keys: NonZeroUsize::MIN,
    }]);
    let _ = routes.find(
        &req,
        ClientKey::from(std::net::IpAddr::from([192, 0, 2, 1])),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PathMatch;

    fn route(name: &str, path: &str) -> RouteConfig {
        RouteConfig {
            name: name.into(),
            matcher: Matcher {
                path: Some(PathMatch::parse(path).unwrap()),
                ..Matcher::default()
            },
            deny: false,
            limit: None,
            key: RouteKey::Client,
            challenge: true,
            max_keys: NonZeroUsize::new(10).unwrap(),
        }
    }

    // RFC 0013 case 1
    #[test]
    fn first_match_applies() {
        let routes = Routes::new(vec![route("login", "=/login"), route("rest", "/")]);
        let c = ClientKey::from(std::net::IpAddr::from([192, 0, 2, 1]));
        let name = |p: &str| {
            let r = Request::get(p).body(()).unwrap();
            routes.matching(&r, c).map(str::to_owned)
        };
        assert_eq!(name("/login").as_deref(), Some("login"));
        assert_eq!(name("/login/x").as_deref(), Some("rest"));
        assert_eq!(name("/a").as_deref(), Some("rest"));
        assert!(
            Routes::default()
                .find(&Request::get("/").body(()).unwrap(), c)
                .is_none()
        );
    }
}
