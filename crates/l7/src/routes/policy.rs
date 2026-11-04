use std::num::NonZeroUsize;
use std::time::Instant;

use dvarapala_engine::{
    ClientKey, Limit, Matcher, Origin, RouteKey, RouteLimits, Verdict, strip_port,
};
use http::Request;
use http::header::HOST;
use metrics::{Counter, Gauge};

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
    /// `false` skips the WAF (RFC 0017).
    pub waf: bool,
    /// Slots a request takes in the upstream concurrency limit (RFC
    /// 0032); 0 bypasses it.
    pub concurrency: u32,
}

/// RFC 0017: set on a request whose route skips the WAF.
#[derive(Debug, Clone, Copy)]
pub struct NoWaf;

/// The routes in order; the first that matches applies.
#[derive(Default)]
pub struct Routes(Vec<Route>);

pub(crate) struct Route {
    name: String,
    matcher: Matcher,
    pub(crate) deny: bool,
    pub(crate) challenge: bool,
    pub(crate) waf: bool,
    pub(crate) concurrency: u32,
    key: RouteKey,
    limits: Option<RouteLimits>,
    // handles made once: a lookup per request allocates the label
    keys: Gauge,
    allow: Counter,
    deny_count: Counter,
    throttle: Counter,
}

impl Routes {
    pub fn new(routes: Vec<RouteConfig>) -> Self {
        Self(
            routes
                .into_iter()
                .map(|r| Route {
                    // only a limited route exports the gauge
                    keys: if r.limit.is_some() {
                        metrics::gauge!("dvarapala_route_keys", "route" => r.name.clone())
                    } else {
                        Gauge::noop()
                    },
                    allow: requests(&r.name, "allow"),
                    deny_count: requests(&r.name, "deny"),
                    throttle: requests(&r.name, "throttle"),
                    limits: r.limit.map(|l| RouteLimits::new(l, r.max_keys)),
                    key: r.key,
                    name: r.name,
                    matcher: r.matcher,
                    deny: r.deny,
                    challenge: r.challenge,
                    waf: r.waf,
                    concurrency: r.concurrency,
                })
                .collect(),
        )
    }

    /// The name of the route `req` from `client` gets, if any.
    pub fn matching<B>(&self, req: &Request<B>, client: ClientKey) -> Option<&str> {
        self.find(req, client, &Origin::default())
            .map(|r| r.name.as_str())
    }

    /// The first route matching `req` from `client`, which comes from
    /// `origin` (RFC 0031).
    pub(crate) fn find<B>(
        &self,
        req: &Request<B>,
        client: ClientKey,
        origin: &Origin,
    ) -> Option<&Route> {
        let ip = client.into();
        // the URI's authority (HTTP/2, absolute form), else the Host header
        let host = match req.uri().host() {
            Some(h) => Some(h.as_bytes()),
            None => req.headers().get(HOST).map(|h| h.as_bytes()),
        }
        .map(strip_port);
        let (method, path) = (req.method().as_str(), req.uri().path());
        // ponytail: linear scan, about 20 ns a route; an index by host or
        // path prefix if configs grow to hundreds of routes
        self.0
            .iter()
            .find(|r| r.matcher.matches(method, host, path, ip) && r.matcher.matches_origin(origin))
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
        let value = match &self.key {
            RouteKey::Client => None,
            RouteKey::Header(h) => req.headers().get(h.as_str()).map(|v| v.as_bytes()),
            RouteKey::Ja4 => ja4.as_ref().map(|j| j.as_str().as_bytes()),
        };
        let (v, keys) = l.take(value, client, now);
        self.keys.set(keys as f64);
        v
    }

    /// `allow`, `throttle` (the route's bucket) or `deny`.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn count(&self, outcome: Outcome) {
        match outcome {
            Outcome::Allow => &self.allow,
            Outcome::Deny => &self.deny_count,
            Outcome::Throttle => &self.throttle,
        }
        .increment(1);
    }
}

/// The `verdict` label of `dvarapala_route_requests_total`.
#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Allow,
    Deny,
    Throttle,
}

fn requests(route: &str, verdict: &'static str) -> Counter {
    metrics::counter!(
        "dvarapala_route_requests_total",
        "route" => route.to_owned(),
        "verdict" => verdict
    )
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
        host: dvarapala_engine::Host::parse(host).ok(),
        path: dvarapala_engine::PathMatch::parse(path).ok(),
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
        waf: true,
        concurrency: 1,
    }]);
    let _ = routes.find(
        &req,
        ClientKey::from(std::net::IpAddr::from([192, 0, 2, 1])),
        &Origin::default(),
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use metrics::{
        Counter, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    use super::*;
    use crate::PathMatch;

    /// Keeps every series it registers with its value, and counts how often
    /// a handle is looked up in the registry.
    #[derive(Default)]
    struct Lookups {
        count: AtomicUsize,
        series: Mutex<BTreeMap<String, Arc<AtomicU64>>>,
    }

    impl Lookups {
        fn register(&self, key: &Key) -> Arc<AtomicU64> {
            self.count.fetch_add(1, Ordering::Relaxed);
            let labels: Vec<_> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let id = format!("{}{{{}}}", key.name(), labels.join(","));
            self.series.lock().unwrap().entry(id).or_default().clone()
        }

        /// Series name to value (a gauge's value is its `f64` bits).
        fn values(&self) -> Vec<(String, u64)> {
            let s = self.series.lock().unwrap();
            s.iter()
                .map(|(k, v)| (k.clone(), v.load(Ordering::Relaxed)))
                .collect()
        }
    }

    impl Recorder for Lookups {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, k: &Key, _: &Metadata<'_>) -> Counter {
            Counter::from_arc(self.register(k))
        }
        fn register_gauge(&self, k: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::from_arc(self.register(k))
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            self.count.fetch_add(1, Ordering::Relaxed);
            Histogram::noop()
        }
    }

    // issue 329: the exported series and values did not change
    #[test]
    fn route_series_and_values_are_unchanged() {
        let rec = Lookups::default();
        metrics::with_local_recorder(&rec, || {
            let routes = Routes::new(vec![RouteConfig {
                limit: Some(Limit::new(1, 1).unwrap()),
                ..route("login", "/")
            }]);
            let c = ClientKey::from(std::net::IpAddr::from([192, 0, 2, 1]));
            let req = Request::get("/").body(()).unwrap();
            let r = routes.find(&req, c, &Origin::default()).unwrap();
            r.take(&req, c, None, Instant::now());
            r.count(Outcome::Allow);
            r.count(Outcome::Deny);
            r.count(Outcome::Deny);
            r.count(Outcome::Throttle);
        });
        let req = |v| format!("dvarapala_route_requests_total{{route=login,verdict={v}}}");
        assert_eq!(
            rec.values(),
            vec![
                ("dvarapala_route_keys{route=login}".into(), 1f64.to_bits()),
                (req("allow"), 1),
                (req("deny"), 2),
                (req("throttle"), 1),
            ]
        );
    }

    // issue 329: the per-request path reuses handles made at construction
    #[test]
    fn route_metrics_are_not_looked_up_per_request() {
        let rec = Lookups::default();
        metrics::with_local_recorder(&rec, || {
            let routes = Routes::new(vec![RouteConfig {
                limit: Some(Limit::new(1, 1).unwrap()),
                ..route("login", "/")
            }]);
            let c = ClientKey::from(std::net::IpAddr::from([192, 0, 2, 1]));
            let req = Request::get("/").body(()).unwrap();
            let r = routes.find(&req, c, &Origin::default()).unwrap();
            let built = rec.count.load(Ordering::Relaxed);
            for _ in 0..5 {
                r.take(&req, c, None, Instant::now());
                for v in [Outcome::Allow, Outcome::Deny, Outcome::Throttle] {
                    r.count(v);
                }
            }
            assert_eq!(rec.count.load(Ordering::Relaxed), built);
        });
    }

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
            waf: true,
            concurrency: 1,
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
        // the authority of an absolute URI wins over the Host header
        let abs = Request::get("https://a.example.com./x")
            .header(HOST, "b.example.com")
            .body(())
            .unwrap();
        let host = Routes::new(vec![RouteConfig {
            matcher: Matcher {
                host: Some(crate::Host::parse("a.example.com").unwrap()),
                ..Matcher::default()
            },
            ..route("a", "/")
        }]);
        assert_eq!(host.matching(&abs, c), Some("a"));
        assert!(
            Routes::default()
                .find(&Request::get("/").body(()).unwrap(), c, &Origin::default())
                .is_none()
        );
    }
}
