//! Redacted samples of requests that hit a trigger, handed to
//! the binary's queue without waiting. Nothing here changes a verdict.

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use dvarapala_engine::{Admit, ClientKey, Features, Gate};
use http::header::{AUTHORIZATION, COOKIE, HOST, HeaderMap, HeaderName, PROXY_AUTHORIZATION};
use http::request::Parts;
use http::{Method, Request, Uri};

use crate::Ja4;

/// Longest path, query included, in a sample.
pub const MAX_PATH: usize = 512;
/// Longest header value in a sample.
const MAX_HEADER: usize = 512;

/// What makes a request a candidate.
#[derive(Debug, Clone, PartialEq)]
pub enum On {
    /// A WAF `block` or `would_block`.
    Waf,
    ChallengeFailed,
    /// Detection in `Attack`.
    Attack,
    /// An `[ml]` score in `[low, high]`.
    MlBand(f64, f64),
    /// The named route.
    Route(String),
}

impl On {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Waf => "waf",
            Self::ChallengeFailed => "challenge_failed",
            Self::Attack => "attack",
            Self::MlBand(..) => "ml_band",
            Self::Route(_) => "route",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Trigger {
    pub on: On,
    /// Share of candidates sampled, in (0, 1].
    pub rate: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LlmConfig {
    pub triggers: Vec<Trigger>,
    pub per_client: Duration,
    /// Request headers sent, by name.
    pub headers: Vec<HeaderName>,
    /// Body bytes sent; only the WAF stage has the body.
    pub body_bytes: usize,
    /// Dedupe table size.
    pub max_clients: usize,
    /// Sample from start.
    pub enabled: bool,
}

/// One redacted request: no client address, no cookies, no credentials,
/// query values replaced by `_`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Sample {
    pub trigger: &'static str,
    /// `""` without a route.
    pub route: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// The client's `[ml]` features, when a model scores.
    pub features: Option<Features>,
    pub score: Option<f64>,
    /// WAF rule IDs, comma separated.
    pub rules: String,
    pub ja4: String,
    pub body: String,
}

/// Takes a sample; `false` when the queue is full.
pub type Sink = Box<dyn Fn(Sample) -> bool + Send + Sync>;

/// The sampler: the switch, the gate and the queue.
pub struct Llm {
    cfg: LlmConfig,
    on: AtomicBool,
    gate: Mutex<Gate>,
    sink: Sink,
    dice: (RandomState, AtomicU64),
    now: fn() -> Instant,
}

impl Llm {
    pub fn new(cfg: LlmConfig, sink: Sink, now: fn() -> Instant) -> Self {
        let rates = cfg.triggers.iter().map(|t| t.rate).collect();
        Self {
            gate: Mutex::new(Gate::new(rates, cfg.per_client, cfg.max_clients)),
            on: AtomicBool::new(cfg.enabled),
            cfg,
            sink,
            dice: (RandomState::new(), AtomicU64::new(0)),
            now,
        }
    }

    pub fn sampling(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    pub fn set(&self, on: bool) {
        self.on.store(on, Ordering::Relaxed);
        metrics::gauge!("dvarapala_llm_sampling").set(if on { 1.0 } else { 0.0 });
    }

    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Offers the request to every trigger `hit` accepts.
    fn offer(&self, key: ClientKey, hit: impl Fn(&On) -> bool, build: impl Fn(&On) -> Sample) {
        for (i, t) in self.cfg.triggers.iter().enumerate() {
            if !hit(&t.on) {
                continue;
            }
            let (seed, n) = &self.dice;
            let roll = (seed.hash_one(n.fetch_add(1, Ordering::Relaxed)) >> 11) as f64
                / (1u64 << 53) as f64;
            let admit = self
                .gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .admit(i, key, (self.now)(), roll);
            let result = match admit {
                Admit::Sent if !(self.sink)(build(&t.on)) => "dropped",
                a => a.name(),
            };
            metrics::counter!(
                "dvarapala_llm_samples_total",
                "trigger" => t.on.name(),
                "result" => result
            )
            .increment(1);
        }
    }
}

/// What the rate limiter knew about one request, carried to the WAF stage
/// in the request's extensions while sampling is on.
#[derive(Clone)]
pub struct Probe {
    pub(crate) llm: Arc<Llm>,
    pub(crate) key: ClientKey,
    pub(crate) route: String,
    pub(crate) attack: bool,
    pub(crate) scored: Option<(f64, Features)>,
    pub(crate) ja4: String,
}

/// Detection in `Attack`, and the `[ml]` score with its features.
pub(crate) type Seen = (bool, Option<(f64, Features)>);

impl Probe {
    /// A probe while `llm` samples.
    pub(crate) fn new(
        llm: Option<&Arc<Llm>>,
        key: ClientKey,
        route: Option<&str>,
        (attack, scored): Seen,
        ja4: Option<Ja4>,
    ) -> Option<Self> {
        let llm = llm.filter(|l| l.sampling())?.clone();
        Some(Self {
            llm,
            key,
            route: route.unwrap_or("").to_owned(),
            attack,
            scored,
            ja4: ja4.map_or_else(String::new, |f| f.to_string()),
        })
    }

    /// The triggers the rate limiter sees: attack, ml_band, route.
    pub(crate) fn limiter<B>(&self, r: &Request<B>) {
        let h = Head(r.method(), r.uri(), r.headers());
        let score = self.scored.map(|s| s.0);
        let hit = |on: &On| match on {
            On::Attack => self.attack,
            On::MlBand(lo, hi) => score.is_some_and(|s| (*lo..=*hi).contains(&s)),
            On::Route(r) => *r == self.route,
            On::Waf | On::ChallengeFailed => false,
        };
        self.llm
            .offer(self.key, hit, |on| self.sample(on, &h, "", b""));
    }

    pub(crate) fn challenge_failed<B>(&self, r: &Request<B>) {
        let h = Head(r.method(), r.uri(), r.headers());
        self.llm.offer(
            self.key,
            |on| *on == On::ChallengeFailed,
            |on| self.sample(on, &h, "", b""),
        );
    }

    /// A WAF match with its rule IDs and the buffered body.
    pub fn waf(&self, p: &Parts, rules: &str, body: &[u8]) {
        let h = Head(&p.method, &p.uri, &p.headers);
        self.llm.offer(
            self.key,
            |on| *on == On::Waf,
            |on| self.sample(on, &h, rules, body),
        );
    }

    fn sample(&self, on: &On, h: &Head<'_>, rules: &str, body: &[u8]) -> Sample {
        let cfg = &self.llm.cfg;
        let Head(method, uri, map) = *h;
        let headers = cfg
            .headers
            .iter()
            // credentials never leave, allowlisted or not
            .filter(|n| ![COOKIE, AUTHORIZATION, PROXY_AUTHORIZATION].contains(n))
            .filter_map(|n| {
                let v = map.get(n)?;
                Some((
                    n.as_str().to_owned(),
                    cut(&String::from_utf8_lossy(v.as_bytes()), MAX_HEADER).to_owned(),
                ))
            })
            .collect();
        let host = uri
            .host()
            .or_else(|| map.get(HOST)?.to_str().ok())
            .unwrap_or("");
        let body = &body[..body.len().min(cfg.body_bytes)];
        Sample {
            trigger: on.name(),
            route: self.route.clone(),
            method: method.as_str().to_owned(),
            host: cut(host, MAX_HEADER).to_owned(),
            path: redact(uri.path(), uri.query()),
            headers,
            features: self.scored.map(|s| s.1),
            score: self.scored.map(|s| s.0),
            rules: rules.to_owned(),
            ja4: self.ja4.clone(),
            body: String::from_utf8_lossy(body).into_owned(),
        }
    }
}

/// The request line and headers, from a request or its parts.
#[derive(Clone, Copy)]
struct Head<'a>(&'a Method, &'a Uri, &'a HeaderMap);

/// The path with the query's keys only (`?a=_&b=_`), cut to `MAX_PATH`.
pub fn redact(path: &str, query: Option<&str>) -> String {
    let mut s = path.to_owned();
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        for (i, kv) in q.split('&').enumerate() {
            s.push(if i == 0 { '?' } else { '&' });
            s.push_str(kv.split('=').next().unwrap_or(""));
            s.push_str("=_");
        }
    }
    cut(&s, MAX_PATH).to_owned()
}

/// `s` cut to at most `max` bytes on a character boundary.
pub fn cut(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use http::Request;

    use super::*;

    fn llm(enabled: bool, out: Arc<Mutex<Vec<Sample>>>) -> Arc<Llm> {
        let cfg = LlmConfig {
            triggers: vec![
                Trigger {
                    on: On::Waf,
                    rate: 1.0,
                },
                Trigger {
                    on: On::Route("login".into()),
                    rate: 1.0,
                },
            ],
            per_client: Duration::from_secs(600),
            headers: vec![http::header::USER_AGENT, http::header::COOKIE],
            body_bytes: 0,
            max_clients: 100,
            enabled,
        };
        let sink: Sink = Box::new(move |s| {
            out.lock().unwrap().push(s);
            true
        });
        Arc::new(Llm::new(cfg, sink, Instant::now))
    }

    fn probe(llm: Arc<Llm>, route: &str) -> Probe {
        Probe {
            llm,
            key: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)).into(),
            route: route.into(),
            attack: false,
            scored: None,
            ja4: String::new(),
        }
    }

    fn parts() -> Parts {
        Request::post("/login?token=abc&x")
            .header("host", "example.test")
            .header("user-agent", "curl/8")
            .header("cookie", "sid=secret")
            .header("authorization", "Bearer secret")
            .body(())
            .unwrap()
            .into_parts()
            .0
    }

    // RFC 0023 case 1: off, nothing reaches the queue
    #[test]
    fn off_sends_nothing() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let p = probe(llm(false, out.clone()), "login");
        // the rate limiter only builds a probe while sampling
        assert!(!p.llm.sampling());
        p.llm.set(true);
        p.waf(&parts(), "942100", b"");
        assert_eq!(out.lock().unwrap().len(), 1);
    }

    // RFC 0023 case 6, the sample itself
    #[test]
    fn samples_are_redacted() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let p = probe(llm(true, out.clone()), "login");
        p.waf(&parts(), "942100", b"password=hunter2");
        p.limiter(&Request::from_parts(parts(), ()));
        let got = out.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        let s = &got[0];
        assert_eq!(
            (
                s.trigger,
                s.path.as_str(),
                s.rules.as_str(),
                s.body.as_str()
            ),
            ("waf", "/login?token=_&x=_", "942100", "")
        );
        assert_eq!(s.host, "example.test");
        // the cookie header is allowlisted here, and still never sent
        assert_eq!(s.headers, vec![("user-agent".into(), "curl/8".into())]);
        assert_eq!(got[1].trigger, "route");
    }

    #[test]
    fn cut_and_redact_bound_the_path() {
        assert_eq!(cut("aé", 2), "a");
        assert_eq!(redact("/", Some("")), "/");
        let long = redact(&"/a".repeat(400), Some("k=v"));
        assert_eq!(long.len(), MAX_PATH);
    }
}
