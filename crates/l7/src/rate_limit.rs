use std::borrow::Cow;
use std::future::Future;
use std::hash::RandomState;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use dvarapala_engine::{
    BlockSink, Blocks, ChallengeMode, ClientKey, ClientStats, Cluster, DetectError, Guard,
    GuardConfig, GuardDetection, Pass, State, TrustedProxies, Verdict, client_key,
};
use http::header::{ACCEPT, HeaderMap, SET_COOKIE};
use http::{Request, Response, StatusCode, Version};
use tower_layer::Layer;
use tower_service::Service;

use crate::challenge::{Challenge, VERIFY_PATH};
use crate::control::Policy;
use crate::detection::{ReqInfo, Watch};
use crate::fingerprint::Rule;
use crate::llm::{Llm, Probe, Seen};
use crate::reply::{Scope, count, reject};
use crate::{
    ChallengeConfig, Detection, Fingerprints, Ja4, PageBody, PeerAddr, RouteConfig, Routes,
    Scoring, is_grpc,
};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub limit: dvarapala_engine::Limit,
    pub max_clients: NonZeroUsize,
    pub trusted: TrustedProxies,
    /// RFC 0002 adaptive detection; `None` turns it off.
    pub detection: Option<Detection>,
    /// RFC 0002 scoring hook; `None` turns it off.
    pub scoring: Option<Scoring>,
    /// The clock. `Instant::now` outside tests.
    pub now: fn() -> Instant,
    /// RFC 0010 shared state; `None` keeps every limit local.
    pub cluster: Option<Arc<Mutex<Cluster>>>,
    /// RFC 0011: heavy hitters in enforce mode go to the XDP block list.
    pub block: Option<BlockSink>,
    /// RFC 0012 challenge; `None` turns it off.
    pub challenge: Option<ChallengeConfig>,
    /// RFC 0012 rules on the JA4 fingerprint.
    pub fingerprints: Fingerprints,
    /// RFC 0013 routes, in order; empty applies the global policy only.
    pub routes: Vec<RouteConfig>,
    /// RFC 0014: manual blocks at most.
    pub max_blocks: usize,
}

/// Per-client token bucket in front of a service. Over the limit, the
/// request gets `429 Too Many Requests` with `Retry-After` and never reaches
/// the inner service.
#[derive(Clone)]
pub struct RateLimitLayer {
    pub(crate) shared: Arc<Shared>,
}

pub(crate) struct Shared {
    // ponytail: one lock for the table and the detector; shard by key hash
    // if it shows up in profiles under load
    state: Mutex<Inner>,
    /// what a reload swaps (RFC 0014); read once per request
    pub(crate) policy: RwLock<Arc<Policy>>,
    /// RFC 0014 manual blocks
    pub(crate) blocks: RwLock<Blocks>,
    pub(crate) now: fn() -> Instant,
    scoring: Option<Scoring>,
    /// seeds the path hash of the distinct-paths feature
    paths: RandomState,
    cluster: Option<Arc<Mutex<Cluster>>>,
    /// how long a published heavy hitter stays listed in enforce mode;
    /// `None` without detection
    cooldown: Option<Duration>,
    pub(crate) block: Option<BlockSink>,
    /// RFC 0023, set once at start
    llm: OnceLock<Arc<Llm>>,
}

pub(crate) struct Inner {
    /// stats are boxed and only filled in when scoring is on, so the table
    /// grows by one pointer per client otherwise
    pub(crate) guard: Guard<Option<Box<ClientStats>>>,
    watch: Watch,
}

impl RateLimitLayer {
    /// Fails on a detection config the engine rejects.
    pub fn new(config: RateLimitConfig) -> Result<Self, DetectError> {
        let cooldown = config
            .detection
            .as_ref()
            .map(|d| d.detect.window * d.detect.cooldown_windows);
        let enforce = config.detection.as_ref().is_some_and(|d| d.enforce);
        let guard = Guard::new(GuardConfig {
            limit: config.limit,
            max_clients: config.max_clients,
            detection: config.detection.map(|d| GuardDetection {
                detect: d.detect,
                enforce: d.enforce,
                attack_rate_factor: d.attack_rate_factor,
            }),
            challenge: config
                .challenge
                .as_ref()
                .map_or(ChallengeMode::Off, |c| c.mode),
        })?;
        Ok(Self {
            shared: Arc::new(Shared {
                state: Mutex::new(Inner {
                    guard,
                    watch: Watch::default(),
                }),
                policy: RwLock::new(Arc::new(Policy {
                    trusted: config.trusted,
                    challenge: config.challenge.map(Challenge::new),
                    fingerprints: config.fingerprints,
                    routes: Arc::new(Routes::new(config.routes)),
                    enforce,
                })),
                blocks: RwLock::new(Blocks::new(config.max_blocks)),
                now: config.now,
                scoring: config.scoring,
                paths: RandomState::new(),
                cluster: config.cluster,
                cooldown,
                block: config.block,
                llm: OnceLock::new(),
            }),
        })
    }

    /// RFC 0023: samples requests that hit a trigger while `llm` samples.
    pub fn set_llm(&self, llm: Arc<Llm>) {
        let _ = self.shared.llm.set(llm);
    }

    /// Clients currently in the table.
    pub fn clients(&self) -> usize {
        self.shared.lock().guard.clients()
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimit<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimit {
            inner,
            shared: self.shared.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RateLimit<S> {
    inner: S,
    shared: Arc<Shared>,
}

impl<S, B, R> Service<Request<B>> for RateLimit<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    R: PageBody,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, R>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        let protocol = match req.version() {
            Version::HTTP_2 => "http2",
            Version::HTTP_3 => "http3",
            _ => "http1",
        };
        let Some(PeerAddr(peer)) = req.extensions().get::<PeerAddr>().copied() else {
            // fail closed: without a peer every client would share one key
            tracing::error!(msg = "request without PeerAddr, the server does not set it");
            count("error", protocol);
            let mut res = Response::new(R::default());
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return ResponseFuture::Rejected { res: Some(res) };
        };
        let policy = self.shared.policy();
        let key = client_key(
            peer.ip(),
            forwarded_for(req.headers()).as_deref(),
            &policy.trusted,
        );
        let grpc = is_grpc(req.headers());
        // RFC 0014: a manual block before anything else
        if self.shared.blocked(key) {
            let res = reject(Verdict::Drop, grpc, protocol, Scope::Block);
            return ResponseFuture::Rejected { res: Some(res) };
        }
        // RFC 0012: fingerprint rules, then the pass cookie
        let fp = req.extensions().get::<Ja4>().copied();
        let rule = policy.fingerprints.rule(fp);
        if rule == Rule::Deny {
            let res = reject(Verdict::Drop, grpc, protocol, Scope::Local);
            return ResponseFuture::Rejected { res: Some(res) };
        }
        // RFC 0013: a denied route costs one match, no token
        let route = policy.routes.find(&req, key);
        if let Some(r) = route.filter(|r| r.deny) {
            r.count("deny");
            let res = reject(Verdict::Drop, grpc, protocol, Scope::Local);
            return ResponseFuture::Rejected { res: Some(res) };
        }
        let challenge = policy.challenge.as_ref();
        let mut pass = challenge.map_or(Pass::Missing, |c| {
            c.pass(req.headers(), key, rule == Rule::Challenge)
        });
        if route.is_some_and(|r| !r.challenge) && pass != Pass::Valid {
            pass = Pass::Exempt;
        }
        let info = self
            .shared
            .scoring
            .as_ref()
            .map(|_| ReqInfo::of(&req, &self.shared.paths));
        let heavy_ttl = self.shared.cooldown.filter(|_| policy.enforce);
        let (mut verdict, scope, seen) = self.shared.take(key, info, pass, heavy_ttl);
        // the route's bucket on top of the global one: both must allow
        if let (Some(r), Verdict::Allow) = (route, verdict) {
            verdict = r.take(&req, key, fp, (self.shared.now)());
            if verdict != Verdict::Allow {
                r.count("throttle");
            }
        }
        // RFC 0023: off the path, never waits
        let probe = Probe::new(
            self.shared.llm.get(),
            key,
            route.map(|r| r.name()),
            seen,
            fp,
        );
        if let Some(p) = &probe {
            p.limiter(&req);
        }
        // the verify endpoint answers within the client's bucket
        if let (Some(c), Verdict::Allow | Verdict::Challenge) = (challenge, verdict)
            && req.uri().path() == VERIFY_PATH
        {
            count("allow", protocol);
            let res: Response<R> = c.verify(req.uri().query(), key);
            if let Some(p) = probe.filter(|_| !res.headers().contains_key(SET_COOKIE)) {
                p.challenge_failed(&req);
            }
            return ResponseFuture::Rejected { res: Some(res) };
        }
        match verdict {
            Verdict::Challenge if !grpc && accepts_html(req.headers()) => {
                count("challenge", protocol);
                let res = challenge
                    .map_or_else(|| reject(verdict, grpc, protocol, scope), |c| c.page(key));
                ResponseFuture::Rejected { res: Some(res) }
            }
            Verdict::Allow => {
                if let Some(r) = route {
                    r.count("allow");
                    if !r.waf {
                        req.extensions_mut().insert(crate::NoWaf);
                    }
                }
                policy.fingerprints.forward(req.headers_mut(), fp);
                if let Some(p) = probe {
                    req.extensions_mut().insert(p);
                }
                count("allow", protocol);
                ResponseFuture::Inner {
                    fut: self.inner.call(req),
                    status: info.map(|_| StatusRecorder(self.shared.clone(), key)),
                }
            }
            v => {
                if matches!(v, Verdict::Throttle { .. }) {
                    log_throttled(key);
                }
                ResponseFuture::Rejected {
                    res: Some(reject(v, grpc, protocol, scope)),
                }
            }
        }
    }
}

impl Shared {
    pub(crate) fn policy(&self) -> Arc<Policy> {
        self.policy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn blocked(&self, key: ClientKey) -> bool {
        let b = self.blocks.read().unwrap_or_else(PoisonError::into_inner);
        b.contains(key.into(), (self.now)())
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // a panic while holding the lock leaves a consistent table (every
        // mutation is a few field writes), so keep serving instead of dying
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn cluster(&self) -> Option<std::sync::MutexGuard<'_, Cluster>> {
        let c = self.cluster.as_ref()?;
        Some(c.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn take(
        &self,
        key: ClientKey,
        info: Option<ReqInfo>,
        pass: Pass,
        heavy_ttl: Option<Duration>,
    ) -> (Verdict, Scope, Seen) {
        let now = (self.now)();
        // the cluster's verdict first: a listed heavy hitter or a client
        // over its cluster count (RFC 0010); never waits on the store
        if let Some(v) = self.cluster().and_then(|c| c.check(key, now)) {
            return (v, Scope::Cluster, (false, None));
        }
        let mut heavy = Vec::new();
        let mut seen: Seen = (false, None);
        let (verdict, clients, evicted) = {
            let mut g = self.lock();
            let Inner { guard, watch } = &mut *g;
            let d = guard.check_passed(key, now, pass);
            if let (Some(r), Some(det)) = (&d.report, guard.detector()) {
                watch.report(r, det, now);
                if heavy_ttl.is_some()
                    && (self.cluster.is_some() || self.block.is_some())
                    && det.state() == State::Attack
                {
                    heavy.extend(det.heavy().iter().map(|(c, _)| *c));
                }
            }
            seen.0 = guard.detector().is_some_and(|d| d.state() == State::Attack);
            if d.would_drop {
                log_would_drop(key);
            }
            let mut v = d.verdict;
            if let (Some(s), Some(info), Verdict::Allow) = (&self.scoring, info, v) {
                let window = guard.window();
                let instance = guard
                    .detector()
                    .map_or((0.0, 0.0), |det| (det.zscore(), det.entropy()));
                if let Some(slot) = guard.get_mut(&key) {
                    let stats = slot.get_or_insert_with(Box::default);
                    let (j, score, features) = s.judge(stats, info, now, window, instance);
                    (v, seen.1) = (j, Some((score, features)));
                }
            }
            (v, guard.clients(), d.evicted)
        };
        metrics::gauge!("dvarapala_limiter_clients").set(clients as f64);
        if evicted > 0 {
            metrics::counter!("dvarapala_limiter_evictions_total").increment(evicted);
        }
        if let (Some(b), Some(_)) = (&self.block, heavy_ttl) {
            for net in &heavy {
                b.block(*net);
            }
        }
        if let Some(mut c) = self.cluster() {
            if verdict == Verdict::Allow {
                c.record(key);
            }
            if let (Some(ttl), false) = (heavy_ttl, heavy.is_empty()) {
                c.publish_heavy(heavy, ttl);
            }
        }
        (verdict, Scope::Local, seen)
    }
}

/// Whether any `Accept` header lists `text/html`, so a page can be shown.
fn accepts_html(headers: &HeaderMap) -> bool {
    headers.get_all(ACCEPT).iter().any(|v| {
        v.as_bytes()
            .windows(9)
            .any(|w| w.eq_ignore_ascii_case(b"text/html"))
    })
}

/// All `X-Forwarded-For` lines as one list. Non-UTF-8 counts as absent, so
/// the key falls back to the peer.
pub(crate) fn forwarded_for(headers: &HeaderMap) -> Option<Cow<'_, str>> {
    let mut values = headers.get_all("x-forwarded-for").iter();
    let first = values.next()?.to_str().ok()?;
    let mut joined: Cow<'_, str> = Cow::Borrowed(first);
    for v in values {
        let s = joined.to_mut();
        s.push_str(", ");
        s.push_str(v.to_str().ok()?);
    }
    Some(joined)
}

/// One debug line per 1024 throttled requests, so a flood does not flood the logs.
fn log_throttled(key: ClientKey) {
    static THROTTLED: AtomicU64 = AtomicU64::new(0);
    if THROTTLED
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(1024)
    {
        tracing::debug!(msg = "throttled", key = %key);
    }
}

/// Observe mode: one info line per 1024 requests enforce mode would drop.
fn log_would_drop(key: ClientKey) {
    static WOULD_DROP: AtomicU64 = AtomicU64::new(0);
    if WOULD_DROP
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(1024)
    {
        tracing::info!(msg = "would_drop", key = %key, mode = "observe");
    }
}

/// Feeds the response status back into the client's stats (scoring only).
pub struct StatusRecorder(Arc<Shared>, ClientKey);

impl StatusRecorder {
    fn record(self, status: StatusCode) {
        let mut g = self.0.lock();
        if let Some(Some(stats)) = g.guard.get_mut(&self.1) {
            stats.record_status(status.as_u16());
        }
    }
}

pin_project_lite::pin_project! {
    /// Either the inner service's future or a ready rejection.
    #[project = Proj]
    pub enum ResponseFuture<F, R> {
        Inner { #[pin] fut: F, status: Option<StatusRecorder> },
        Rejected { res: Option<Response<R>> },
    }
}

impl<F, R, E> Future for ResponseFuture<F, R>
where
    F: Future<Output = Result<Response<R>, E>>,
{
    type Output = Result<Response<R>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            Proj::Inner { fut, status } => {
                let out = std::task::ready!(fut.poll(cx));
                if let (Ok(res), Some(s)) = (&out, status.take()) {
                    s.record(res.status());
                }
                Poll::Ready(out)
            }
            Proj::Rejected { res } => Poll::Ready(Ok(res
                .take()
                .expect("ResponseFuture polled after completion"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::header::HeaderValue;

    use super::*;

    #[test]
    fn forwarded_for_joins_repeated_headers() {
        let mut h = HeaderMap::new();
        assert_eq!(forwarded_for(&h), None);
        h.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        assert_eq!(forwarded_for(&h).as_deref(), Some("198.51.100.7"));
        h.append("x-forwarded-for", HeaderValue::from_static("192.0.2.1"));
        assert_eq!(
            forwarded_for(&h).as_deref(),
            Some("198.51.100.7, 192.0.2.1")
        );
        h.append("x-forwarded-for", HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(forwarded_for(&h), None);
    }
}
