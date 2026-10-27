use std::borrow::Cow;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use dvarapala_engine::{ClientKey, Limit, Table, TrustedProxies, Verdict, client_key};
use http::header::{CONNECTION, HeaderMap, HeaderValue, RETRY_AFTER};
use http::{Request, Response, StatusCode};
use tower_layer::Layer;
use tower_service::Service;

use crate::{Detection, PeerAddr, Scoring};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub limit: Limit,
    pub max_clients: NonZeroUsize,
    pub trusted: TrustedProxies,
    /// RFC 0002 adaptive detection; `None` turns it off.
    pub detection: Option<Detection>,
    /// RFC 0002 scoring hook; `None` turns it off.
    pub scoring: Option<Scoring>,
    /// The clock. `Instant::now` outside tests.
    pub now: fn() -> Instant,
}

/// Per-client token bucket in front of a service. Over the limit, the
/// request gets `429 Too Many Requests` with `Retry-After` and never reaches
/// the inner service.
#[derive(Clone)]
pub struct RateLimitLayer {
    shared: Arc<Shared>,
}

struct Shared {
    // ponytail: one lock for the whole table; shard by key hash if it shows
    // up in profiles under load
    table: Mutex<Table<ClientKey>>,
    limit: Limit,
    trusted: TrustedProxies,
}

impl RateLimitLayer {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                table: Mutex::new(Table::new(config.max_clients)),
                limit: config.limit,
                trusted: config.trusted,
            }),
        }
    }

    /// Clients currently in the table.
    pub fn clients(&self) -> usize {
        self.shared.lock().len()
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
    R: Default,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future, R>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let Some(PeerAddr(peer)) = req.extensions().get::<PeerAddr>().copied() else {
            // fail closed: without a peer every client would share one key
            tracing::error!(msg = "request without PeerAddr, the server does not set it");
            metrics::counter!("dvarapala_requests_total", "verdict" => "error").increment(1);
            return rejected(StatusCode::INTERNAL_SERVER_ERROR);
        };
        let key = client_key(
            peer.ip(),
            forwarded_for(req.headers()).as_deref(),
            &self.shared.trusted,
        );
        match self.shared.take(key) {
            Verdict::Allow => {
                metrics::counter!("dvarapala_requests_total", "verdict" => "allow").increment(1);
                ResponseFuture::Inner {
                    fut: self.inner.call(req),
                }
            }
            Verdict::Throttle { retry_after } => {
                metrics::counter!("dvarapala_requests_total", "verdict" => "throttle").increment(1);
                log_throttled(key);
                let mut fut = rejected(StatusCode::TOO_MANY_REQUESTS);
                if let ResponseFuture::Rejected { res: Some(res) } = &mut fut {
                    res.headers_mut()
                        .insert(RETRY_AFTER, retry_after_secs(retry_after));
                }
                fut
            }
            // ponytail: no challenge page until the challenge RFC; a 429
            // without Retry-After is the closest honest answer
            Verdict::Challenge => {
                metrics::counter!("dvarapala_requests_total", "verdict" => "challenge")
                    .increment(1);
                rejected(StatusCode::TOO_MANY_REQUESTS)
            }
            Verdict::Drop => {
                metrics::counter!("dvarapala_requests_total", "verdict" => "drop").increment(1);
                let mut fut = rejected(StatusCode::FORBIDDEN);
                if let ResponseFuture::Rejected { res: Some(res) } = &mut fut {
                    res.headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                }
                fut
            }
        }
    }
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, Table<ClientKey>> {
        // a panic while holding the lock leaves a consistent table (every
        // mutation is a few field writes), so keep serving instead of dying
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn take(&self, key: ClientKey) -> Verdict {
        let (verdict, clients, evicted) = {
            let mut t = self.lock();
            let before = t.evictions();
            let v = t.take(key, &self.limit, Instant::now());
            (v, t.len(), t.evictions() - before)
        };
        metrics::gauge!("dvarapala_limiter_clients").set(clients as f64);
        if evicted > 0 {
            metrics::counter!("dvarapala_limiter_evictions_total").increment(evicted);
        }
        verdict
    }
}

fn rejected<F, R: Default>(status: StatusCode) -> ResponseFuture<F, R> {
    let mut res = Response::new(R::default());
    *res.status_mut() = status;
    ResponseFuture::Rejected { res: Some(res) }
}

/// Whole seconds, rounded up, at least 1 (`Retry-After: 0` invites a retry storm).
fn retry_after_secs(d: Duration) -> HeaderValue {
    HeaderValue::from(d.as_secs_f64().ceil().max(1.0) as u64)
}

/// All `X-Forwarded-For` lines as one list. Non-UTF-8 counts as absent, so
/// the key falls back to the peer.
fn forwarded_for(headers: &HeaderMap) -> Option<Cow<'_, str>> {
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

pin_project_lite::pin_project! {
    /// Either the inner service's future or a ready rejection.
    #[project = Proj]
    pub enum ResponseFuture<F, R> {
        Inner { #[pin] fut: F },
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
            Proj::Inner { fut } => fut.poll(cx),
            Proj::Rejected { res } => Poll::Ready(Ok(res
                .take()
                .expect("ResponseFuture polled after completion"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_rounds_up_and_is_never_zero() {
        assert_eq!(retry_after_secs(Duration::from_millis(1)), "1");
        assert_eq!(retry_after_secs(Duration::from_millis(1500)), "2");
        assert_eq!(retry_after_secs(Duration::ZERO), "1");
    }

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
