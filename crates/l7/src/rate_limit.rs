use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use dvarapala_engine::{ClientKey, Limit, Table, TrustedProxies};
use http::{Request, Response};
use tower_layer::Layer;
use tower_service::Service;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub limit: Limit,
    pub max_clients: NonZeroUsize,
    pub trusted: TrustedProxies,
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
    pub fn new(_config: RateLimitConfig) -> Self {
        todo!("rfc 0001")
    }

    /// Clients currently in the table.
    pub fn clients(&self) -> usize {
        todo!("rfc 0001")
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

    fn call(&mut self, _req: Request<B>) -> Self::Future {
        todo!("rfc 0001")
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
