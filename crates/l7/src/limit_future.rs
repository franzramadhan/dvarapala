//! The rate limiter's response future, and the status it feeds back into
//! the client's stats.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use dvarapala_engine::ClientKey;
use http::{Response, StatusCode};

use crate::rate_limit::Shared;

/// Feeds the response status back into the client's stats (scoring only).
pub struct StatusRecorder(pub(crate) Arc<Shared>, pub(crate) ClientKey);

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
