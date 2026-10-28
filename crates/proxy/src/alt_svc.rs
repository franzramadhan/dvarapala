use std::task::{Context, Poll};

use http::{Request, Response};
use tower_service::Service;

/// Adds `Alt-Svc: h3=":<port>"; ma=86400` to every response, so clients
/// find the HTTP/3 listener (RFC 0006).
#[derive(Clone)]
pub struct AltSvc<S> {
    inner: S,
}

impl<S> AltSvc<S> {
    pub fn new(inner: S, port: u16) -> Self {
        let _ = (inner, port);
        todo!("rfc 0006")
    }
}

impl<S, B, R> Service<Request<B>> for AltSvc<S>
where
    S: Service<Request<B>, Response = Response<R>>,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let _ = req;
        todo!("rfc 0006")
    }
}
