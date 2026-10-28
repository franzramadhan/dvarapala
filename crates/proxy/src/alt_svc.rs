use std::task::{Context, Poll};

use http::header::{ALT_SVC, HeaderValue};
use http::{Request, Response};
use tower_service::Service;

/// Adds `Alt-Svc: h3=":<port>"; ma=86400` to every response, so clients
/// find the HTTP/3 listener (RFC 0006).
#[derive(Clone)]
pub struct AltSvc<S> {
    inner: S,
    value: HeaderValue,
}

impl<S> AltSvc<S> {
    pub fn new(inner: S, port: u16) -> Self {
        let value = HeaderValue::try_from(format!("h3=\":{port}\"; ma=86400"))
            .expect("digits and ASCII only");
        Self { inner, value }
    }
}

impl<S, B, R> Service<Request<B>> for AltSvc<S>
where
    S: Service<Request<B>, Response = Response<R>>,
    S::Future: Send + 'static,
    S::Error: 'static,
    R: 'static,
{
    type Response = Response<R>;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response<R>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (fut, value) = (self.inner.call(req), self.value.clone());
        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut().insert(ALT_SVC, value);
            Ok(res)
        })
    }
}
