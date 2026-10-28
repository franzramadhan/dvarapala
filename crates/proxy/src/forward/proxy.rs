use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response};
use hyper::body::Body;
use tower_service::Service;

use crate::ProxyBody;
use crate::forward::{ForwardConfig, ForwardError};

/// Forwards requests from allowed clients to listed destinations, each
/// shaped to its rate (RFC 0007).
pub struct ForwardProxy<B> {
    _body: PhantomData<fn(B)>,
}

impl<B> Clone for ForwardProxy<B> {
    fn clone(&self) -> Self {
        Self { _body: PhantomData }
    }
}

impl<B> ForwardProxy<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub fn new(config: &ForwardConfig) -> Result<Self, ForwardError> {
        let _ = config;
        todo!("rfc 0007")
    }
}

impl<B> Service<Request<B>> for ForwardProxy<B>
where
    B: Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let _ = req;
        todo!("rfc 0007")
    }
}
