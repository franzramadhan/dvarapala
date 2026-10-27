use std::convert::Infallible;
use std::future::Future;

use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::net::TcpListener;
use tower_service::Service;

use crate::ProxyBody;

/// Serves `service` on `listener` (HTTP/1.1 and HTTP/2) until `shutdown`
/// resolves, then waits for open connections to finish. Every request gets
/// a [`dvarapala_l7::PeerAddr`] extension.
pub async fn serve<S>(_listener: TcpListener, _service: S, _shutdown: impl Future<Output = ()>)
where
    S: Service<Request<Incoming>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    todo!("rfc 0001")
}
