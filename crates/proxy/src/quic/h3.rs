//! HTTP/3 requests into the tower service, bodies both ways.

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use dvarapala_l7::PeerAddr;
use http::{Request, Response};
use http_body_util::BodyExt;
use tower_service::Service;

use super::H3Body;
use crate::ProxyBody;

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Serves the requests on one established connection until it closes.
pub(super) async fn connection<S>(conn: quinn::Connection, service: S)
where
    S: Service<Request<H3Body>, Response = Response<ProxyBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let peer = conn.remote_address();
    let Ok(mut h3) = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await else {
        return;
    };
    while let Ok(Some(resolver)) = h3.accept().await {
        let service = service.clone();
        tokio::spawn(async move {
            if let Ok((req, stream)) = resolver.resolve_request().await {
                request(req, stream, peer, service).await;
            }
        });
    }
}

async fn request<S>(req: Request<()>, stream: Stream, peer: SocketAddr, mut service: S)
where
    S: Service<Request<H3Body>, Response = Response<ProxyBody>, Error = Infallible>,
{
    let (mut send, recv) = stream.split();
    let (mut parts, ()) = req.into_parts();
    parts.extensions.insert(PeerAddr(peer));
    let Ok(res) = service
        .call(Request::from_parts(parts, H3Body { recv }))
        .await;
    let (parts, mut body) = res.into_parts();
    if send
        .send_response(Response::from_parts(parts, ()))
        .await
        .is_err()
    {
        return;
    }
    while let Some(frame) = body.frame().await {
        let sent = match frame.map(|f| f.into_data()) {
            Ok(Ok(data)) => send.send_data(data).await,
            Ok(Err(f)) => match f.into_trailers() {
                Ok(t) => send.send_trailers(t).await,
                Err(_) => Ok(()),
            },
            // the upstream broke off: reset the stream, not finish it
            Err(_) => return send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR),
        };
        if sent.is_err() {
            return;
        }
    }
    let _ = send.finish().await;
}
