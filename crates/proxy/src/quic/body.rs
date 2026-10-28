use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use hyper::body::{Body, Frame};

/// An HTTP/3 request body, read from the request stream as the service
/// polls it.
pub struct H3Body {
    // ponytail: request trailers are dropped
    pub(super) recv: RequestStream<h3_quinn::RecvStream, Bytes>,
}

impl Body for H3Body {
    type Data = Bytes;
    type Error = h3::error::StreamError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        Poll::Ready(
            ready!(self.recv.poll_recv_data(cx))
                .map(|d| d.map(|mut b| Frame::data(b.copy_to_bytes(b.remaining()))))
                .transpose(),
        )
    }
}
