use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use hyper::body::{Body, Frame};

/// An HTTP/3 request body, read from the request stream as the service
/// polls it.
pub struct H3Body {}

impl Body for H3Body {
    type Data = Bytes;
    type Error = h3::error::StreamError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let _ = cx;
        todo!("rfc 0006")
    }
}
