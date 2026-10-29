//! RFC 0017: the request body after the WAF, the frames it read for the
//! agent first, then the rest of the client's body.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

pin_project_lite::pin_project! {
    pub struct WafBody<B> {
        head: VecDeque<Frame<Bytes>>,
        #[pin]
        rest: Option<B>,
    }
}

impl<B> WafBody<B> {
    /// The body untouched.
    pub fn new(body: B) -> Self {
        todo!("rfc 0017")
    }

    /// `head` read already; `rest` is `None` when the body ended.
    pub(crate) fn buffered(head: VecDeque<Frame<Bytes>>, rest: Option<B>) -> Self {
        todo!("rfc 0017")
    }

    fn head_len(&self) -> u64 {
        todo!("rfc 0017")
    }
}

impl<B: Body<Data = Bytes>> Body for WafBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        todo!("rfc 0017")
    }

    fn is_end_stream(&self) -> bool {
        todo!("rfc 0017")
    }

    fn size_hint(&self) -> SizeHint {
        todo!("rfc 0017")
    }
}
