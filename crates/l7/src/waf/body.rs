//! RFC 0017: the request body after the WAF, the frames it read for the
//! agent first, then the rest of the client's body.

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
        Self::buffered(VecDeque::new(), Some(body))
    }

    /// `head` read already; `rest` is `None` when the body ended.
    pub(crate) fn buffered(head: VecDeque<Frame<Bytes>>, rest: Option<B>) -> Self {
        Self { head, rest }
    }

    fn head_len(&self) -> u64 {
        self.head
            .iter()
            .filter_map(Frame::data_ref)
            .map(|d| d.len() as u64)
            .sum()
    }
}

impl<B: Body<Data = Bytes>> Body for WafBody<B> {
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.project();
        if let Some(f) = this.head.pop_front() {
            return Poll::Ready(Some(Ok(f)));
        }
        match this.rest.as_pin_mut() {
            Some(b) => b.poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.head.is_empty() && self.rest.as_ref().is_none_or(B::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        let n = self.head_len();
        let Some(rest) = &self.rest else {
            return SizeHint::with_exact(n);
        };
        let h = rest.size_hint();
        let mut s = SizeHint::new();
        s.set_lower(h.lower() + n);
        if let Some(u) = h.upper() {
            s.set_upper(u + n);
        }
        s
    }
}
