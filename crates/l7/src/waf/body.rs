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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use http_body_util::{BodyExt, Full};

    use super::*;

    /// A body of unknown length.
    struct Open;

    impl Body for Open {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(None)
        }
    }

    fn head(chunks: &[&'static [u8]]) -> VecDeque<Frame<Bytes>> {
        chunks
            .iter()
            .map(|c| Frame::data(Bytes::from_static(c)))
            .collect()
    }

    // RFC 0017: the upstream reads the buffered frames, then the rest
    #[tokio::test]
    async fn head_then_rest_with_the_length_of_both() {
        let full = |s: &'static [u8]| Full::new(Bytes::from_static(s));
        let b = WafBody::buffered(head(&[b"ab", b"c"]), Some(full(b"de")));
        assert_eq!(b.size_hint().exact(), Some(5));
        assert!(!b.is_end_stream());
        assert_eq!(b.collect().await.unwrap().to_bytes(), &b"abcde"[..]);

        let ended = WafBody::<Full<Bytes>>::buffered(head(&[b"xyz"]), None);
        assert_eq!(ended.size_hint().exact(), Some(3));
        assert!(!ended.is_end_stream());
        assert_eq!(ended.collect().await.unwrap().to_bytes(), &b"xyz"[..]);
        assert!(WafBody::<Full<Bytes>>::buffered(VecDeque::new(), None).is_end_stream());

        let open = WafBody::buffered(head(&[b"ab"]), Some(Open));
        let h = open.size_hint();
        assert_eq!((h.lower(), h.upper()), (2, None));
        assert!(!open.is_end_stream());
        assert_eq!(open.collect().await.unwrap().to_bytes(), &b"ab"[..]);
        assert!(WafBody::new(full(b"")).is_end_stream());
    }
}
