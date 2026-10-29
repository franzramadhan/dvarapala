use bytes::Bytes;
use http_body_util::combinators::{BoxBody, UnsyncBoxBody};
use http_body_util::{BodyExt, Full};

/// A response body the rate limit layer can write a challenge page into.
pub trait PageBody: Default {
    fn page(html: Bytes) -> Self;
}

impl PageBody for Full<Bytes> {
    fn page(html: Bytes) -> Self {
        Full::new(html)
    }
}

impl<E: 'static> PageBody for BoxBody<Bytes, E> {
    fn page(html: Bytes) -> Self {
        Full::new(html).map_err(|never| match never {}).boxed()
    }
}

impl<E: 'static> PageBody for UnsyncBoxBody<Bytes, E> {
    fn page(html: Bytes) -> Self {
        Full::new(html)
            .map_err(|never| match never {})
            .boxed_unsync()
    }
}
