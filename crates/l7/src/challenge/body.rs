#![allow(unused_variables, unused_imports, dead_code)]
use bytes::Bytes;
use http_body_util::combinators::{BoxBody, UnsyncBoxBody};
use http_body_util::{BodyExt, Full};

/// A response body the rate limit layer can write a challenge page into.
pub trait PageBody: Default {
    fn page(html: Bytes) -> Self;
}

impl PageBody for Full<Bytes> {
    fn page(html: Bytes) -> Self {
        todo!("rfc 0012")
    }
}

impl<E: 'static> PageBody for BoxBody<Bytes, E> {
    fn page(html: Bytes) -> Self {
        todo!("rfc 0012")
    }
}

impl<E: 'static> PageBody for UnsyncBoxBody<Bytes, E> {
    fn page(html: Bytes) -> Self {
        todo!("rfc 0012")
    }
}
