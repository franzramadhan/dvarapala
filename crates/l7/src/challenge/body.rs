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

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    // RFC 0012: the page fits the boxed bodies a server answers with
    #[tokio::test]
    async fn every_body_carries_the_page() {
        let html = Bytes::from_static(b"<p>solve</p>");
        let full = Full::<Bytes>::page(html.clone()).collect().await.unwrap();
        let boxed = BoxBody::<Bytes, Infallible>::page(html.clone())
            .collect()
            .await
            .unwrap();
        let unsync = UnsyncBoxBody::<Bytes, std::io::Error>::page(html.clone())
            .collect()
            .await
            .unwrap();
        for b in [full, boxed, unsync] {
            assert_eq!(b.to_bytes(), html);
        }
    }
}
