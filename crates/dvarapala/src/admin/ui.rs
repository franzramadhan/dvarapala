//! The console bundle (RFC 0018), built from `ui/` and checked in gzip
//! compressed: no Node to build the binary.

use http::header::{
    CACHE_CONTROL, CONTENT_ENCODING, CONTENT_TYPE, ETAG, HeaderValue, IF_NONE_MATCH, LOCATION,
};
use http::{HeaderMap, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;

macro_rules! dist {
    ($f:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../ui/dist/", $f))
    };
}

static INDEX: &[u8] = dist!("index.html.gz");
static JS: &[u8] = dist!("app.js.gz");
static CSS: &[u8] = dist!("app.css.gz");

/// The console's answer for `path` under `/ui`; any unknown path is the
/// page itself so deep links work.
pub fn asset(path: &str, headers: &HeaderMap) -> Response<Full<Bytes>> {
    if path == "/ui" {
        let mut r = Response::new(Full::default());
        *r.status_mut() = StatusCode::MOVED_PERMANENTLY;
        r.headers_mut()
            .insert(LOCATION, HeaderValue::from_static("/ui/"));
        return r;
    }
    let (body, kind) = match path {
        "/ui/app.js" => (JS, "text/javascript; charset=utf-8"),
        "/ui/app.css" => (CSS, "text/css; charset=utf-8"),
        _ => (INDEX, "text/html; charset=utf-8"),
    };
    let tag = format!("\"{:016x}\"", fnv(body));
    let fresh = headers
        .get(IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == tag.as_bytes());
    let mut r = if fresh {
        let mut r = Response::new(Full::default());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let mut r = Response::new(Full::new(Bytes::from_static(body)));
        let h = r.headers_mut();
        h.insert(CONTENT_TYPE, HeaderValue::from_static(kind));
        h.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        r
    };
    let h = r.headers_mut();
    // ponytail: fixed names, so revalidate by ETag instead of a long cache
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    h.insert(ETAG, HeaderValue::from_str(&tag).expect("hex"));
    r
}

/// FNV-1a: an ETag, not a security property.
fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325, |h, x| {
        (h ^ u64::from(*x)).wrapping_mul(0x0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_links_get_the_page_and_etags_revalidate() {
        let none = HeaderMap::new();
        let page = asset("/ui/blocks", &none);
        assert_eq!(page.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(page.headers()[CONTENT_ENCODING], "gzip");
        assert_eq!(
            asset("/ui/app.js", &none).headers()[CONTENT_TYPE],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(asset("/ui", &none).status(), StatusCode::MOVED_PERMANENTLY);
        let mut again = HeaderMap::new();
        again.insert(IF_NONE_MATCH, page.headers()[ETAG].clone());
        assert_eq!(asset("/ui/", &again).status(), StatusCode::NOT_MODIFIED);
    }
}
