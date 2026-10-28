use std::time::Duration;

use http::header::{CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use http::{HeaderMap, Response};

use crate::rate_limit::retry_after_secs;

/// gRPC status codes dvarapala answers with itself (RFC 0004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcStatus {
    /// `7`: a `Drop` verdict.
    PermissionDenied,
    /// `8`: a `Throttle` or `Challenge` verdict.
    ResourceExhausted,
    /// `14`: the upstream could not be reached.
    Unavailable,
}

/// `content-type: application/grpc` or `application/grpc+<codec>`.
pub fn is_grpc(headers: &HeaderMap) -> bool {
    let Some(v) = headers.get(CONTENT_TYPE) else {
        return false;
    };
    let v = v.as_bytes();
    let prefix = b"application/grpc";
    v.len() >= prefix.len()
        && v[..prefix.len()].eq_ignore_ascii_case(prefix)
        && matches!(v.get(prefix.len()), None | Some(b'+' | b';'))
}

/// A trailers-only gRPC response: HTTP 200, `grpc-status` and a fixed
/// `grpc-message` in the headers, no body. `retry_after` adds
/// `retry-after` and `grpc-retry-pushback-ms`.
pub fn grpc_response<R: Default>(status: GrpcStatus, retry_after: Option<Duration>) -> Response<R> {
    let (code, message, label) = match status {
        GrpcStatus::PermissionDenied => ("7", "denied", "permission_denied"),
        GrpcStatus::ResourceExhausted => ("8", "rate limited", "resource_exhausted"),
        GrpcStatus::Unavailable => ("14", "upstream unavailable", "unavailable"),
    };
    metrics::counter!("dvarapala_grpc_local_responses_total", "status" => label).increment(1);
    let mut res = Response::new(R::default());
    let h = res.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    h.insert("grpc-status", HeaderValue::from_static(code));
    h.insert("grpc-message", HeaderValue::from_static(message));
    if let Some(d) = retry_after {
        h.insert(RETRY_AFTER, retry_after_secs(d));
        h.insert(
            "grpc-retry-pushback-ms",
            HeaderValue::from(d.as_millis().max(1) as u64),
        );
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn ct(v: &[u8]) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("content-type", HeaderValue::from_bytes(v).unwrap());
        h
    }

    /// RFC 0004 case 19
    #[test]
    fn detects_grpc_content_types_only() {
        for yes in [
            &b"application/grpc"[..],
            b"application/grpc+proto",
            b"application/grpc+json",
            b"Application/GRPC",
            b"application/grpc; charset=utf-8",
        ] {
            assert!(is_grpc(&ct(yes)), "{yes:?}");
        }
        for no in [
            &b""[..],
            b"application/grpc-web",
            b"application/grpc-web+proto",
            b"application/grpcx",
            b"application/json",
            b"text/plain",
            b"application/grp",
            b"\xff\xfe",
        ] {
            assert!(!is_grpc(&ct(no)), "{no:?}");
        }
        assert!(!is_grpc(&HeaderMap::new()));
    }

    #[test]
    fn trailers_only_response() {
        let r: Response<()> = grpc_response(
            GrpcStatus::ResourceExhausted,
            Some(Duration::from_millis(1500)),
        );
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "application/grpc");
        assert_eq!(r.headers()["grpc-status"], "8");
        assert_eq!(r.headers()["retry-after"], "2");
        assert_eq!(r.headers()["grpc-retry-pushback-ms"], "1500");
        let r: Response<()> = grpc_response(GrpcStatus::Unavailable, None);
        assert_eq!(r.headers()["grpc-status"], "14");
        assert!(r.headers().get("grpc-retry-pushback-ms").is_none());
        let r: Response<()> = grpc_response(GrpcStatus::PermissionDenied, None);
        assert_eq!(r.headers()["grpc-status"], "7");
    }
}
