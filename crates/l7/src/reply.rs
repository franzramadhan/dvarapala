//! Local answers to requests the layer refuses, and their metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dvarapala_engine::Verdict;
use http::header::{CONNECTION, HeaderValue, RETRY_AFTER};
use http::{Response, StatusCode};

use crate::{GrpcStatus, grpc_response};

/// The `verdict` values of `dvarapala_requests_total`.
const VERDICTS: [&str; 5] = ["allow", "throttle", "challenge", "drop", "error"];
static TOTALS: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

/// The totals behind `dvarapala_requests_total` per verdict since start,
/// protocol and scope folded in (RFC 0018, admin `/status`).
pub fn totals() -> [(&'static str, u64); 5] {
    std::array::from_fn(|i| (VERDICTS[i], TOTALS[i].load(Ordering::Relaxed)))
}

fn total(verdict: &str) {
    if let Some(i) = VERDICTS.iter().position(|v| *v == verdict) {
        TOTALS[i].fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn count(verdict: &'static str, protocol: &'static str) {
    total(verdict);
    metrics::counter!("dvarapala_requests_total", "verdict" => verdict, "protocol" => protocol)
        .increment(1);
}

/// Who decided a rejection: this replica's bucket, the cluster (RFC 0010)
/// or a manual block (RFC 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Local,
    Cluster,
    Block,
}

/// The local answer to a rejected request (RFC 0004): trailers-only gRPC
/// for gRPC clients, an HTTP status otherwise.
pub(crate) fn reject<R: Default>(
    v: Verdict,
    grpc: bool,
    protocol: &'static str,
    scope: Scope,
) -> Response<R> {
    use GrpcStatus::{PermissionDenied, ResourceExhausted};
    let (label, code, grpc_status, retry_after) = match v {
        Verdict::Throttle { retry_after } => (
            "throttle",
            StatusCode::TOO_MANY_REQUESTS,
            ResourceExhausted,
            Some(retry_after),
        ),
        // a client that cannot show the page (no `text/html`, gRPC): a 429
        // without Retry-After is the closest honest answer
        Verdict::Challenge => (
            "challenge",
            StatusCode::TOO_MANY_REQUESTS,
            ResourceExhausted,
            None,
        ),
        // `Allow` never gets here; fail closed if it ever does
        Verdict::Drop | Verdict::Allow => ("drop", StatusCode::FORBIDDEN, PermissionDenied, None),
    };
    match scope {
        Scope::Local => count(label, protocol),
        Scope::Cluster | Scope::Block => {
            total(label);
            metrics::counter!(
            "dvarapala_requests_total",
            "verdict" => label,
            "protocol" => protocol,
            "scope" => if scope == Scope::Block { "block" } else { "cluster" }
            )
            .increment(1);
        }
    }
    if grpc {
        return grpc_response(grpc_status, retry_after);
    }
    let mut res = Response::new(R::default());
    *res.status_mut() = code;
    if let Some(d) = retry_after {
        res.headers_mut().insert(RETRY_AFTER, retry_after_secs(d));
    }
    if code == StatusCode::FORBIDDEN {
        res.headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    res
}

/// Whole seconds, rounded up, at least 1 (`Retry-After: 0` invites a retry storm).
pub(crate) fn retry_after_secs(d: Duration) -> HeaderValue {
    HeaderValue::from(d.as_secs_f64().ceil().max(1.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_rounds_up_and_is_never_zero() {
        assert_eq!(retry_after_secs(Duration::from_millis(1)), "1");
        assert_eq!(retry_after_secs(Duration::from_millis(1500)), "2");
        assert_eq!(retry_after_secs(Duration::ZERO), "1");
    }
}
