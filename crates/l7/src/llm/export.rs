//! RFC 0024: the `GET /llm/export` parameters.
#![allow(unused_variables, unused_imports, dead_code)]

use http::StatusCode;

use crate::admin::Refusal;

/// Values of `label` or of `trigger` at most.
pub const MAX_FILTER: usize = 32;

/// The range, inclusive, and the filters; empty lists match all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportQuery {
    pub since_ms: u64,
    pub until_ms: u64,
    pub labels: Vec<String>,
    pub triggers: Vec<String>,
}

/// `since`, `until` (RFC 3339 or Unix ms), `label` and `trigger`
/// (repeatable). Other parameters are ignored.
pub fn export_query(q: &str) -> Result<ExportQuery, Refusal> {
    todo!("rfc 0024")
}

/// Unix ms, or an RFC 3339 date-time.
fn time(s: &str) -> Option<u64> {
    todo!("rfc 0024")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0024 case 5
    #[test]
    #[ignore = "rfc 0024"]
    fn range_and_filters() {
        let e = export_query(
            "since=2026-10-29T00:00:00Z&until=1793318400000&label=scanner&trigger=waf&trigger=attack&x=1",
        )
        .unwrap();
        assert_eq!(e.since_ms, 1_793_232_000_000);
        assert_eq!(e.until_ms, 1_793_318_400_000);
        assert_eq!(e.labels, ["scanner"]);
        assert_eq!(e.triggers, ["waf", "attack"]);
        let all = export_query("").unwrap();
        assert_eq!((all.since_ms, all.until_ms), (0, u64::MAX));
        assert!(all.labels.is_empty() && all.triggers.is_empty());
    }

    #[test]
    #[ignore = "rfc 0024"]
    fn rfc3339_forms() {
        assert_eq!(time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(time("1970-01-01t00:00:01.5z"), Some(1_500));
        assert_eq!(time("1970-01-01T01:00:00.123456+01:00"), Some(123));
        assert_eq!(time("2000-02-29T00:00:00-00:30"), Some(951_784_200_000));
        for bad in [
            "2001-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-10-29T24:00:00Z",
            "2026-10-29T00:00:00",
            "2026-10-29T00:00:00.Z",
            "2026-10-29T00:00:00+0100",
            "1969-12-31T23:59:59Z",
            "+026-10-29T00:00:00Z",
            "",
        ] {
            assert_eq!(time(bad), None, "{bad}");
        }
    }

    // RFC 0024 case 6
    #[test]
    #[ignore = "rfc 0024"]
    fn bad_parameters_are_named() {
        let many = "label=a&".repeat(MAX_FILTER + 1);
        for (q, name) in [
            ("since=abc", "since"),
            ("until=2026-10-29", "until"),
            (many.as_str(), "label"),
            ("trigger=", "trigger"),
            ("since=2000&until=1000", "since"),
            ("label=%zz", "label"),
        ] {
            let (status, msg) = export_query(q).unwrap_err();
            assert_eq!(status, StatusCode::BAD_REQUEST, "{q}");
            assert!(msg.starts_with(name), "{q}: {msg}");
        }
    }
}
