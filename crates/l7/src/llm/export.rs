//! RFC 0024: the `GET /llm/export` parameters.

use http::StatusCode;

use crate::admin::{Refusal, decode};

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
    let bad = |m: String| (StatusCode::BAD_REQUEST, m);
    let mut e = ExportQuery {
        since_ms: 0,
        until_ms: u64::MAX,
        labels: Vec::new(),
        triggers: Vec::new(),
    };
    for kv in q.split('&').filter(|kv| !kv.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let v = decode(v).ok_or_else(|| bad(format!("{k}: bad percent escape")))?;
        match k {
            "since" | "until" => {
                let t = time(&v).ok_or_else(|| bad(format!("{k}: use RFC 3339 or Unix ms")))?;
                *if k == "since" {
                    &mut e.since_ms
                } else {
                    &mut e.until_ms
                } = t;
            }
            "label" | "trigger" => {
                let list = if k == "label" {
                    &mut e.labels
                } else {
                    &mut e.triggers
                };
                if v.is_empty() {
                    return Err(bad(format!("{k} is empty")));
                }
                if list.len() == MAX_FILTER {
                    return Err(bad(format!("{k}: at most {MAX_FILTER} values")));
                }
                list.push(v);
            }
            _ => {}
        }
    }
    if e.since_ms > e.until_ms {
        return Err(bad("since is after until".into()));
    }
    Ok(e)
}

/// Unix ms, or an RFC 3339 date-time.
fn time(s: &str) -> Option<u64> {
    match num(s) {
        Some(_) => s.parse().ok(),
        None => rfc3339(s),
    }
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|+HH:MM|-HH:MM)` in Unix ms; before 1970
/// is refused.
fn rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let f = |i: usize, n: usize| num(s.get(i..i + n)?);
    let (y, mo, d) = (f(0, 4)?, f(5, 2)?, f(8, 2)?);
    let (h, mi, sec) = (f(11, 2)?, f(14, 2)?, f(17, 2)?);
    let mut rest = s.get(19..)?;
    let mut ms = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        ms = frac
            .bytes()
            .take(n.min(3))
            .fold(0, |a, c| a * 10 + i64::from(c - b'0'))
            * 10_i64.pow(3 - n.min(3) as u32);
        rest = &frac[n..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let o = rest.as_bytes();
            let sign = match o.first() {
                Some(b'+') => 1,
                Some(b'-') => -1,
                _ => return None,
            };
            if o.len() != 6 || o[3] != b':' {
                return None;
            }
            sign * (num(rest.get(1..3)?)? * 60 + num(rest.get(4..6)?)?) * 60_000
        }
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let month = [
        31,
        28 + i64::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo)
        || !(1..=month[(mo - 1) as usize]).contains(&d)
        || h > 23
        || mi > 59
        || sec > 60
    {
        return None;
    }
    let t = days(y, mo, d) * 86_400_000 + (h * 3_600 + mi * 60 + sec) * 1_000 + ms - offset;
    u64::try_from(t).ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant).
fn days(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0024 case 5
    #[test]
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
