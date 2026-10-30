//! RFC 0021: the rules the agent matched, for the console's WAF page, and
//! their `dvarapala_waf_rule_matches_total{rule}` labels.

use std::sync::{Mutex, PoisonError};

/// Rule IDs kept by ID (and as metric labels); the rest count as `other`.
pub const MAX_RULES: usize = 256;
/// Longest path kept for a rule's last match.
const MAX_PATH: usize = 256;

/// One rule ID and its last match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule: i64,
    pub count: u64,
    /// Unix seconds.
    pub last_seen: u64,
    pub method: String,
    /// Without the query string, at most 256 bytes.
    pub path: String,
    pub anomaly_score: Option<i64>,
}

/// Matched rules, bounded to `MAX_RULES` IDs plus an `other` count.
#[derive(Debug, Default)]
pub struct Rules {
    inner: Mutex<(Vec<RuleMatch>, u64)>,
}

impl Rules {
    pub const fn new() -> Self {
        Self {
            inner: Mutex::new((Vec::new(), 0)),
        }
    }

    /// Counts a match; returns the metric label, the ID or `other`.
    pub fn record(
        &self,
        rule: i64,
        method: &str,
        path: &str,
        score: Option<i64>,
        now: u64,
    ) -> String {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (rules, other) = &mut *g;
        let i = match rules.iter().position(|m| m.rule == rule) {
            Some(i) => i,
            None if rules.len() < MAX_RULES => {
                rules.push(RuleMatch {
                    rule,
                    count: 0,
                    last_seen: 0,
                    method: String::new(),
                    path: String::new(),
                    anomaly_score: None,
                });
                rules.len() - 1
            }
            None => {
                *other += 1;
                return "other".into();
            }
        };
        let m = &mut rules[i];
        m.count += 1;
        m.last_seen = now;
        m.method = method.to_owned();
        m.path = cut(path, MAX_PATH).to_owned();
        m.anomaly_score = score;
        rule.to_string()
    }

    /// The rules by count, highest first, and the `other` count.
    pub fn snapshot(&self) -> (Vec<RuleMatch>, u64) {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mut rules = g.0.clone();
        rules.sort_by(|a, b| b.count.cmp(&a.count).then(a.rule.cmp(&b.rule)));
        (rules, g.1)
    }
}

/// The process wide table the WAF layer feeds.
pub static MATCHED: Rules = Rules::new();

/// The matched rules of this process (RFC 0021).
pub fn matched_rules() -> (Vec<RuleMatch>, u64) {
    MATCHED.snapshot()
}

/// `s` cut to at most `max` bytes on a char boundary.
fn cut(s: &str, max: usize) -> &str {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_keeps_the_last_match() {
        let r = Rules::new();
        assert_eq!(r.record(942100, "GET", "/a", Some(5), 10), "942100");
        assert_eq!(r.record(941100, "POST", "/b", None, 11), "941100");
        assert_eq!(r.record(942100, "PUT", "/c", Some(8), 12), "942100");
        let (rules, other) = r.snapshot();
        assert_eq!(other, 0);
        assert_eq!(rules[0].rule, 942100);
        assert_eq!(rules[0].count, 2);
        assert_eq!(
            (
                rules[0].last_seen,
                rules[0].method.as_str(),
                rules[0].path.as_str()
            ),
            (12, "PUT", "/c")
        );
        assert_eq!(rules[0].anomaly_score, Some(8));
        assert_eq!((rules[1].rule, rules[1].count), (941100, 1));
    }

    // RFC 0021 case 6
    #[test]
    fn bounded_to_256_ids_then_other() {
        let r = Rules::new();
        for id in 0..300 {
            r.record(id, "GET", "/", None, 1);
        }
        let (rules, other) = r.snapshot();
        assert_eq!(rules.len(), MAX_RULES);
        assert_eq!(other, 300 - MAX_RULES as u64);
        assert_eq!(r.record(5, "GET", "/", None, 2), "5");
        assert_eq!(r.record(299, "GET", "/", None, 2), "other");
    }

    #[test]
    fn long_paths_cut_on_a_char_boundary() {
        let r = Rules::new();
        let long = "é".repeat(200);
        r.record(1, "GET", &long, None, 1);
        let p = &r.snapshot().0[0].path;
        assert!(p.len() <= MAX_PATH && p.len() >= MAX_PATH - 1);
    }
}
