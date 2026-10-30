//! The `[waf]` section (RFC 0017).

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, de};

use super::{Mode, duration};

/// Largest `max_body`: a frame carries it whole.
const MAX_BODY: usize = 64 << 20;
/// Files `rules_files` names at most (RFC 0021).
pub const MAX_RULES_FILES: usize = 8;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Waf {
    pub enabled: bool,
    pub mode: Mode,
    /// `host:port` or `unix:/path`.
    pub endpoint: String,
    pub app: String,
    #[serde(
        deserialize_with = "duration",
        serialize_with = "crate::config::view::ser_duration"
    )]
    pub timeout: Duration,
    pub on_error: Fallback,
    #[serde(deserialize_with = "size")]
    pub max_body: usize,
    pub body_limit_action: Fallback,
    pub max_concurrent: usize,
    /// RFC 0021: the agent's rule files, shown on the console's WAF page.
    pub rules_files: Vec<String>,
}

/// `on_error` and `body_limit_action`: refuse the request or let it pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Fallback {
    /// `on_error` only.
    Block,
    /// `body_limit_action` only.
    Reject,
    Pass,
}

impl Default for Waf {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: Mode::Observe,
            endpoint: String::new(),
            app: "default".into(),
            timeout: Duration::from_millis(250),
            on_error: Fallback::Block,
            max_body: 16 * 1024,
            body_limit_action: Fallback::Reject,
            max_concurrent: 64,
            rules_files: Vec::new(),
        }
    }
}

impl Waf {
    /// The checks that need no agent; errors name the key.
    pub fn check(&self, reverse: bool) -> Result<(), String> {
        if self.rules_files.len() > MAX_RULES_FILES {
            return Err(format!(
                "waf.rules_files names at most {MAX_RULES_FILES} files"
            ));
        }
        if !self.enabled {
            return Ok(());
        }
        if !reverse {
            return Err("waf runs in the reverse proxy: mode = \"reverse\"".into());
        }
        if self.endpoint.is_empty() {
            return Err("waf.endpoint is required with waf.enabled".into());
        }
        if self.timeout.is_zero() {
            return Err("waf.timeout must be above 0".into());
        }
        if self.max_concurrent == 0 {
            return Err("waf.max_concurrent must be above 0".into());
        }
        if self.max_body > MAX_BODY {
            return Err(format!("waf.max_body must be at most {MAX_BODY} bytes"));
        }
        if self.on_error == Fallback::Reject {
            return Err("waf.on_error is \"block\" or \"pass\"".into());
        }
        if self.body_limit_action == Fallback::Block {
            return Err("waf.body_limit_action is \"reject\" or \"pass\"".into());
        }
        Ok(())
    }
}

/// Bytes: `16384`, `"16384"`, `"16KiB"`, `"1MiB"`.
pub fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let (n, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => s.split_at(i),
        None => (s, ""),
    };
    let mult = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        u => return Err(format!("size {s:?}: unit {u:?}, use B, KiB or MiB")),
    };
    n.parse::<usize>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| format!("size {s:?}"))
}

fn size<'de, D: Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    #[derive(Deserialize, Serialize)]
    #[serde(untagged)]
    enum Raw {
        Int(usize),
        Str(String),
    }
    match Raw::deserialize(d)? {
        Raw::Int(n) => Ok(n),
        Raw::Str(s) => parse_size(&s).map_err(de::Error::custom),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("16KiB"), Ok(16_384));
        assert_eq!(parse_size("1 MiB"), Ok(1 << 20));
        assert_eq!(parse_size("100B"), Ok(100));
        assert!(parse_size("16kb").is_err());
        assert!(parse_size("KiB").is_err());
    }

    #[test]
    fn checks_name_the_key() {
        let on = Waf {
            enabled: true,
            endpoint: "127.0.0.1:9000".into(),
            ..Waf::default()
        };
        assert_eq!(on.check(true), Ok(()));
        assert_eq!(Waf::default().check(false), Ok(()));
        assert!(on.check(false).unwrap_err().contains("reverse"));
        let bad = |f: fn(&mut Waf)| {
            let mut w = on.clone();
            f(&mut w);
            w.check(true).unwrap_err()
        };
        assert!(bad(|w| w.endpoint.clear()).contains("waf.endpoint"));
        assert!(bad(|w| w.timeout = Duration::ZERO).contains("waf.timeout"));
        assert!(bad(|w| w.max_concurrent = 0).contains("waf.max_concurrent"));
        assert!(bad(|w| w.max_body = MAX_BODY + 1).contains("waf.max_body"));
        assert!(bad(|w| w.on_error = Fallback::Reject).contains("waf.on_error"));
        assert!(bad(|w| w.body_limit_action = Fallback::Block).contains("body_limit_action"));
    }
}
