use std::fmt;

use crate::Cidr;

/// Longest line read, comment included.
pub const MAX_LINE: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedError {
    /// More than `max_entries` networks.
    TooMany,
    /// A line that is not a network, numbered from 1.
    Line(usize, String),
}

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany => f.write_str("more entries than max_entries"),
            Self::Line(n, e) => write!(f, "line {n}: {e}"),
        }
    }
}

impl std::error::Error for FeedError {}

/// A feed body: one CIDR or address per line, `#` and `;` start a
/// comment, blank lines are skipped. Prefixes shorter than /8 (IPv4) or
/// /16 (IPv6) are refused, so a broken list cannot cover everyone.
pub fn parse_feed(body: &str, max_entries: usize) -> Result<Vec<Cidr>, FeedError> {
    let _ = (body, max_entries);
    todo!("rfc 0031")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0031 case 1
    #[test]
    #[ignore = "rfc 0031"]
    fn cidrs_addresses_comments_and_blank_lines() {
        let body = "; Spamhaus DROP List\n\
                    # generated\n\
                    \n\
                    192.0.2.0/24 ; SBL123\n\
                    198.51.100.7\n\
                    \t2001:db8::/32   # docs\n\
                    203.0.113.0/25;SBL9\r\n";
        let got = parse_feed(body, 10).unwrap();
        let want: Vec<Cidr> = [
            "192.0.2.0/24",
            "198.51.100.7",
            "2001:db8::/32",
            "203.0.113.0/25",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(got, want);
        assert_eq!(parse_feed("", 0), Ok(Vec::new()));
    }

    #[test]
    #[ignore = "rfc 0031"]
    fn a_malformed_line_names_its_number() {
        let e = parse_feed("192.0.2.0/24\n# x\nexample.com\n", 10).unwrap_err();
        assert!(matches!(e, FeedError::Line(3, _)), "{e:?}");
        assert!(e.to_string().starts_with("line 3:"), "{e}");
        let long = format!("192.0.2.1 #{}", "x".repeat(MAX_LINE));
        assert!(matches!(parse_feed(&long, 10), Err(FeedError::Line(1, _))));
    }

    #[test]
    #[ignore = "rfc 0031"]
    fn too_wide_prefixes_and_too_many_entries_are_refused() {
        for wide in ["0.0.0.0/0", "10.0.0.0/7", "::/0", "2001::/15"] {
            assert!(parse_feed(wide, 10).is_err(), "{wide}");
        }
        assert!(parse_feed("10.0.0.0/8\n2001:db8::/16", 10).is_ok());
        let two = "192.0.2.1\n192.0.2.2\n";
        assert_eq!(parse_feed(two, 1), Err(FeedError::TooMany));
        assert_eq!(parse_feed(two, 2).unwrap().len(), 2);
    }
}
