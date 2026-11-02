use std::fmt;
use std::net::IpAddr;

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
    let mut out = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let err = |e: &str| FeedError::Line(i + 1, e.into());
        if line.len() > MAX_LINE {
            return Err(err("longer than 128 bytes"));
        }
        let entry = line.split(['#', ';']).next().unwrap_or("").trim();
        if entry.is_empty() {
            continue;
        }
        let net: Cidr = entry.parse().map_err(|_| err("not a CIDR or an address"))?;
        // a mapped IPv4 network is looked up as IPv4: /8 in its last 32 bits
        let min = match net.addr() {
            IpAddr::V4(_) => 8,
            IpAddr::V6(a) if a.to_ipv4_mapped().is_some() => 104,
            IpAddr::V6(_) => 16,
        };
        if net.prefix() < min {
            return Err(err("prefix shorter than /8 (IPv4) or /16 (IPv6)"));
        }
        if out.len() == max_entries {
            return Err(FeedError::TooMany);
        }
        out.push(net);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0031 case 1
    #[test]
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
    fn a_malformed_line_names_its_number() {
        let e = parse_feed("192.0.2.0/24\n# x\nexample.com\n", 10).unwrap_err();
        assert!(matches!(e, FeedError::Line(3, _)), "{e:?}");
        assert!(e.to_string().starts_with("line 3:"), "{e}");
        let long = format!("192.0.2.1 #{}", "x".repeat(MAX_LINE));
        assert!(matches!(parse_feed(&long, 10), Err(FeedError::Line(1, _))));
    }

    #[test]
    fn too_wide_prefixes_and_too_many_entries_are_refused() {
        for wide in [
            "0.0.0.0/0",
            "10.0.0.0/7",
            "::/0",
            "2001::/15",
            "::ffff:0.0.0.0/96",
        ] {
            assert!(parse_feed(wide, 10).is_err(), "{wide}");
        }
        assert!(parse_feed("10.0.0.0/8\n2001:db8::/16", 10).is_ok());
        let two = "192.0.2.1\n192.0.2.2\n";
        assert_eq!(parse_feed(two, 1), Err(FeedError::TooMany));
        assert_eq!(parse_feed(two, 2).unwrap().len(), 2);
    }
}
