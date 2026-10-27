use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// An address block such as `192.0.2.0/24` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrError(pub String);

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid CIDR {:?}", self.0)
    }
}

impl std::error::Error for CidrError {}

impl FromStr for Cidr {
    type Err = CidrError;

    /// Accepts `addr/prefix` or a bare address (a single host).
    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!("rfc 0001")
    }
}

impl Cidr {
    pub fn contains(&self, _ip: IpAddr) -> bool {
        let _ = (self.addr, self.prefix);
        todo!("rfc 0001")
    }
}

/// Peers allowed to set `X-Forwarded-For`.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    pub fn new(cidrs: Vec<Cidr>) -> Self {
        Self(cidrs)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    #[ignore = "rfc 0001"]
    fn v4_block() {
        let c: Cidr = "192.0.2.0/24".parse().unwrap();
        assert!(c.contains(ip("192.0.2.255")));
        assert!(!c.contains(ip("192.0.3.0")));
        assert!(!c.contains(ip("2001:db8::1")));
    }

    #[test]
    #[ignore = "rfc 0001"]
    fn v6_block_and_bare_host() {
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(ip("2001:db8:ffff::1")));
        assert!(!c.contains(ip("2001:db9::1")));
        let h: Cidr = "198.51.100.7".parse().unwrap();
        assert!(h.contains(ip("198.51.100.7")));
        assert!(!h.contains(ip("198.51.100.8")));
    }

    #[test]
    #[ignore = "rfc 0001"]
    fn zero_prefix_matches_family() {
        let c: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(c.contains(ip("203.0.113.9")));
        assert!(!c.contains(ip("::1")));
    }

    #[test]
    #[ignore = "rfc 0001"]
    fn rejects_garbage() {
        for s in [
            "",
            "/",
            "192.0.2.0/33",
            "2001:db8::/129",
            "192.0.2.0/-1",
            "x/8",
            "192.0.2.0/8/8",
        ] {
            assert!(s.parse::<Cidr>().is_err(), "{s:?} parsed");
        }
    }
}
