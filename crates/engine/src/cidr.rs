use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// An address block such as `192.0.2.0/24` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || CidrError(s.to_owned());
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| err())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            // u8 parsing rejects signs, spaces and a second slash
            Some(p) => p.parse::<u8>().ok().filter(|&p| p <= max).ok_or_else(err)?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl Cidr {
    /// The `prefix`-bit block holding `ip`, host bits cleared. `prefix` is
    /// capped at the family's width.
    pub fn of(ip: IpAddr, prefix: u8) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(a) => {
                let prefix = prefix.min(32);
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                Self {
                    addr: IpAddr::V4((u32::from(a) & mask).into()),
                    prefix,
                }
            }
            IpAddr::V6(a) => {
                let prefix = prefix.min(128);
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                Self {
                    addr: IpAddr::V6((u128::from(a) & mask).into()),
                    prefix,
                }
            }
        }
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// Where L4 and L7 report sources to block earlier, at the XDP fast path
/// (RFC 0011). Called from the request path: it must not block.
#[derive(Clone)]
pub struct BlockSink(Arc<dyn Fn(Cidr) + Send + Sync>);

impl BlockSink {
    pub fn new(f: impl Fn(Cidr) + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    pub fn block(&self, net: Cidr) {
        (self.0)(net)
    }
}

impl fmt::Debug for BlockSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlockSink")
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
    fn v4_block() {
        let c: Cidr = "192.0.2.0/24".parse().unwrap();
        assert!(c.contains(ip("192.0.2.255")));
        assert!(!c.contains(ip("192.0.3.0")));
        assert!(!c.contains(ip("2001:db8::1")));
    }

    #[test]
    fn v6_block_and_bare_host() {
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains(ip("2001:db8:ffff::1")));
        assert!(!c.contains(ip("2001:db9::1")));
        let h: Cidr = "198.51.100.7".parse().unwrap();
        assert!(h.contains(ip("198.51.100.7")));
        assert!(!h.contains(ip("198.51.100.8")));
    }

    #[test]
    fn zero_prefix_matches_family() {
        let c: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(c.contains(ip("203.0.113.9")));
        assert!(!c.contains(ip("::1")));
    }

    #[test]
    fn of_clears_host_bits() {
        assert_eq!(Cidr::of(ip("192.0.2.77"), 24).to_string(), "192.0.2.0/24");
        assert_eq!(Cidr::of(ip("192.0.2.77"), 40).to_string(), "192.0.2.77/32");
        assert_eq!(
            Cidr::of(ip("2001:db8:1:2:3::9"), 48).to_string(),
            "2001:db8:1::/48"
        );
        // v4-mapped v6 groups with plain v4
        assert_eq!(
            Cidr::of(ip("::ffff:192.0.2.77"), 32),
            Cidr::of(ip("192.0.2.77"), 32)
        );
    }

    #[test]
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

    #[test]
    fn block_sink_hands_networks_to_its_callback() {
        use std::sync::Mutex;
        let got = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&got);
        let sink = BlockSink::new(move |n| seen.lock().unwrap().push(n));
        let net: Cidr = "192.0.2.0/24".parse().unwrap();
        sink.clone().block(net);
        assert_eq!(*got.lock().unwrap(), [net]);
        assert_eq!(format!("{sink:?}"), "BlockSink");
    }
}
