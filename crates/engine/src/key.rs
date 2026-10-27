use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::TrustedProxies;

/// Who a request is counted against. IPv6 clients are keyed per /64 so one
/// host cannot rotate addresses inside its own subnet to dodge a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    V4(Ipv4Addr),
    /// The upper 64 bits of the address.
    V6(u64),
}

impl From<IpAddr> for ClientKey {
    fn from(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(a) => Self::V4(a),
            IpAddr::V6(a) => Self::V6((u128::from(a) >> 64) as u64),
        }
    }
}

/// The address a key stands for: the IPv4 address, or the /64 network.
impl From<ClientKey> for IpAddr {
    fn from(_key: ClientKey) -> Self {
        todo!("rfc 0002")
    }
}

impl fmt::Display for ClientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(a) => write!(f, "{a}"),
            Self::V6(p) => write!(f, "{}/64", Ipv6Addr::from(u128::from(p) << 64)),
        }
    }
}

/// The client behind `peer`. `X-Forwarded-For` counts only when `peer` is a
/// trusted proxy; then the rightmost untrusted hop is the client. Anything
/// malformed falls back to `peer`, never to a value the client chose.
pub fn client_key(peer: IpAddr, xff: Option<&str>, trusted: &TrustedProxies) -> ClientKey {
    let fallback = ClientKey::from(peer);
    let Some(xff) = xff.filter(|_| trusted.contains(peer)) else {
        return fallback;
    };
    let mut leftmost = None;
    for (n, hop) in xff.rsplit(',').enumerate() {
        if n == MAX_HOPS {
            return fallback;
        }
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            return fallback;
        };
        if !trusted.contains(ip) {
            return ip.into();
        }
        leftmost = Some(ip);
    }
    leftmost.map_or(fallback, ClientKey::from)
}

/// Hops read from `X-Forwarded-For` before giving up and using the peer,
/// so a huge header costs bounded work.
const MAX_HOPS: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cidr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn trusted(cidrs: &[&str]) -> TrustedProxies {
        TrustedProxies::new(cidrs.iter().map(|c| c.parse::<Cidr>().unwrap()).collect())
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let k = client_key(ip("192.0.2.10"), Some("198.51.100.7"), &trusted(&[]));
        assert_eq!(k, ClientKey::from(ip("192.0.2.10")));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_hop() {
        let t = trusted(&["192.0.2.0/24"]);
        let k = client_key(ip("192.0.2.1"), Some("198.51.100.7, 192.0.2.1"), &t);
        assert_eq!(k, ClientKey::from(ip("198.51.100.7")));
        // a spoofed leftmost entry does not win over the real hop
        let k = client_key(ip("192.0.2.1"), Some("203.0.113.1, 198.51.100.7"), &t);
        assert_eq!(k, ClientKey::from(ip("198.51.100.7")));
    }

    #[test]
    fn malformed_xff_falls_back_to_peer() {
        let t = trusted(&["192.0.2.0/24"]);
        for xff in ["", " , ", "not-an-ip", "198.51.100.7, garbage", "999.1.1.1"] {
            let k = client_key(ip("192.0.2.1"), Some(xff), &t);
            assert_eq!(k, ClientKey::from(ip("192.0.2.1")), "xff {xff:?}");
        }
    }

    #[test]
    fn all_hops_trusted_uses_leftmost() {
        let t = trusted(&["192.0.2.0/24"]);
        let k = client_key(ip("192.0.2.1"), Some("192.0.2.5, 192.0.2.6"), &t);
        assert_eq!(k, ClientKey::from(ip("192.0.2.5")));
    }

    #[test]
    fn ipv6_keyed_per_64() {
        let a = ClientKey::from(ip("2001:db8::1"));
        let b = ClientKey::from(ip("2001:db8::ffff:1"));
        let c = ClientKey::from(ip("2001:db8:0:1::1"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.to_string(), "2001:db8::/64");
    }

    #[test]
    fn ipv4_mapped_v6_is_v4() {
        assert_eq!(
            ClientKey::from(ip("::ffff:192.0.2.1")),
            ClientKey::from(ip("192.0.2.1"))
        );
    }

    #[test]
    fn too_many_hops_falls_back_to_peer() {
        let t = trusted(&["192.0.2.0/24"]);
        let xff = vec!["192.0.2.9"; 100].join(", ");
        let k = client_key(ip("192.0.2.1"), Some(&xff), &t);
        assert_eq!(k, ClientKey::from(ip("192.0.2.1")));
    }

    #[test]
    #[ignore = "rfc 0002"]
    fn key_back_to_address() {
        assert_eq!(
            IpAddr::from(ClientKey::from(ip("192.0.2.1"))),
            ip("192.0.2.1")
        );
        assert_eq!(
            IpAddr::from(ClientKey::from(ip("2001:db8:1:2:3::9"))),
            ip("2001:db8:1:2::")
        );
    }
}
