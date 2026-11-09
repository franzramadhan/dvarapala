use std::net::IpAddr;
use std::sync::Arc;

use dvarapala_engine::{ConnsConfig, ConnsError, Refused};

/// When a connection is counted against its client (RFC 0036): only on an
/// address that is proven, so a spoofed source never takes a place.
// used by the endpoint in the layer that implements the limits
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum When {
    /// A valid Retry token came with the Initial.
    Accept,
    /// Otherwise: once the handshake has completed.
    Handshake,
}

#[allow(dead_code)]
impl When {
    pub(crate) fn of(validated: bool) -> Self {
        if validated {
            Self::Accept
        } else {
            Self::Handshake
        }
    }
}

/// The per-client table of a QUIC listener, apart from the TCP one.
pub struct ClientLimits(());

/// One connection's place; dropping it frees the place.
pub struct ClientGuard(());

impl ClientLimits {
    pub fn new(config: &ConnsConfig) -> Result<Arc<Self>, ConnsError> {
        let _ = config;
        todo!("rfc 0036")
    }

    /// A place for a connection from the proven address `ip`, or the
    /// refusal, counted and logged at most once a second.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ClientGuard, Refused> {
        let _ = ip;
        todo!("rfc 0036")
    }

    /// Entries in the table.
    pub fn clients(&self) -> usize {
        todo!("rfc 0036")
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn limits(tune: impl FnOnce(&mut ConnsConfig)) -> Arc<ClientLimits> {
        let mut c = ConnsConfig::default();
        tune(&mut c);
        ClientLimits::new(&c).unwrap()
    }

    // case 6: an address that is not proven is not counted
    #[test]
    #[ignore = "rfc 0036"]
    fn spoofed_sources_take_no_place() {
        assert_eq!(When::of(false), When::Handshake);
        assert_eq!(When::of(true), When::Accept);
        assert_eq!(limits(|_| {}).clients(), 0);
    }

    // case 8
    #[test]
    #[ignore = "rfc 0036"]
    fn prefix_groups_clients() {
        let l = limits(|c| {
            c.prefix_v6 = 64;
            c.max_per_client = 1;
        });
        let _a = l.admit(ip("2001:db8::1")).unwrap();
        assert_eq!(l.admit(ip("2001:db8::2")).err(), Some(Refused::PerClient));
        assert_eq!(l.clients(), 1);
        assert!(l.admit(ip("2001:db8:0:1::1")).is_ok());
    }

    // case 9
    #[test]
    #[ignore = "rfc 0036"]
    fn full_table_evicts_the_least_recently_seen() {
        let l = limits(|c| c.max_clients = NonZeroUsize::new(2).unwrap());
        let a = l.admit(ip("192.0.2.1")).unwrap();
        let _b = l.admit(ip("192.0.2.2")).unwrap();
        drop(a);
        let _c = l.admit(ip("192.0.2.3")).unwrap();
        assert_eq!(l.clients(), 2);
    }

    #[test]
    #[ignore = "rfc 0036"]
    fn dropping_the_guard_frees_the_place() {
        let l = limits(|c| c.max_per_client = 1);
        let g = l.admit(ip("192.0.2.1")).unwrap();
        assert!(l.admit(ip("192.0.2.1")).is_err());
        drop(g);
        assert!(l.admit(ip("192.0.2.1")).is_ok());
    }
}
