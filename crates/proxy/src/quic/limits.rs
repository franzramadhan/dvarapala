use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{ConnKey, Conns, ConnsConfig, ConnsError, Refused};

/// When a connection is counted against its client (RFC 0036): only on an
/// address that is proven, so a spoofed source never takes a place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum When {
    /// A valid Retry token came with the Initial.
    Accept,
    /// Otherwise: once the handshake has completed.
    Handshake,
}

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
pub struct ClientLimits {
    conns: Mutex<Conns>,
    /// unix second of the last "quic connection limit" log
    logged: AtomicU64,
}

/// One connection's place; dropping it frees the place.
pub struct ClientGuard {
    limits: Arc<ClientLimits>,
    key: ConnKey,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        let mut conns = self.limits.lock();
        conns.close(self.key);
        metrics::gauge!("dvarapala_quic_clients").set(conns.clients() as f64);
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {}
}

impl ClientLimits {
    pub fn new(config: &ConnsConfig) -> Result<Arc<Self>, ConnsError> {
        Ok(Arc::new(Self {
            conns: Mutex::new(Conns::new(config.clone())?),
            logged: AtomicU64::new(0),
        }))
    }

    /// A place for a connection from the proven address `ip`, or the
    /// refusal, counted and logged at most once a second.
    pub fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<ClientGuard, Refused> {
        let mut conns = self.lock();
        let key = conns.open(ip, Instant::now()).map_err(|r| {
            self.refused(r, ip);
            r
        })?;
        metrics::gauge!("dvarapala_quic_clients").set(conns.clients() as f64);
        Ok(ClientGuard {
            limits: self.clone(),
            key,
        })
    }

    /// Entries in the table.
    pub fn clients(&self) -> usize {
        self.lock().clients()
    }

    fn refused(&self, reason: Refused, ip: IpAddr) {
        let reason = reason.as_str();
        metrics::counter!("dvarapala_quic_rejected_total", "reason" => reason).increment(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if self.logged.swap(now, Ordering::Relaxed) != now {
            tracing::warn!(reason, client = %ip, "quic connection limit");
        }
    }

    fn lock(&self) -> MutexGuard<'_, Conns> {
        // counts only; a panic mid-update loses at most one count
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
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
    fn spoofed_sources_take_no_place() {
        assert_eq!(When::of(false), When::Handshake);
        assert_eq!(When::of(true), When::Accept);
        assert_eq!(limits(|_| {}).clients(), 0);
    }

    // case 8
    #[test]
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
    fn full_table_evicts_the_least_recently_seen() {
        let l = limits(|c| c.max_clients = NonZeroUsize::new(2).unwrap());
        let a = l.admit(ip("192.0.2.1")).unwrap();
        let _b = l.admit(ip("192.0.2.2")).unwrap();
        drop(a);
        let _c = l.admit(ip("192.0.2.3")).unwrap();
        assert_eq!(l.clients(), 2);
    }

    #[test]
    fn dropping_the_guard_frees_the_place() {
        let l = limits(|c| c.max_per_client = 1);
        let g = l.admit(ip("192.0.2.1")).unwrap();
        assert!(l.admit(ip("192.0.2.1")).is_err());
        drop(g);
        assert!(l.admit(ip("192.0.2.1")).is_ok());
    }
}
