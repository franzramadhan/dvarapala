use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use dvarapala_engine::{ConnKey, Conns};

use crate::{L4Config, L4Error};

/// The open-connection counts behind a [`crate::Listener`].
pub(crate) struct Limits {
    conns: Mutex<Conns>,
    open: AtomicUsize,
    /// 0 off
    max_connections: usize,
    /// unix second of the last "connection limit" log
    logged: AtomicU64,
}

/// One accepted connection's place; dropping it frees the place.
pub(crate) struct Guard {
    limits: Arc<Limits>,
    key: Option<ConnKey>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let mut conns = self.limits.lock();
            conns.close(key);
            metrics::gauge!("dvarapala_l4_clients").set(conns.clients() as f64);
        }
        self.limits.open.fetch_sub(1, Ordering::AcqRel);
        metrics::gauge!("dvarapala_l4_connections_open").decrement(1.0);
    }
}

impl Limits {
    pub(crate) fn new(config: &L4Config) -> Result<Arc<Self>, L4Error> {
        let conns = Conns::new(config.conns.clone()).map_err(|e| L4Error(e.0))?;
        Ok(Arc::new(Self {
            conns: Mutex::new(conns),
            open: AtomicUsize::new(0),
            max_connections: config.max_connections,
            logged: AtomicU64::new(0),
        }))
    }

    /// A place for a connection from `ip`, or the refusal, counted and
    /// logged at most once a second.
    pub(crate) fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<Guard, &'static str> {
        let mut guard = self.total(ip)?;
        self.client(&mut guard, ip)?;
        Ok(guard)
    }

    /// A place against `max_connections` only, for a connection whose
    /// client is not known yet (RFC 0030); `peer` is for the log.
    pub(crate) fn total(self: &Arc<Self>, peer: IpAddr) -> Result<Guard, &'static str> {
        let open = self.open.fetch_add(1, Ordering::AcqRel);
        // from here the guard gives the place back, also on refusal
        let guard = Guard {
            limits: self.clone(),
            key: None,
        };
        metrics::gauge!("dvarapala_l4_connections_open").increment(1.0);
        if self.max_connections > 0 && open >= self.max_connections {
            return Err(self.refused("total", peer));
        }
        Ok(guard)
    }

    /// Counts the connection holding `guard` against client `ip`.
    pub(crate) fn client(&self, guard: &mut Guard, ip: IpAddr) -> Result<(), &'static str> {
        let mut conns = self.lock();
        let key = conns
            .open(ip, Instant::now())
            .map_err(|r| self.refused(r.as_str(), ip))?;
        metrics::gauge!("dvarapala_l4_clients").set(conns.clients() as f64);
        guard.key = Some(key);
        Ok(())
    }

    /// Counts and logs a refusal, the log at most once a second.
    fn refused(&self, reason: &'static str, ip: IpAddr) -> &'static str {
        metrics::counter!("dvarapala_l4_rejected_total", "reason" => reason).increment(1);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if self.logged.swap(now, Ordering::Relaxed) != now {
            tracing::warn!(reason, client = %ip, "connection limit");
        }
        reason
    }

    fn lock(&self) -> MutexGuard<'_, Conns> {
        // counts only; a panic mid-update loses at most one count
        self.conns.lock().unwrap_or_else(|e| e.into_inner())
    }
}
