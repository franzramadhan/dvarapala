use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use dvarapala_engine::{Cidr, ClientKey, Reply};

use crate::{Error, Round, Store};

/// A store inside one process: clones share it. The default backend never
/// syncs to it; tests use it as two replicas' common store.
#[derive(Clone, Default)]
pub struct Memory(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    down: bool,
    replicas: HashMap<(String, String), Instant>,
    counts: HashMap<(String, u64, ClientKey), (u64, Instant)>,
    heavy: HashMap<(String, Cidr), Instant>,
    pauses: HashMap<(String, String), Instant>,
}

impl Memory {
    /// While down, every round fails, as if the store went away.
    pub fn set_down(&self, down: bool) {
        self.lock().down = down;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store for Memory {
    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        let now = Instant::now();
        let mut s = self.lock();
        if s.down {
            return Err(Error("store down".into()));
        }
        let c = r.cluster.to_owned();
        s.replicas.retain(|_, t| *t > now);
        s.counts.retain(|_, (_, t)| *t > now);
        s.heavy.retain(|_, t| *t > now);
        s.pauses.retain(|_, t| *t > now);
        s.replicas
            .insert((c.clone(), r.replica.to_owned()), now + r.heartbeat);
        let replicas = s.replicas.keys().filter(|(k, _)| *k == c).count() as u32;
        let expires = now + r.window * 2;
        let totals = r
            .batch
            .counts
            .iter()
            .map(|&(key, n)| {
                let e = s
                    .counts
                    .entry((c.clone(), r.batch.window_start, key))
                    .or_insert((0, expires));
                e.0 += u64::from(n);
                (key, e.0)
            })
            .collect();
        for &(net, ttl) in &r.batch.heavy {
            let t = s.heavy.entry((c.clone(), net)).or_insert(now);
            *t = (*t).max(now + ttl);
        }
        for (name, ttl) in &r.batch.pauses {
            let t = s.pauses.entry((c.clone(), name.clone())).or_insert(now);
            *t = (*t).max(now + *ttl);
        }
        let heavy = s
            .heavy
            .iter()
            .filter(|((k, _), _)| *k == c)
            .take(r.max_list)
            .map(|((_, net), t)| (*net, *t - now))
            .collect();
        let pauses = s
            .pauses
            .iter()
            .filter(|((k, _), _)| *k == c)
            .take(r.max_list)
            .map(|((_, name), t)| (name.clone(), *t - now))
            .collect();
        Ok(Reply {
            replicas,
            totals,
            heavy,
            pauses,
        })
    }
}
