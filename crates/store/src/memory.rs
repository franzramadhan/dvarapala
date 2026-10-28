#![allow(unused_variables, unused_imports, unused_mut, dead_code)]
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
        todo!("rfc 0010")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        todo!("rfc 0010")
    }
}

impl Store for Memory {
    async fn round(&mut self, r: &Round<'_>) -> Result<Reply, Error> {
        todo!("rfc 0010")
    }
}
