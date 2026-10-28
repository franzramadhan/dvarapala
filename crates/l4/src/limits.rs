use std::net::IpAddr;
use std::sync::Arc;

use dvarapala_engine::ConnKey;

use crate::{L4Config, L4Error};

/// The open-connection counts behind a [`crate::Listener`].
// rfc 0009: stubs until the implementation layer
#[allow(dead_code)]
pub(crate) struct Limits {
    _todo: (),
}

/// One accepted connection's place; dropping it frees the place.
#[allow(dead_code)]
pub(crate) struct Guard {
    _limits: Arc<Limits>,
    _key: ConnKey,
}

#[allow(dead_code)]
impl Limits {
    pub(crate) fn new(config: &L4Config) -> Result<Arc<Self>, L4Error> {
        let _ = config;
        todo!("rfc 0009")
    }

    /// A place for a connection from `ip`, or the `reason` label.
    pub(crate) fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<Guard, &'static str> {
        let _ = ip;
        todo!("rfc 0009")
    }
}
