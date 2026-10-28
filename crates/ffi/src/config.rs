use std::num::NonZeroUsize;

use dvarapala_engine::{ConnsConfig, GuardConfig, TrustedProxies};

/// What a guard is built from: `CONFIG.md` key names and string values.
#[derive(Debug, Default, Clone)]
pub(crate) struct Settings(pub(crate) Vec<(String, String)>);

/// The guard's parts, validated.
#[derive(Debug)]
pub(crate) struct Built {
    pub(crate) guard: GuardConfig,
    pub(crate) trusted: TrustedProxies,
    /// `None` with `l4.enabled = false`
    pub(crate) conns: Option<ConnsConfig>,
    /// 0 off
    pub(crate) max_connections: usize,
}

impl Settings {
    /// The parts, or an error naming the key.
    pub(crate) fn build(&self) -> Result<Built, String> {
        let _ = NonZeroUsize::MIN;
        todo!("rfc 0008")
    }
}
