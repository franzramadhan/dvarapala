//! Starts the RFC 0011 XDP fast path when `xdp.interface` is set.
#![allow(unused_variables, unused_imports, dead_code)]

use std::error::Error;

use dvarapala_engine::BlockSink;

use crate::config;

/// Loads and attaches the program on `xdp.interface`. Returns the sink for
/// L4 and L7 refusals when dynamic blocks are on (`mode = "enforce"`,
/// `block_ttl` above 0). The program stays attached while the runtime
/// runs and is detached when the process exits.
pub fn start(cfg: &config::Config) -> Result<Option<BlockSink>, Box<dyn Error>> {
    todo!("rfc 0011")
}

#[cfg(all(feature = "xdp", target_os = "linux"))]
fn load(plan: config::XdpPlan) -> Result<Option<BlockSink>, Box<dyn Error>> {
    todo!("rfc 0011")
}

#[cfg(not(all(feature = "xdp", target_os = "linux")))]
fn load(_: config::XdpPlan) -> Result<Option<BlockSink>, Box<dyn Error>> {
    todo!("rfc 0011")
}

#[cfg(all(test, not(feature = "xdp")))]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use figment::Jail;

    // RFC 0011 case 11
    #[test]
    #[ignore = "rfc 0011"]
    fn interface_needs_the_feature() {
        todo!("rfc 0011")
    }
}
