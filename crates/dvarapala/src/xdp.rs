//! Starts the RFC 0011 XDP fast path when `xdp.interface` is set.

use std::error::Error;

use dvarapala_engine::BlockSink;

use crate::config;

/// Loads and attaches the program on `xdp.interface`. Returns the sink for
/// L4 and L7 refusals when dynamic blocks are on (`mode = "enforce"`,
/// `block_ttl` above 0). The program stays attached while the runtime
/// runs and is detached when the process exits.
pub fn start(cfg: &config::Config) -> Result<Option<BlockSink>, Box<dyn Error>> {
    if cfg.xdp.interface.is_none() {
        return Ok(None);
    }
    if !cfg!(all(feature = "xdp", target_os = "linux")) {
        return Err("xdp.interface needs a Linux build with the xdp feature".into());
    }
    let udp = cfg.quic.listen.map_or(0, |a| a.port());
    let Some(plan) = cfg.xdp.plan(cfg.listen.port(), udp)? else {
        return Ok(None);
    };
    load(plan)
}

#[cfg(all(feature = "xdp", target_os = "linux"))]
fn load(plan: config::XdpPlan) -> Result<Option<BlockSink>, Box<dyn Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    let mut x = dvarapala_xdp::Xdp::load(&plan.config)?;
    x.attach(&plan.interface, plan.attach)?;
    let x = Arc::new(x);
    let t = x.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(1));
        loop {
            every.tick().await;
            t.tick();
        }
    });
    let dynamic = plan.config.enforce && !plan.config.block_ttl.is_zero();
    Ok(dynamic.then(|| BlockSink::new(move |net| x.block(net))))
}

#[cfg(not(all(feature = "xdp", target_os = "linux")))]
fn load(_: config::XdpPlan) -> Result<Option<BlockSink>, Box<dyn Error>> {
    unreachable!("start refuses xdp.interface first")
}

#[cfg(all(test, not(all(feature = "xdp", target_os = "linux"))))]
// figment::Jail closures return figment::Error by value; not ours to box
#[allow(clippy::result_large_err)]
mod tests {
    use figment::Jail;

    // RFC 0011 case 11
    #[test]
    fn interface_needs_the_feature() {
        Jail::expect_with(|j| {
            j.set_env("DVARAPALA__UPSTREAM", "http://127.0.0.1:8081");
            j.set_env("DVARAPALA__XDP__INTERFACE", "eth0");
            let c = crate::config::load(None).map_err(|e| e.to_string())?;
            let e = super::start(&c).unwrap_err().to_string();
            assert!(e.contains("xdp feature"), "{e}");
            Ok(())
        });
    }
}
