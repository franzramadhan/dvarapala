//! RFC 0017: the `[waf]` stage between the rate limiter and the proxy.
//! Built even when off, so a reload can turn it on.

#[cfg(not(feature = "waf"))]
use std::convert::Infallible;

#[cfg(feature = "waf")]
pub use dvarapala_l7::{WafBody as Body, WafLayer as Layer};

use crate::config;

/// The `[waf]` keys as the layer takes them; `None` when off.
#[cfg(feature = "waf")]
pub fn config(cfg: &config::Config) -> Result<Option<dvarapala_l7::WafConfig>, String> {
    use dvarapala_engine::{Cidr, TrustedProxies};
    use dvarapala_l7::{Endpoint, WafConfig};

    let w = &cfg.waf;
    w.check(cfg.mode == config::ProxyMode::Reverse)?;
    if !w.enabled {
        return Ok(None);
    }
    let endpoint = Endpoint::parse(&w.endpoint).map_err(|e| format!("waf.endpoint {e}"))?;
    if !endpoint.is_local() {
        tracing::warn!(
            endpoint = %w.endpoint,
            "waf.endpoint is not loopback or a unix socket: requests cross the network in clear"
        );
    }
    let trusted = cfg
        .trusted_proxies
        .iter()
        .map(|c| {
            c.parse::<Cidr>()
                .map_err(|e| format!("trusted_proxies: {e}"))
        })
        .collect::<Result<_, _>>()?;
    Ok(Some(WafConfig {
        enforce: w.mode == config::Mode::Enforce,
        endpoint,
        app: w.app.clone(),
        timeout: w.timeout,
        fail_open: w.on_error == config::Fallback::Pass,
        max_body: w.max_body,
        reject_over_limit: w.body_limit_action == config::Fallback::Reject,
        max_concurrent: w.max_concurrent,
        trusted: TrustedProxies::new(trusted),
        listen: cfg.listen,
    }))
}

/// A build without the `waf` feature refuses `waf.enabled`.
#[cfg(not(feature = "waf"))]
pub fn config(cfg: &config::Config) -> Result<Option<Infallible>, String> {
    cfg.waf.check(cfg.mode == config::ProxyMode::Reverse)?;
    if cfg.waf.enabled {
        return Err("waf.enabled needs a build with the waf feature".into());
    }
    Ok(None)
}

#[cfg(not(feature = "waf"))]
pub type Body<B> = B;

/// Never inspects: the service passes through.
#[cfg(not(feature = "waf"))]
#[derive(Clone, Default)]
pub struct Layer;

#[cfg(not(feature = "waf"))]
impl Layer {
    pub fn new(_: Option<Infallible>) -> Self {
        Self
    }

    pub fn reload(&self, _: Option<Infallible>) {}
}

#[cfg(not(feature = "waf"))]
impl<S> tower_layer::Layer<S> for Layer {
    type Service = S;

    fn layer(&self, inner: S) -> S {
        inner
    }
}
