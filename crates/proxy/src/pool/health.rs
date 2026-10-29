use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::Empty;
#[cfg(not(feature = "tls"))]
use hyper_util::client::legacy::connect::HttpConnector;

use super::Pool;
use crate::{UpstreamConfig, UpstreamError};

/// RFC 0015 active checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthConfig {
    /// Joined onto each endpoint's base path.
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub unhealthy_after: u32,
    pub healthy_after: u32,
}

/// Starts one check task per endpoint when the pool has a health config.
/// Needs a Tokio runtime.
pub fn spawn_health(pool: &Arc<Pool>, config: &UpstreamConfig) -> Result<(), UpstreamError> {
    let Some(h) = pool.health.clone() else {
        return Ok(());
    };
    #[cfg(feature = "tls")]
    let connector = config
        .tls
        .connector(pool.https(), config.protocol)
        .map_err(UpstreamError::Tls)?;
    #[cfg(not(feature = "tls"))]
    let connector = HttpConnector::new();
    let client = config.protocol.client::<_, Empty<Bytes>>(connector);
    for (i, e) in pool.endpoints.iter().enumerate() {
        let uri = Uri::builder()
            .scheme(e.scheme.clone())
            .authority(e.authority.clone())
            .path_and_query(format!("{}{}", e.base_path, h.path))
            .build()
            .map_err(|_| UpstreamError::Invalid(format!("{}{}", e.authority, h.path)))?;
        let (pool, client, h) = (pool.clone(), client.clone(), h.clone());
        let version = config.protocol.version();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(h.interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let mut req = Request::new(Empty::new());
                *req.uri_mut() = uri.clone();
                *req.version_mut() = version;
                let ok = matches!(
                    tokio::time::timeout(h.timeout, client.request(req)).await,
                    Ok(Ok(res)) if res.status().is_success() || res.status().is_redirection()
                );
                pool.check(i, ok);
            }
        });
    }
    Ok(())
}
