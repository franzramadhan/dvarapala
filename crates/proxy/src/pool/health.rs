#![allow(unused_variables, unused_imports, dead_code, unreachable_code)]
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
    todo!("rfc 0015")
}
