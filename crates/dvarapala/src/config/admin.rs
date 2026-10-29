//! The `[admin]` section (RFC 0014).

use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

use super::duration;

/// Shortest bearer token accepted.
const MIN_TOKEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Admin {
    /// Empty turns the admin API off.
    pub listen: String,
    pub token: String,
    pub max_blocks: usize,
    #[serde(deserialize_with = "duration")]
    pub max_block_ttl: Duration,
}

impl Default for Admin {
    fn default() -> Self {
        Self {
            listen: String::new(),
            token: String::new(),
            max_blocks: 4096,
            max_block_ttl: Duration::from_secs(24 * 3600),
        }
    }
}

impl Admin {
    /// The listener address when the API is on, after checking the token.
    pub fn addr(&self) -> Result<Option<SocketAddr>, String> {
        if self.listen.is_empty() {
            return Ok(None);
        }
        if self.token.len() < MIN_TOKEN {
            return Err(format!(
                "admin.token must be at least {MIN_TOKEN} bytes when admin.listen is set"
            ));
        }
        if self.max_block_ttl.is_zero() {
            return Err("admin.max_block_ttl must be above 0".into());
        }
        let addr = self
            .listen
            .parse()
            .map_err(|e| format!("admin.listen {:?}: {e}", self.listen))?;
        Ok(Some(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 0014 case 11
    #[test]
    fn token_required_with_listen() {
        let off = Admin::default();
        assert_eq!(off.addr(), Ok(None));
        let mut on = Admin {
            listen: "127.0.0.1:9091".into(),
            ..Admin::default()
        };
        assert!(on.addr().unwrap_err().contains("admin.token"));
        on.token = "short".into();
        assert!(on.addr().unwrap_err().contains("admin.token"));
        on.token = "x".repeat(32);
        assert_eq!(on.addr(), Ok(Some("127.0.0.1:9091".parse().unwrap())));
        on.listen = "nope".into();
        assert!(on.addr().unwrap_err().contains("admin.listen"));
    }
}
