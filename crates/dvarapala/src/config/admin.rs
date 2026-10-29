//! The `[admin]` section (RFC 0014) and the console keys (RFC 0018).

use std::net::SocketAddr;
use std::time::Duration;

use dvarapala_l7::secure_url;
use serde::Deserialize;

use super::duration;

/// Shortest bearer token accepted.
const MIN_TOKEN: usize = 32;
/// Longest console session.
const MAX_SESSION_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Admin {
    /// Empty turns the admin API off.
    pub listen: String,
    pub token: String,
    pub max_blocks: usize,
    #[serde(deserialize_with = "duration")]
    pub max_block_ttl: Duration,
    /// Serves the console at `/ui/`.
    pub ui_enabled: bool,
    #[serde(deserialize_with = "duration")]
    pub session_ttl: Duration,
    pub max_sessions: usize,
    /// The console's origin as the browser sees it.
    pub public_url: String,
    pub oidc: Oidc,
}

/// `[admin.oidc]`: SSO for the console; an empty `issuer` turns it off.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Oidc {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub allow_emails: Vec<String>,
    pub allow_groups: Vec<String>,
    pub groups_claim: String,
    pub label: String,
}

impl Default for Oidc {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            scopes: vec!["openid".into(), "email".into()],
            allow_emails: Vec::new(),
            allow_groups: Vec::new(),
            groups_claim: "groups".into(),
            label: "SSO".into(),
        }
    }
}

impl Default for Admin {
    fn default() -> Self {
        Self {
            listen: String::new(),
            token: String::new(),
            max_blocks: 4096,
            max_block_ttl: Duration::from_secs(24 * 3600),
            ui_enabled: false,
            session_ttl: Duration::from_secs(8 * 3600),
            max_sessions: 64,
            public_url: String::new(),
            oidc: Oidc::default(),
        }
    }
}

impl Admin {
    /// The listener address when the API is on, after checking the token.
    pub fn addr(&self) -> Result<Option<SocketAddr>, String> {
        if self.listen.is_empty() {
            if self.ui_enabled {
                return Err("admin.ui_enabled needs admin.listen".into());
            }
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
        self.console()?;
        let addr = self
            .listen
            .parse()
            .map_err(|e| format!("admin.listen {:?}: {e}", self.listen))?;
        Ok(Some(addr))
    }
}

impl Admin {
    /// The console keys (RFC 0018).
    fn console(&self) -> Result<(), String> {
        if !self.ui_enabled {
            if !self.oidc.issuer.is_empty() {
                return Err("admin.oidc.issuer needs admin.ui_enabled".into());
            }
            return Ok(());
        }
        if !cfg!(feature = "ui") {
            return Err("admin.ui_enabled: this build has no console (the ui feature)".into());
        }
        if self.session_ttl.is_zero() || self.session_ttl > MAX_SESSION_TTL {
            return Err("admin.session_ttl must be above 0 and at most 24h".into());
        }
        if self.max_sessions == 0 {
            return Err("admin.max_sessions must be above 0".into());
        }
        let o = &self.oidc;
        if o.issuer.is_empty() {
            return Ok(());
        }
        if !secure_url(&o.issuer) {
            return Err("admin.oidc.issuer must be https".into());
        }
        if !secure_url(&self.public_url) {
            return Err(
                "admin.public_url must be https (http only on a loopback host) with admin.oidc"
                    .into(),
            );
        }
        if o.client_id.is_empty() || o.client_secret.is_empty() {
            return Err("admin.oidc.client_id and admin.oidc.client_secret are required with admin.oidc.issuer".into());
        }
        if o.allow_emails.is_empty() && o.allow_groups.is_empty() {
            return Err("admin.oidc.allow_emails or admin.oidc.allow_groups must name someone: an empty rule lets nobody in".into());
        }
        Ok(())
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

    // RFC 0018 case 16
    #[test]
    fn console_keys() {
        let ui = Admin {
            ui_enabled: true,
            ..Admin::default()
        };
        assert!(ui.addr().unwrap_err().contains("admin.listen"));
        let on = Admin {
            listen: "127.0.0.1:9091".into(),
            token: "x".repeat(32),
            ..ui
        };
        if !cfg!(feature = "ui") {
            assert!(on.addr().unwrap_err().contains("ui feature"));
            return;
        }
        assert!(on.addr().is_ok());
        let oidc = |public_url: &str, emails: &[&str]| Admin {
            public_url: public_url.into(),
            oidc: Oidc {
                issuer: "https://idp.example".into(),
                client_id: "c".into(),
                client_secret: "s".into(),
                allow_emails: emails.iter().map(|e| (*e).to_owned()).collect(),
                ..Oidc::default()
            },
            ..on.clone()
        };
        assert!(oidc("https://admin.example", &["<email>"]).addr().is_ok());
        assert!(oidc("http://127.0.0.1:9091", &["<email>"]).addr().is_ok());
        let err = |a: Admin| a.addr().unwrap_err();
        assert!(err(oidc("https://admin.example", &[])).contains("allow_emails"));
        assert!(err(oidc("http://admin.example", &["<email>"])).contains("admin.public_url"));
        let off = Admin {
            ui_enabled: false,
            ..oidc("https://admin.example", &["<email>"])
        };
        assert!(err(off).contains("ui_enabled"));
        let long = Admin {
            session_ttl: Duration::from_secs(25 * 3600),
            ..on
        };
        assert!(err(long).contains("session_ttl"));
    }
}
