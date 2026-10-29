//! OIDC login for the admin console (RFC 0018): the authorization code
//! flow with PKCE, the callback and the ID token's claims. No I/O: the
//! binary fetches discovery and exchanges the code.
#![allow(unused_variables, unused_imports, dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::digest::{SHA256, digest};
use serde_json::Value;

use crate::admin::{param, secure_url};
use crate::session::random;

/// Pending logins at most; the oldest is dropped for a new one.
pub const MAX_PENDING: usize = 64;
/// How long a login may take at the issuer.
pub const PENDING_TTL: Duration = Duration::from_secs(600);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// `<public_url>/session/oidc/callback`
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub allow_emails: Vec<String>,
    pub allow_groups: Vec<String>,
    pub groups_claim: String,
}

/// The endpoints discovery names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// Why a login did not open a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// The token or the callback is not acceptable.
    Invalid(String),
    /// A valid login by someone not in the allow lists; the subject.
    NotAllowed(String),
}

pub fn discovery_url(issuer: &str) -> String {
    todo!("rfc 0018")
}

/// The provider from a discovery document, which must name `issuer`.
pub fn provider(doc: &[u8], issuer: &str) -> Result<Provider, String> {
    todo!("rfc 0018")
}

/// A login waiting for the issuer's redirect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub verifier: String,
    pub nonce: String,
    started: Instant,
}

/// Pending logins by `state`, single use, bounded.
#[derive(Default)]
pub struct Logins {
    map: Mutex<HashMap<String, Pending>>,
}

impl Logins {
    /// Starts a login; the URL to send the browser to.
    pub fn begin(&self, cfg: &OidcConfig, p: &Provider, now: Instant) -> String {
        todo!("rfc 0018")
    }

    /// The login behind `state`, removed: a second callback finds nothing.
    pub fn take(&self, state: &str, now: Instant) -> Option<Pending> {
        todo!("rfc 0018")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        todo!("rfc 0018")
    }
}

/// `code` and `state` from the redirect, or the issuer's `error`.
pub fn callback(query: Option<&str>) -> Result<(String, String), Denied> {
    todo!("rfc 0018")
}

/// The token request body (`client_secret_post`).
pub fn token_request(cfg: &OidcConfig, code: &str, verifier: &str) -> String {
    todo!("rfc 0018")
}

/// `id_token` from the token endpoint's answer.
pub fn id_token(body: &[u8]) -> Result<String, Denied> {
    todo!("rfc 0018")
}

/// Checks the ID token's claims and the allow lists; the subject on
/// success. The signature is not checked: the token came straight from the
/// token endpoint over verified TLS (OIDC Core 3.1.3.7).
pub fn check(cfg: &OidcConfig, id_token: &str, nonce: &str, now: u64) -> Result<String, Denied> {
    todo!("rfc 0018")
}

/// 256 random bits, base64url: `state`, `nonce` and the PKCE verifier.
fn token() -> String {
    todo!("rfc 0018")
}

/// Percent-encodes everything but the unreserved characters.
pub fn enc(s: &str) -> String {
    todo!("rfc 0018")
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url(b: &[u8]) -> String {
    todo!("rfc 0018")
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    todo!("rfc 0018")
}

/// RFC 0018 case 7: a callback query on the first line, an ID token
/// payload (before base64url) after it. Never panics.
pub fn fuzz_oidc_callback(data: &[u8]) {
    todo!("rfc 0018")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://idp.example";

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: ISS.into(),
            client_id: "dvarapala".into(),
            client_secret: "<secret>".into(),
            redirect_uri: "https://admin.example/session/oidc/callback".into(),
            scopes: vec!["openid".into(), "email".into()],
            allow_emails: vec!["ops@example.com".into()],
            allow_groups: vec![],
            groups_claim: "groups".into(),
        }
    }

    fn jwt(claims: &str) -> String {
        format!("eyJhbGciOiJSUzI1NiJ9.{}.c2ln", b64url(claims.as_bytes()))
    }

    fn query(url: &str) -> HashMap<String, String> {
        let q = url.split_once('?').unwrap().1;
        q.split('&')
            .map(|kv| kv.split_once('=').unwrap())
            .map(|(k, _)| (k.to_owned(), param(q, k).unwrap().unwrap()))
            .collect()
    }

    // RFC 0018 case 3
    #[test]
    #[ignore = "rfc 0018"]
    fn authorization_url_with_pkce() {
        let p = Provider {
            authorization_endpoint: format!("{ISS}/auth"),
            token_endpoint: format!("{ISS}/token"),
        };
        let logins = Logins::default();
        let now = Instant::now();
        let a = query(&logins.begin(&cfg(), &p, now));
        let b = query(&logins.begin(&cfg(), &p, now));
        assert_eq!(a["response_type"], "code");
        assert_eq!(a["code_challenge_method"], "S256");
        assert_eq!(a["client_id"], "dvarapala");
        assert_eq!(a["scope"], "openid email");
        assert_eq!(a["redirect_uri"], cfg().redirect_uri);
        assert_ne!(a["state"], b["state"]);
        assert_ne!(a["nonce"], b["nonce"]);
        let pending = logins.take(&a["state"], now).unwrap();
        assert_eq!(pending.nonce, a["nonce"]);
        let challenge = b64url(digest(&SHA256, pending.verifier.as_bytes()).as_ref());
        assert_eq!(a["code_challenge"], challenge);
        assert_eq!(pending.verifier.len(), 43);
    }

    // RFC 0018 case 4
    #[test]
    #[ignore = "rfc 0018"]
    fn claims_are_checked() {
        let ok = r#"{"iss":"https://idp.example","aud":"dvarapala","exp":2000,"nonce":"n","sub":"1","email":"Ops@example.com","email_verified":true}"#;
        assert_eq!(
            check(&cfg(), &jwt(ok), "n", 1000),
            Ok("Ops@example.com".into())
        );
        let with = |from: &str, to: &str| jwt(&ok.replace(from, to));
        let reason = |t: String, now| match check(&cfg(), &t, "n", now) {
            Err(Denied::Invalid(r)) => r,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            reason(with("idp.example", "evil.example"), 1000),
            "iss mismatch"
        );
        assert_eq!(
            reason(with(r#""aud":"dvarapala""#, r#""aud":"other""#), 1000),
            "aud mismatch"
        );
        assert_eq!(reason(jwt(ok), 2000), "expired");
        assert_eq!(
            reason(with(r#""nonce":"n""#, r#""nonce":"m""#), 1000),
            "nonce mismatch"
        );
        assert_eq!(
            check(&cfg(), &with("true", "false"), "n", 1000),
            Err(Denied::NotAllowed("Ops@example.com".into()))
        );
        let aud_list = with(r#""aud":"dvarapala""#, r#""aud":["x","dvarapala"]"#);
        assert!(check(&cfg(), &aud_list, "n", 1000).is_ok());
        assert_eq!(reason("a.b".into(), 1000), "id_token is not a JWT");
        assert_eq!(
            reason("a.!!.c".into(), 1000),
            "id_token payload is not base64url"
        );
    }

    // RFC 0018 case 5
    #[test]
    #[ignore = "rfc 0018"]
    fn groups_rule() {
        let c = OidcConfig {
            allow_emails: vec![],
            allow_groups: vec!["sre".into()],
            groups_claim: "roles".into(),
            ..cfg()
        };
        let t = |roles: &str| {
            jwt(&format!(
                r#"{{"iss":"{ISS}","aud":"dvarapala","exp":2000,"nonce":"n","sub":"42"{roles}}}"#
            ))
        };
        assert_eq!(
            check(&c, &t(r#","roles":["sre"]"#), "n", 1),
            Ok("42".into())
        );
        assert_eq!(check(&c, &t(r#","roles":"sre""#), "n", 1), Ok("42".into()));
        let denied = Err(Denied::NotAllowed("42".into()));
        assert_eq!(check(&c, &t(r#","roles":["dev"]"#), "n", 1), denied);
        assert_eq!(check(&c, &t(""), "n", 1), denied);
    }

    // RFC 0018 case 6
    #[test]
    #[ignore = "rfc 0018"]
    fn state_is_single_use_and_expires() {
        let p = Provider {
            authorization_endpoint: format!("{ISS}/auth?x=1"),
            token_endpoint: format!("{ISS}/token"),
        };
        let logins = Logins::default();
        let now = Instant::now();
        let url = logins.begin(&cfg(), &p, now);
        assert!(url.starts_with("https://idp.example/auth?x=1&response_type=code"));
        let state = query(&url)["state"].clone();
        assert_eq!(logins.take("unknown", now), None);
        assert!(logins.take(&state, now).is_some());
        assert_eq!(logins.take(&state, now), None, "used twice");
        let old = query(&logins.begin(&cfg(), &p, now))["state"].clone();
        assert_eq!(logins.take(&old, now + PENDING_TTL), None, "too old");
        for _ in 0..MAX_PENDING + 5 {
            logins.begin(&cfg(), &p, now);
        }
        assert_eq!(logins.lock().len(), MAX_PENDING);
    }

    #[test]
    #[ignore = "rfc 0018"]
    fn callback_and_token_answer() {
        assert_eq!(
            callback(Some("code=a%2Fb&state=s")),
            Ok(("a/b".into(), "s".into()))
        );
        assert!(matches!(callback(Some("state=s")), Err(Denied::Invalid(_))));
        assert_eq!(
            callback(Some("error=access_denied&error_description=no%20way")),
            Err(Denied::Invalid("issuer: access_denied: no way".into()))
        );
        assert_eq!(id_token(br#"{"id_token":"x.y.z"}"#), Ok("x.y.z".into()));
        assert!(id_token(b"{}").is_err());
        let body = token_request(&cfg(), "c&d", "v");
        assert!(body.contains("code=c%26d&"));
        assert!(body.contains("client_secret=%3Csecret%3E"));
        assert!(body.ends_with("code_verifier=v"));
    }

    #[test]
    #[ignore = "rfc 0018"]
    fn discovery_and_urls() {
        let doc = br#"{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/a","token_endpoint":"https://idp.example/t"}"#;
        assert_eq!(
            provider(doc, ISS).unwrap().token_endpoint,
            "https://idp.example/t"
        );
        assert!(provider(doc, "https://other.example").is_err());
        let plain =
            String::from_utf8_lossy(doc).replace("https://idp.example/t", "http://idp.example/t");
        assert!(provider(plain.as_bytes(), ISS).is_err());
        assert_eq!(
            discovery_url("https://idp.example/"),
            "https://idp.example/.well-known/openid-configuration"
        );
        for ok in [
            "https://x",
            "http://localhost:8080/cb",
            "http://127.0.0.1",
            "http://[::1]:9/",
        ] {
            assert!(secure_url(ok), "{ok}");
        }
        for no in [
            "http://example.com",
            "http://127.0.0.1:1@evil.example/",
            "ftp://localhost",
            "http://localhost.evil",
        ] {
            assert!(!secure_url(no), "{no}");
        }
        for s in [&b""[..], b"f", b"fo", b"foo", b"foob", b"\xff\x00"] {
            assert_eq!(b64url_decode(&b64url(s)).unwrap(), s);
        }
        assert_eq!(b64url(b"\xfb\xff"), "-_8");
    }
}
