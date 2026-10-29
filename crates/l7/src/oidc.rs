//! OIDC login for the admin console (RFC 0018): the authorization code
//! flow with PKCE, the callback and the ID token's claims. No I/O: the
//! binary fetches discovery and exchanges the code.

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
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// The provider from a discovery document, which must name `issuer`.
pub fn provider(doc: &[u8], issuer: &str) -> Result<Provider, String> {
    let v: Value = serde_json::from_slice(doc).map_err(|e| format!("discovery: {e}"))?;
    if v["issuer"].as_str() != Some(issuer) {
        return Err(format!("discovery: issuer is not {issuer:?}"));
    }
    let endpoint = |k: &str| match v[k].as_str() {
        Some(u) if secure_url(u) => Ok(u.to_owned()),
        Some(u) => Err(format!("discovery: {k} {u:?} is not https")),
        None => Err(format!("discovery: no {k}")),
    };
    Ok(Provider {
        authorization_endpoint: endpoint("authorization_endpoint")?,
        token_endpoint: endpoint("token_endpoint")?,
    })
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
        let (state, nonce, verifier) = (token(), token(), token());
        let challenge = b64url(digest(&SHA256, verifier.as_bytes()).as_ref());
        let url = format!(
            "{}{}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={nonce}&code_challenge={challenge}&code_challenge_method=S256",
            p.authorization_endpoint,
            if p.authorization_endpoint.contains('?') {
                '&'
            } else {
                '?'
            },
            enc(&cfg.client_id),
            enc(&cfg.redirect_uri),
            enc(&cfg.scopes.join(" ")),
        );
        let mut map = self.lock();
        map.retain(|_, l| now.saturating_duration_since(l.started) < PENDING_TTL);
        if map.len() >= MAX_PENDING
            && let Some(k) = map
                .iter()
                .min_by_key(|(_, l)| l.started)
                .map(|(k, _)| k.clone())
        {
            map.remove(&k);
        }
        let started = now;
        map.insert(
            state,
            Pending {
                verifier,
                nonce,
                started,
            },
        );
        url
    }

    /// The login behind `state`, removed: a second callback finds nothing.
    pub fn take(&self, state: &str, now: Instant) -> Option<Pending> {
        let l = self.lock().remove(state)?;
        (now.saturating_duration_since(l.started) < PENDING_TTL).then_some(l)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// `code` and `state` from the redirect, or the issuer's `error`.
pub fn callback(query: Option<&str>) -> Result<(String, String), Denied> {
    let q = query.unwrap_or("");
    let get = |k| param(q, k).map_err(|(_, m)| Denied::Invalid(m));
    if let Some(e) = get("error")? {
        let detail = get("error_description")?
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        return Err(Denied::Invalid(format!("issuer: {e}{detail}")));
    }
    match (get("code")?, get("state")?) {
        (Some(c), Some(s)) if !c.is_empty() && !s.is_empty() => Ok((c, s)),
        _ => Err(Denied::Invalid("code and state are required".into())),
    }
}

/// The token request body (`client_secret_post`).
pub fn token_request(cfg: &OidcConfig, code: &str, verifier: &str) -> String {
    format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={verifier}",
        enc(code),
        enc(&cfg.redirect_uri),
        enc(&cfg.client_id),
        enc(&cfg.client_secret),
    )
}

/// `id_token` from the token endpoint's answer.
pub fn id_token(body: &[u8]) -> Result<String, Denied> {
    let v: Value =
        serde_json::from_slice(body).map_err(|e| Denied::Invalid(format!("token answer: {e}")))?;
    v["id_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Denied::Invalid("token answer without id_token".into()))
}

/// Checks the ID token's claims and the allow lists; the subject on
/// success. The signature is not checked: the token came straight from the
/// token endpoint over verified TLS (OIDC Core 3.1.3.7).
pub fn check(cfg: &OidcConfig, id_token: &str, nonce: &str, now: u64) -> Result<String, Denied> {
    let bad = |m: &str| Denied::Invalid(m.to_owned());
    let mut parts = id_token.split('.');
    let payload = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(p), Some(_), None) => p,
        _ => return Err(bad("id_token is not a JWT")),
    };
    let json = b64url_decode(payload).ok_or_else(|| bad("id_token payload is not base64url"))?;
    let c: Value =
        serde_json::from_slice(&json).map_err(|_| bad("id_token payload is not JSON"))?;
    if c["iss"].as_str() != Some(cfg.issuer.as_str()) {
        return Err(bad("iss mismatch"));
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => *a == cfg.client_id,
        Value::Array(a) => a.iter().any(|x| x.as_str() == Some(cfg.client_id.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(bad("aud mismatch"));
    }
    if !c["exp"].as_u64().is_some_and(|exp| exp > now) {
        return Err(bad("expired"));
    }
    if c["nonce"].as_str() != Some(nonce) {
        return Err(bad("nonce mismatch"));
    }
    let verified = matches!(&c["email_verified"], Value::Bool(true))
        || c["email_verified"].as_str() == Some("true");
    let email = c["email"].as_str().filter(|_| verified);
    let sub = c["sub"].as_str().unwrap_or("");
    let subject = email.unwrap_or(sub).to_owned();
    if let Some(e) = email
        && cfg.allow_emails.iter().any(|a| a.eq_ignore_ascii_case(e))
    {
        return Ok(subject);
    }
    let in_group = |g: &Value| {
        g.as_str()
            .is_some_and(|g| cfg.allow_groups.iter().any(|a| a == g))
    };
    let grouped = match &c[cfg.groups_claim.as_str()] {
        Value::Array(gs) => gs.iter().any(in_group),
        g => in_group(g),
    };
    if grouped && !subject.is_empty() {
        return Ok(subject);
    }
    let shown = c["email"].as_str().unwrap_or(sub);
    Err(Denied::NotAllowed(shown.to_owned()))
}

/// 256 random bits, base64url: `state`, `nonce` and the PKCE verifier.
fn token() -> String {
    b64url(&random::<32>())
}

/// Percent-encodes everything but the unreserved characters.
pub fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(B64[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes() {
        let v = B64.iter().position(|&x| x == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// RFC 0018 case 7: a callback query on the first line, an ID token
/// payload (before base64url) after it. Never panics.
pub fn fuzz_oidc_callback(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let (q, payload) = s.split_once('\n').unwrap_or((&s, ""));
    let _ = callback(Some(q));
    let _ = id_token(payload.as_bytes());
    let _ = provider(payload.as_bytes(), "https://idp.example");
    let _ = b64url_decode(q);
    let cfg = OidcConfig {
        issuer: "https://idp.example".into(),
        client_id: "c".into(),
        allow_groups: vec!["g".into()],
        groups_claim: "groups".into(),
        ..OidcConfig::default()
    };
    let jwt = format!("e30.{}.sig", b64url(payload.as_bytes()));
    let _ = check(&cfg, &jwt, "n", 0);
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
