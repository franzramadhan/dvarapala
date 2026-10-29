//! The console (RFC 0018): its bundle, sessions, and the token and OIDC
//! logins that open them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dvarapala_l7::{
    Denied, LoginMethod, Logins, OidcConfig, Session, Sessions, authorized, check_id_token, cookie,
    csrf_ok, oidc_callback, percent_encode, unix_now,
};
use http::header::{AUTHORIZATION, HeaderValue, LOCATION, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;

use super::api::{error, json, string};
use super::oidc::Issuer;
use super::ui;
use crate::config::Admin as AdminConfig;

const COOKIE: &str = "dvarapala_session";
const CSRF: &str = "x-dvarapala-csrf";

pub struct Console {
    sessions: Sessions,
    ttl: Duration,
    /// `Secure` on the cookie: `public_url` is `https`.
    secure: bool,
    issuer: Option<Arc<Issuer>>,
    logins: Logins,
}

impl Console {
    /// The console for `[admin]`; starts OIDC discovery in the background.
    pub fn new(a: &AdminConfig) -> Result<Self, String> {
        let issuer = if a.oidc.issuer.is_empty() {
            None
        } else {
            let o = &a.oidc;
            let cfg = OidcConfig {
                issuer: o.issuer.clone(),
                client_id: o.client_id.clone(),
                client_secret: o.client_secret.clone(),
                redirect_uri: format!(
                    "{}/session/oidc/callback",
                    a.public_url.trim_end_matches('/')
                ),
                scopes: o.scopes.clone(),
                allow_emails: o.allow_emails.clone(),
                allow_groups: o.allow_groups.clone(),
                groups_claim: o.groups_claim.clone(),
                trust_email: !o.require_email_verified,
            };
            if cfg.trust_email {
                tracing::warn!(msg = "oidc email trusted without email_verified", issuer = %o.issuer);
            }
            let issuer = Arc::new(Issuer::new(cfg, o.label.clone())?);
            let i = issuer.clone();
            tokio::spawn(async move { i.provider().await });
            Some(issuer)
        };
        Ok(Self {
            sessions: Sessions::new(a.max_sessions, a.session_ttl),
            ttl: a.session_ttl,
            secure: a.public_url.starts_with("https://"),
            issuer,
            logins: Logins::default(),
        })
    }

    /// The console's own paths; `None` for the API.
    pub async fn answer(&self, token: &[u8], req: &Request<()>) -> Option<Response<Full<Bytes>>> {
        let path = req.uri().path();
        let get = req.method() == Method::GET || req.method() == Method::HEAD;
        Some(match (path, req.method()) {
            (p, _) if get && (p == "/ui" || p.starts_with("/ui/")) => ui::asset(p, req.headers()),
            ("/session/methods", &Method::GET) => json(StatusCode::OK, self.methods()),
            ("/session", &Method::POST) => self.token_login(token, req),
            ("/session", &Method::GET) => self.whoami(req),
            ("/session", &Method::DELETE) => self.logout(req),
            ("/session/oidc", &Method::GET) => self.oidc_start().await?,
            ("/session/oidc/callback", &Method::GET) => self.oidc_finish(req).await?,
            _ => return None,
        })
    }

    /// The subject of the request's session; a state changing call without
    /// the CSRF header is refused. `None` without a live session.
    pub fn actor(&self, req: &Request<()>) -> Option<Result<String, (StatusCode, &'static str)>> {
        let s = self.session(req)?;
        let safe = req.method() == Method::GET || req.method() == Method::HEAD;
        if !safe && !csrf_ok(req.headers().get(CSRF), &s.csrf) {
            return Some(Err((
                StatusCode::FORBIDDEN,
                "missing or wrong X-Dvarapala-Csrf",
            )));
        }
        Some(Ok(s.subject))
    }

    fn session(&self, req: &Request<()>) -> Option<Session> {
        let id = cookie(req.headers(), COOKIE)?;
        self.sessions.get(id, Instant::now())
    }

    fn methods(&self) -> String {
        let oidc = self.issuer.as_ref().map_or_else(
            || "null".into(),
            |i| format!("{{\"label\":{}}}", string(&i.label)),
        );
        format!("{{\"token\":true,\"oidc\":{oidc}}}")
    }

    fn token_login(&self, token: &[u8], req: &Request<()>) -> Response<Full<Bytes>> {
        if !authorized(req.headers().get(AUTHORIZATION), token) {
            logged("token", "", Err(Denied::Invalid("wrong token".into())));
            return json(StatusCode::UNAUTHORIZED, error("unauthorized"));
        }
        logged("token", "token", Ok(()));
        let mut r = status(StatusCode::NO_CONTENT);
        self.open(&mut r, "token".into(), LoginMethod::Token);
        r
    }

    fn whoami(&self, req: &Request<()>) -> Response<Full<Bytes>> {
        let Some(s) = self.session(req) else {
            return json(StatusCode::UNAUTHORIZED, error("unauthorized"));
        };
        let left = s
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs();
        json(
            StatusCode::OK,
            format!(
                "{{\"subject\":{},\"method\":\"{}\",\"expires_in\":{left},\"csrf\":\"{}\"}}",
                string(&s.subject),
                s.method.name(),
                s.csrf
            ),
        )
    }

    fn logout(&self, req: &Request<()>) -> Response<Full<Bytes>> {
        match self.actor(req) {
            None => return json(StatusCode::UNAUTHORIZED, error("unauthorized")),
            Some(Err((status, msg))) => return json(status, error(msg)),
            Some(Ok(_)) => {}
        }
        if let Some(id) = cookie(req.headers(), COOKIE) {
            self.sessions.remove(id);
        }
        self.gauge();
        let mut r = status(StatusCode::NO_CONTENT);
        r.headers_mut().insert(SET_COOKIE, self.cookie("", 0));
        r
    }

    async fn oidc_start(&self) -> Option<Response<Full<Bytes>>> {
        let issuer = self.issuer.as_ref()?;
        Some(match issuer.provider().await {
            Ok(p) => redirect(
                StatusCode::FOUND,
                &self.logins.begin(&issuer.cfg, &p, Instant::now()),
            ),
            Err(e) => {
                logged("oidc", "", Err(Denied::Invalid(e.clone())));
                to_login(&e)
            }
        })
    }

    async fn oidc_finish(&self, req: &Request<()>) -> Option<Response<Full<Bytes>>> {
        let issuer = self.issuer.as_ref()?;
        let done = async {
            let (code, state) = oidc_callback(req.uri().query())?;
            let pending = self
                .logins
                .take(&state, Instant::now())
                .ok_or_else(|| Denied::Invalid("unknown or expired login, sign in again".into()))?;
            let token = issuer.exchange(&code, &pending.verifier).await?;
            check_id_token(&issuer.cfg, &token, &pending.nonce, unix_now())
        };
        Some(match done.await {
            Ok(subject) => {
                logged("oidc", &subject, Ok(()));
                let mut r = redirect(StatusCode::FOUND, "/ui/");
                self.open(&mut r, subject, LoginMethod::Oidc);
                r
            }
            Err(d) => {
                let msg = match &d {
                    Denied::NotAllowed(s) => format!("{s} is not allowed in"),
                    Denied::Invalid(e) => format!("sign in failed: {e}"),
                };
                logged("oidc", "", Err(d));
                to_login(&msg)
            }
        })
    }

    /// Opens a session and sets its cookie on `r`.
    fn open(&self, r: &mut Response<Full<Bytes>>, subject: String, method: LoginMethod) {
        let (id, _) = self.sessions.create(subject, method, Instant::now());
        r.headers_mut()
            .insert(SET_COOKIE, self.cookie(&id, self.ttl.as_secs()));
        self.gauge();
    }

    fn cookie(&self, id: &str, max_age: u64) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{COOKIE}={id}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}{secure}"
        ))
        .expect("hex id")
    }

    fn gauge(&self) {
        ::metrics::gauge!("dvarapala_admin_sessions").set(self.sessions.len(Instant::now()) as f64);
    }
}

/// `msg="admin login"` and its counter.
fn logged(method: &'static str, subject: &str, result: Result<(), Denied>) {
    let result = match result {
        Ok(()) => {
            tracing::info!(msg = "admin login", method, subject = ?subject, result = "ok");
            "ok"
        }
        Err(Denied::NotAllowed(s)) => {
            tracing::warn!(msg = "admin login", method, subject = ?s, result = "denied");
            "denied"
        }
        Err(Denied::Invalid(e)) => {
            tracing::warn!(msg = "admin login", method, result = "failed", error = %e);
            "failed"
        }
    };
    ::metrics::counter!("dvarapala_admin_logins_total", "method" => method, "result" => result)
        .increment(1);
}

fn status(s: StatusCode) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::default());
    *r.status_mut() = s;
    r
}

fn redirect(s: StatusCode, to: &str) -> Response<Full<Bytes>> {
    let mut r = status(s);
    if let Ok(v) = HeaderValue::from_str(to) {
        r.headers_mut().insert(LOCATION, v);
    }
    r
}

/// Back to the login page, which shows `msg`.
fn to_login(msg: &str) -> Response<Full<Bytes>> {
    redirect(
        StatusCode::SEE_OTHER,
        &format!("/ui/login?error={}", percent_encode(msg)),
    )
}
