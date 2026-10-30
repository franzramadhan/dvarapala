//! The admin listener: connections, who is calling, the audit log and the
//! headers every answer carries.

use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dvarapala_l7::{Call, RateLimitLayer, authorized, parse_admin};
use http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderValue, REFERRER_POLICY,
    WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use super::api::{error, json};
use crate::reload::Reloader;

/// Open admin connections at most; one request each.
const MAX_CONNS: usize = 16;

/// The console's policy, on every admin answer (RFC 0018).
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub struct Admin {
    pub token: String,
    pub max_block_ttl: Duration,
    /// `None` when the reverse proxy's rate limiter is off.
    pub layer: Option<RateLimitLayer>,
    pub reloader: Arc<Reloader>,
    /// `reverse` or `forward`
    pub mode: &'static str,
    /// RFC 0021: `GET /metrics` renders it.
    pub metrics: metrics_exporter_prometheus::PrometheusHandle,
    /// RFC 0021: allows `POST /mode`.
    pub mode_switch: bool,
    /// The console, with `ui_enabled`.
    #[cfg(feature = "ui")]
    pub console: Option<super::Console>,
}

/// Binds `addr` and serves the admin API until the process exits.
pub async fn serve(addr: SocketAddr, admin: Admin) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "admin listening");
    let admin = Arc::new(admin);
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            // over the bound: close it instead of queueing
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let admin = admin.clone();
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let admin = admin.clone();
                // no admin call reads a body
                let req = Request::from_parts(req.into_parts().0, ());
                async move { Ok::<_, Infallible>(admin.answer(&req).await) }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(Duration::from_secs(5))
                    .keep_alive(false)
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
                drop(slot);
            });
        }
    });
    Ok(())
}

impl Admin {
    async fn answer(&self, req: &Request<()>) -> Response<Full<Bytes>> {
        let mut res = self.route(req).await;
        let h = res.headers_mut();
        h.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
        h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        h.entry(CACHE_CONTROL)
            .or_insert(HeaderValue::from_static("no-store"));
        ::metrics::counter!(
            "dvarapala_admin_requests_total",
            "endpoint" => endpoint(req.uri().path()),
            "status" => res.status().as_str().to_owned()
        )
        .increment(1);
        res
    }

    async fn route(&self, req: &Request<()>) -> Response<Full<Bytes>> {
        #[cfg(feature = "ui")]
        if let Some(c) = &self.console
            && let Some(res) = c.answer(self.token.as_bytes(), req).await
        {
            return res;
        }
        let actor = match self.actor(req) {
            Ok(a) => a,
            Err((status, msg)) => {
                let mut r = json(status, error(msg));
                if status == StatusCode::UNAUTHORIZED {
                    r.headers_mut()
                        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                }
                return r;
            }
        };
        let call = match parse_admin(req.method().as_str(), req.uri().path(), req.uri().query()) {
            Ok(call) => call,
            Err((status, msg)) => return json(status, error(&msg)),
        };
        let audit = matches!(
            call,
            Call::Reload | Call::Block { .. } | Call::Unblock { .. } | Call::Mode { .. }
        );
        let res = self.call(call, &actor);
        if audit {
            tracing::info!(
                msg = "admin action",
                actor = ?actor,
                call = %format_args!("{} {}", req.method(), req.uri().path()),
                query = req.uri().query().unwrap_or(""),
                status = res.status().as_u16(),
            );
        }
        res
    }

    /// Who is calling: `token` for the bearer header, or the subject of a
    /// console session.
    fn actor(&self, req: &Request<()>) -> Result<String, (StatusCode, &'static str)> {
        if authorized(req.headers().get(AUTHORIZATION), self.token.as_bytes()) {
            return Ok("token".into());
        }
        #[cfg(feature = "ui")]
        if let Some(c) = &self.console
            && let Some(actor) = c.actor(req)
        {
            return actor;
        }
        Err((StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

/// The `endpoint` label: the API paths, the console's groups, `other`.
fn endpoint(path: &str) -> String {
    match path {
        "/status" | "/top" | "/reload" | "/blocks" | "/config" | "/waf" | "/mode" | "/metrics" => {
            path.to_owned()
        }
        p if p == "/ui" || p.starts_with("/ui/") => "ui".into(),
        p if p.starts_with("/session/oidc") => "oidc".into(),
        p if p == "/session" || p.starts_with("/session/") => "session".into(),
        _ => "other".into(),
    }
}
