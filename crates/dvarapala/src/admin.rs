//! The RFC 0014 admin API on its own listener: JSON over HTTP/1.1, every
//! call behind the bearer token.

use std::convert::Infallible;
use std::fmt::Write;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dvarapala_l7::{Call, RateLimitLayer, authorized, parse_admin};
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, WWW_AUTHENTICATE};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::config::parse_duration;
use crate::reload::{Outcome, Reloader};

/// Open admin connections at most; one request each.
const MAX_CONNS: usize = 16;

pub struct Admin {
    pub token: String,
    pub max_block_ttl: Duration,
    /// `None` when the reverse proxy's rate limiter is off.
    pub layer: Option<RateLimitLayer>,
    pub reloader: Arc<Reloader>,
    /// `reverse` or `forward`
    pub mode: &'static str,
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
                let res = admin.answer(&req);
                async move { Ok::<_, Infallible>(res) }
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
    fn answer<B>(&self, req: &Request<B>) -> Response<Full<Bytes>> {
        let path = req.uri().path();
        let endpoint = match path {
            "/status" | "/top" | "/reload" | "/blocks" => path.to_owned(),
            _ => "other".to_owned(),
        };
        let res = if !authorized(req.headers().get(AUTHORIZATION), self.token.as_bytes()) {
            let mut r = json(StatusCode::UNAUTHORIZED, error("unauthorized"));
            r.headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            r
        } else {
            match parse_admin(req.method().as_str(), path, req.uri().query()) {
                Ok(call) => self.call(call),
                Err((status, msg)) => json(status, error(&msg)),
            }
        };
        ::metrics::counter!(
            "dvarapala_admin_requests_total",
            "endpoint" => endpoint,
            "status" => res.status().as_str().to_owned()
        )
        .increment(1);
        res
    }

    fn call(&self, call: Call) -> Response<Full<Bytes>> {
        if call == Call::Reload {
            let out = self.reloader.reload();
            let status = match out.result {
                Ok(_) => StatusCode::OK,
                Err(_) => StatusCode::UNPROCESSABLE_ENTITY,
            };
            return json(status, outcome(&out));
        }
        let Some(l) = &self.layer else {
            if call == Call::Status {
                return json(StatusCode::OK, self.status(None));
            }
            return json(
                StatusCode::SERVICE_UNAVAILABLE,
                error("the reverse proxy's rate limiter is off"),
            );
        };
        match call {
            Call::Status => json(StatusCode::OK, self.status(Some(l))),
            Call::Top => {
                let mut s = String::from("{\"top\":[");
                for (i, (net, n)) in l.top().iter().enumerate() {
                    let sep = if i == 0 { "" } else { "," };
                    let _ = write!(s, "{sep}{{\"cidr\":\"{net}\",\"count\":{n}}}");
                }
                json(StatusCode::OK, s + "]}")
            }
            Call::Blocks => {
                let mut s = String::from("{\"blocks\":[");
                for (i, b) in l.blocks().iter().enumerate() {
                    let sep = if i == 0 { "" } else { "," };
                    let secs = b.remaining.as_secs();
                    let _ = write!(s, "{sep}{{\"cidr\":\"{}\",\"ttl_secs\":{secs}}}", b.net);
                }
                json(StatusCode::OK, s + "]}")
            }
            Call::Block { net, ttl } => {
                let ttl = match ttl.as_deref().map(parse_duration).transpose() {
                    Ok(t) => t.unwrap_or(self.max_block_ttl),
                    Err(e) => return json(StatusCode::BAD_REQUEST, error(&e)),
                };
                if ttl.is_zero() || ttl > self.max_block_ttl {
                    return json(
                        StatusCode::BAD_REQUEST,
                        error("ttl must be above 0 and at most admin.max_block_ttl"),
                    );
                }
                match l.block(net, ttl) {
                    Ok(()) => {
                        tracing::info!(msg = "blocked", cidr = %net, ttl = ?ttl);
                        let body = format!("{{\"cidr\":\"{net}\",\"ttl_secs\":{}}}", ttl.as_secs());
                        json(StatusCode::OK, body)
                    }
                    Err(e) => json(StatusCode::INSUFFICIENT_STORAGE, error(&e.to_string())),
                }
            }
            Call::Unblock { net } => {
                if l.unblock(net) {
                    tracing::info!(msg = "unblocked", cidr = %net);
                    json(StatusCode::OK, format!("{{\"cidr\":\"{net}\"}}"))
                } else {
                    json(StatusCode::NOT_FOUND, error("not blocked"))
                }
            }
            Call::Reload => unreachable!("answered above"),
        }
    }

    fn status(&self, l: Option<&RateLimitLayer>) -> String {
        let s = l.map(RateLimitLayer::status);
        let detection = match s.as_ref().and_then(|s| s.detection) {
            Some(d) => format!("\"{d}\""),
            None => "null".into(),
        };
        let reload = self
            .reloader
            .last()
            .map_or_else(|| "null".into(), |o| outcome(&o));
        format!(
            "{{\"version\":\"{}\",\"mode\":\"{}\",\"detection\":{detection},\"clients\":{},\"blocks\":{},\"last_reload\":{reload}}}",
            env!("CARGO_PKG_VERSION"),
            self.mode,
            s.as_ref().map_or(0, |s| s.clients),
            s.as_ref().map_or(0, |s| s.blocks),
        )
    }
}

fn outcome(o: &Outcome) -> String {
    match &o.result {
        Ok(restart) => {
            let keys: Vec<String> = restart.iter().map(|k| string(k)).collect();
            format!(
                "{{\"at\":{},\"result\":\"ok\",\"restart\":[{}]}}",
                o.at,
                keys.join(",")
            )
        }
        Err(e) => format!(
            "{{\"at\":{},\"result\":\"failed\",\"error\":{}}}",
            o.at,
            string(e)
        ),
    }
}

fn error(msg: &str) -> String {
    format!("{{\"error\":{}}}", string(msg))
}

/// `s` as a JSON string.
fn string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(body)));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_strings() {
        assert_eq!(string("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }
}
