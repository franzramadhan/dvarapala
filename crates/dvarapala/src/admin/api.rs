//! The RFC 0014 calls and their JSON, written by hand (no new dependency).

use std::fmt::Write;

use dvarapala_l7::{Call, ModeLayer, RateLimitLayer, request_totals};
use http::header::{CONTENT_TYPE, HeaderValue};
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use super::Admin;
use super::switch::{self, Switch};
use crate::config::{self, parse_duration};
use crate::reload::Outcome;

impl Admin {
    pub(super) fn call(&self, call: Call, actor: &str) -> Response<Full<Bytes>> {
        match call {
            Call::Config => {
                let (start, cur) = self.reloader.configs();
                return json(StatusCode::OK, config::view::view(&start, &cur).to_string());
            }
            Call::Waf => return json(StatusCode::OK, self.waf().to_string()),
            Call::Metrics => {
                let mut r = Response::new(Full::new(Bytes::from(self.metrics.render())));
                r.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; version=0.0.4"),
                );
                return r;
            }
            Call::Mode { layer, enforce } => return self.switch(layer, enforce, actor),
            Call::Llm => return self.llm(None, actor),
            Call::LlmSwitch { on } => return self.llm(Some(on), actor),
            // RFC 0024: no store yet
            Call::LlmExport(_) => {
                return json(StatusCode::CONFLICT, error("ml.llm.persist is off"));
            }
            _ => {}
        }
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
            Call::Reload
            | Call::Config
            | Call::Waf
            | Call::Metrics
            | Call::Mode { .. }
            | Call::Llm
            | Call::LlmSwitch { .. }
            | Call::LlmExport(_) => {
                unreachable!("answered above")
            }
            Call::History { .. } => unreachable!("answered by the admin router"),
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
        let mut requests = String::new();
        for (i, (verdict, n)) in request_totals().iter().enumerate() {
            let sep = if i == 0 { "" } else { "," };
            let _ = write!(requests, "{sep}\"{verdict}\":{n}");
        }
        let (_, cur) = self.reloader.configs();
        let waf = if cur.waf.enabled {
            format!(
                "\"{}\"",
                switch::mode(self.reloader.enforce(ModeLayer::Waf))
            )
        } else {
            "null".into()
        };
        let switches: Vec<_> = self
            .reloader
            .switches
            .all()
            .iter()
            .map(Switch::json)
            .collect();
        format!(
            "{{\"version\":\"{}\",\"mode\":\"{}\",\"detection\":{detection},\"clients\":{},\"blocks\":{},\"last_reload\":{reload},\"requests\":{{{requests}}},\"waf\":{waf},\"switches\":{},\"llm\":{}}}",
            env!("CARGO_PKG_VERSION"),
            self.mode,
            s.as_ref().map_or(0, |s| s.clients),
            s.as_ref().map_or(0, |s| s.blocks),
            serde_json::Value::Array(switches),
            self.llm_status(),
        )
    }
}

impl Admin {
    /// `POST /mode` (RFC 0021).
    fn switch(&self, layer: ModeLayer, enforce: bool, actor: &str) -> Response<Full<Bytes>> {
        if !self.mode_switch {
            return json(
                StatusCode::FORBIDDEN,
                error("mode switches are off: admin.mode_switch"),
            );
        }
        match self.reloader.switch(layer, enforce, actor) {
            Ok(previous) => {
                tracing::info!(
                    msg = "mode switched",
                    layer = layer.name(),
                    mode = switch::mode(enforce),
                    previous = switch::mode(previous),
                    actor,
                );
                let body = serde_json::json!({
                    "layer": layer.name(),
                    "mode": switch::mode(enforce),
                    "previous": switch::mode(previous),
                    "switch": self.reloader.switches.get(layer).as_ref().map(Switch::json),
                });
                json(StatusCode::OK, body.to_string())
            }
            Err((status, e)) => json(status, error(&e)),
        }
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

pub(super) fn error(msg: &str) -> String {
    format!("{{\"error\":{}}}", string(msg))
}

/// `s` as a JSON string.
pub(super) fn string(s: &str) -> String {
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

pub(super) fn json(status: StatusCode, body: String) -> Response<Full<Bytes>> {
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
