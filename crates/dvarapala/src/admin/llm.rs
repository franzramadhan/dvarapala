//! RFC 0023: `GET /llm` and `POST /llm`.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use super::Admin;
use super::api::{error, json};

impl Admin {
    pub(super) fn llm(&self, on: Option<Option<String>>, actor: &str) -> Response<Full<Bytes>> {
        let Some(l) = &self.llm else {
            return off(on.is_some());
        };
        #[cfg(not(feature = "llm"))]
        {
            let _ = actor;
            match *l {}
        }
        #[cfg(feature = "llm")]
        match on {
            None => json(StatusCode::OK, l.json().to_string()),
            Some(_) if !self.mode_switch => json(
                StatusCode::FORBIDDEN,
                error("switches are off: admin.mode_switch"),
            ),
            Some(None) => {
                l.off("console");
                json(StatusCode::OK, l.json().to_string())
            }
            Some(Some(d)) => match l.on(&d, actor) {
                Ok(_) => json(StatusCode::OK, l.json().to_string()),
                Err(e) => json(StatusCode::BAD_REQUEST, error(&e)),
            },
        }
    }
}

impl Admin {
    /// `/status`'s `llm`: `null` when off, else whether it samples.
    pub(super) fn llm_status(&self) -> String {
        match &self.llm {
            None => "null".into(),
            #[cfg(feature = "llm")]
            Some(l) => format!("{{\"sampling\":{}}}", l.llm.sampling()),
            #[cfg(not(feature = "llm"))]
            Some(l) => match *l {},
        }
    }
}

/// Without `ml.llm.endpoint`.
fn off(switch: bool) -> Response<Full<Bytes>> {
    if switch {
        json(StatusCode::CONFLICT, error("ml.llm.endpoint is not set"))
    } else {
        json(
            StatusCode::OK,
            r#"{"configured":false,"sampling":false}"#.into(),
        )
    }
}
