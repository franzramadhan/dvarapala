//! RFC 0023: `GET /llm` and `POST /llm`; RFC 0024: `GET /llm/export`.

use dvarapala_l7::ExportQuery;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Response, StatusCode};

use super::Admin;
use super::api::{error, json};
use super::serve::{Body, whole};

impl Admin {
    /// `GET /llm`, from the store with `ml.llm.persist`.
    pub(super) async fn llm_get(&self) -> Response<Full<Bytes>> {
        match &self.llm {
            None => off(false),
            #[cfg(feature = "llm")]
            Some(l) => json(StatusCode::OK, l.answer().await),
            #[cfg(not(feature = "llm"))]
            Some(l) => match *l {},
        }
    }

    /// `POST /llm`: `on` for this long, `None` stops.
    pub(super) fn llm(&self, on: Option<String>, actor: &str) -> Response<Full<Bytes>> {
        let Some(l) = &self.llm else {
            return off(true);
        };
        #[cfg(not(feature = "llm"))]
        {
            let _ = (on, actor);
            match *l {}
        }
        #[cfg(feature = "llm")]
        match on {
            _ if !self.mode_switch => json(
                StatusCode::FORBIDDEN,
                error("switches are off: admin.mode_switch"),
            ),
            None => {
                l.off("console");
                json(StatusCode::OK, l.json().to_string())
            }
            Some(d) => match l.on(&d, actor) {
                Ok(_) => json(StatusCode::OK, l.json().to_string()),
                Err(e) => json(StatusCode::BAD_REQUEST, error(&e)),
            },
        }
    }

    /// `GET /llm/export`: JSON lines streamed a page at a time; `409`
    /// without `ml.llm.persist`.
    #[allow(unused_variables)]
    pub(super) fn llm_export(&self, q: ExportQuery) -> Response<Body> {
        #[cfg(feature = "llm")]
        if let Some(rx) = self.llm.as_ref().and_then(|l| l.export(q)) {
            use http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderValue};
            use http_body_util::BodyExt;
            let mut r = Response::new(Lines(rx).boxed());
            let h = r.headers_mut();
            h.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-ndjson"),
            );
            h.insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"llm-labels.jsonl\""),
            );
            return r;
        }
        whole(json(StatusCode::CONFLICT, error("ml.llm.persist is off")))
    }
}

/// The export's pages as a body; a store error aborts the connection, so a
/// cut export never looks complete.
#[cfg(feature = "llm")]
struct Lines(tokio::sync::mpsc::Receiver<Result<String, dvarapala_store::Error>>);

#[cfg(feature = "llm")]
impl hyper::body::Body for Lines {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        self.get_mut().0.poll_recv(cx).map(|o| {
            o.map(|r| {
                r.map(|s| hyper::body::Frame::data(Bytes::from(s)))
                    .map_err(|e| std::io::Error::other(e.0))
            })
        })
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
