//! Discovery and the code exchange with the issuer (RFC 0018): `https`
//! with certificate checks, bounded in time and size.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use dvarapala_l7::{
    Denied, OidcConfig, Provider, discovery_url, id_token, provider, token_request,
};
use dvarapala_proxy::UpstreamProtocol;
use dvarapala_proxy::tls::{Connector, UpstreamTls};
use http::header::{ACCEPT, CONTENT_TYPE};
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

const TIMEOUT: Duration = Duration::from_secs(5);
/// Largest discovery document or token answer read.
const MAX_ANSWER: usize = 64 * 1024;
/// A failed discovery is tried again at a login, at most this often.
const RETRY: Duration = Duration::from_secs(10);

pub struct Issuer {
    pub cfg: OidcConfig,
    pub label: String,
    client: Client<Connector, Full<Bytes>>,
    /// The provider once discovered, and the last failed try.
    found: Mutex<(Option<Provider>, Option<Instant>)>,
}

impl Issuer {
    pub fn new(cfg: OidcConfig, label: String) -> Result<Self, String> {
        let connector = UpstreamTls::default().connector(true, UpstreamProtocol::Http1)?;
        Ok(Self {
            cfg,
            label,
            client: Client::builder(TokioExecutor::new()).build(connector),
            found: Mutex::new((None, None)),
        })
    }

    /// The provider, discovered once; a failure is retried at most every
    /// 10 s so logins cannot drive requests to the issuer.
    pub async fn provider(&self) -> Result<Provider, String> {
        {
            let mut f = self.lock();
            if let Some(p) = &f.0 {
                return Ok(p.clone());
            }
            if f.1.is_some_and(|t| t.elapsed() < RETRY) {
                return Err("issuer discovery failed, retry in a few seconds".into());
            }
            f.1 = Some(Instant::now());
        }
        let req = Request::get(discovery_url(&self.cfg.issuer))
            .header(ACCEPT, "application/json")
            .body(Full::default())
            .map_err(|e| e.to_string())?;
        let found = self
            .fetch(req)
            .await
            .and_then(|b| provider(&b, &self.cfg.issuer));
        match &found {
            Ok(p) => {
                tracing::info!(msg = "oidc discovered", issuer = %self.cfg.issuer);
                self.lock().0 = Some(p.clone());
            }
            Err(e) => {
                tracing::warn!(msg = "oidc discovery failed", issuer = %self.cfg.issuer, error = %e)
            }
        }
        found
    }

    /// The ID token for `code`.
    pub async fn exchange(&self, code: &str, verifier: &str) -> Result<String, Denied> {
        let p = self.provider().await.map_err(Denied::Invalid)?;
        let req = Request::post(p.token_endpoint)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(ACCEPT, "application/json")
            .body(Full::new(Bytes::from(token_request(
                &self.cfg, code, verifier,
            ))))
            .map_err(|e| Denied::Invalid(e.to_string()))?;
        let body = self.fetch(req).await.map_err(Denied::Invalid)?;
        id_token(&body)
    }

    async fn fetch(&self, req: Request<Full<Bytes>>) -> Result<Bytes, String> {
        let uri = req.uri().clone();
        let call = async {
            let res = self
                .client
                .request(req)
                .await
                .map_err(|e| format!("{uri}: {e}"))?;
            let status = res.status();
            if !status.is_success() {
                return Err(format!("{uri} answered {status}"));
            }
            Limited::new(res.into_body(), MAX_ANSWER)
                .collect()
                .await
                .map(|b| b.to_bytes())
                .map_err(|e| format!("{uri}: {e}"))
        };
        tokio::time::timeout(TIMEOUT, call)
            .await
            .map_err(|_| format!("{uri}: timed out"))?
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (Option<Provider>, Option<Instant>)> {
        self.found
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
