//! The calls: at most `concurrency` in flight, each bounded by `timeout`
//! and its answer by 64 KiB. No retry: the provider owns the budget.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dvarapala_l7::{MAX_REPLY, Protocol, Sample, parse_reply, request_body};
use dvarapala_proxy::UpstreamProtocol;
use dvarapala_proxy::tls::{Connector, UpstreamTls};
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderValue, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::{Semaphore, mpsc};

use super::Labels;
use crate::config;

struct Worker {
    client: Client<Connector, Full<Bytes>>,
    url: String,
    auth: Option<HeaderValue>,
    protocol: Protocol,
    model: String,
    labels: BTreeMap<String, String>,
    instructions: String,
    timeout: Duration,
    out: Arc<Labels>,
}

pub fn spawn(
    c: &config::Llm,
    mut rx: mpsc::Receiver<Sample>,
    out: Arc<Labels>,
) -> Result<(), String> {
    let endpoint = c.endpoint.clone().unwrap_or_default();
    let (protocol, url) = match c.protocol {
        config::Protocol::Systemone => (Protocol::SystemOne, endpoint),
        config::Protocol::Chat => (
            Protocol::Chat,
            format!("{}/chat/completions", endpoint.trim_end_matches('/')),
        ),
    };
    let connector =
        UpstreamTls::default().connector(url.starts_with("https://"), UpstreamProtocol::Http1)?;
    let auth = (!c.api_key.is_empty())
        .then(|| HeaderValue::try_from(format!("Bearer {}", c.api_key)))
        .transpose()
        .map_err(|_| "ml.llm.api_key is not a valid header value".to_owned())?
        .map(|mut v| {
            v.set_sensitive(true);
            v
        });
    let w = Arc::new(Worker {
        client: Client::builder(TokioExecutor::new()).build(connector),
        url,
        auth,
        protocol,
        model: c.model.clone(),
        labels: c.labels.clone(),
        instructions: c.instructions.clone(),
        timeout: c.timeout,
        out,
    });
    let slots = Arc::new(Semaphore::new(c.concurrency));
    tokio::spawn(async move {
        // a slot first, so the queue holds what waits and no more
        while let Ok(slot) = slots.clone().acquire_owned().await {
            let Some(s) = rx.recv().await else { break };
            let w = w.clone();
            tokio::spawn(async move {
                w.call(s).await;
                drop(slot);
            });
        }
    });
    Ok(())
}

impl Worker {
    async fn call(&self, s: Sample) {
        let body = request_body(
            self.protocol,
            &self.model,
            &self.labels,
            &self.instructions,
            &s,
        );
        let mut req = Request::post(&self.url)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)));
        if let (Ok(r), Some(a)) = (&mut req, &self.auth) {
            r.headers_mut().insert(AUTHORIZATION, a.clone());
        }
        let Ok(req) = req else {
            return count("error");
        };
        let start = Instant::now();
        let out = tokio::time::timeout(self.timeout, async {
            let res = self.client.request(req).await.map_err(|_| "error")?;
            match res.status() {
                StatusCode::TOO_MANY_REQUESTS => return Err("limited"),
                s if !s.is_success() => return Err("error"),
                _ => {}
            }
            Limited::new(res.into_body(), MAX_REPLY)
                .collect()
                .await
                .map(|b| b.to_bytes())
                .map_err(|_| "invalid")
        })
        .await;
        metrics::histogram!("dvarapala_llm_call_seconds").record(start.elapsed().as_secs_f64());
        let body = match out {
            Err(_) => return count("timeout"),
            Ok(Err(r)) => return count(r),
            Ok(Ok(b)) => b,
        };
        let Some(a) = parse_reply(self.protocol, &self.labels, &body) else {
            return count("invalid");
        };
        count("ok");
        let (prompt, completion) = a.tokens;
        metrics::counter!("dvarapala_llm_tokens_total", "kind" => "prompt").increment(prompt);
        metrics::counter!("dvarapala_llm_tokens_total", "kind" => "completion")
            .increment(completion);
        metrics::counter!(
            "dvarapala_llm_labels_total",
            "label" => a.label.clone(),
            "trigger" => s.trigger
        )
        .increment(1);
        tracing::info!(
            msg = "llm label",
            label = %a.label,
            confidence = a.confidence,
            pattern = ?a.pattern,
            trigger = s.trigger,
            route = %s.route,
            method = %s.method,
            path = ?s.path,
        );
        self.out.record(&s, &a);
    }
}

fn count(result: &'static str) {
    metrics::counter!("dvarapala_llm_calls_total", "result" => result).increment(1);
}
