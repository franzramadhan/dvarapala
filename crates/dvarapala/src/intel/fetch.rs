//! A `url` feed's refresh task: `https://` only, the body capped at
//! `intel.max_bytes`, 30 s per fetch, never on the request path.

use std::time::Duration;

use dvarapala_l7::FeedList;
use dvarapala_proxy::UpstreamProtocol;
use dvarapala_proxy::tls::{Connector, UpstreamTls};
use http::Request;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::task::AbortHandle;
use tokio::time::MissedTickBehavior;

use super::feeds::{Failed, apply};
use crate::config;

const TIMEOUT: Duration = Duration::from_secs(30);

/// Fetches the feed now, then every `refresh`. A failure keeps the list
/// in force: empty until the first good fetch.
pub fn spawn(f: &config::Feed, url: &str, max_bytes: usize, list: FeedList) -> Option<AbortHandle> {
    let connector = match UpstreamTls::default().connector(true, UpstreamProtocol::Http1) {
        Ok(c) => c,
        Err(e) => {
            let _ = apply(&f.name, &list, Err(Failed::Fetch(e)), f.max_entries);
            return None;
        }
    };
    let client = Client::builder(TokioExecutor::new()).build(connector);
    let (name, url, every, max) = (f.name.clone(), url.to_owned(), f.refresh, f.max_entries);
    let task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let body = fetch(&client, &url, max_bytes).await;
            let _ = apply(&name, &list, body, max);
        }
    });
    Some(task.abort_handle())
}

async fn fetch(
    client: &Client<Connector, Full<Bytes>>,
    url: &str,
    max: usize,
) -> Result<Vec<u8>, Failed> {
    let call = async {
        let req = Request::get(url)
            .body(Full::default())
            .map_err(|e| Failed::Fetch(e.to_string()))?;
        let res = client
            .request(req)
            .await
            .map_err(|e| Failed::Fetch(e.to_string()))?;
        if !res.status().is_success() {
            return Err(Failed::Fetch(format!("answered {}", res.status())));
        }
        Limited::new(res.into_body(), max)
            .collect()
            .await
            .map(|b| b.to_bytes().to_vec())
            .map_err(|e| match e.downcast_ref::<LengthLimitError>() {
                Some(_) => Failed::TooLarge,
                None => Failed::Fetch(e.to_string()),
            })
    };
    tokio::time::timeout(TIMEOUT, call)
        .await
        .unwrap_or_else(|_| Err(Failed::Fetch("timed out after 30s".into())))
}
