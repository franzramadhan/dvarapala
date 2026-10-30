//! RFC 0023: the LLM labels worker. Samples come from the rate limiter
//! through a bounded queue; calls run off the request path, and their
//! answers go to logs, metrics, `GET /llm` and the export file.

mod call;
mod labels;

use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

use dvarapala_l7::{Llm, RateLimitLayer, Sink};
use tokio::sync::mpsc;

pub use labels::Labels;

use crate::config::Config;

/// Starts the worker and hooks the sampler into `layer`; `None` when
/// `[ml.llm]` is off or does not apply.
pub fn start(
    cfg: &Config,
    layer: Option<&RateLimitLayer>,
) -> Result<Option<Arc<Labels>>, Box<dyn Error>> {
    let c = &cfg.ml.llm;
    let (Some(sampler), Some(layer)) = (c.sampler(cfg)?, layer) else {
        return Ok(None);
    };
    let (tx, rx) = mpsc::channel(c.queue);
    let sink: Sink = Box::new(move |s| tx.try_send(s).is_ok());
    let llm = Arc::new(Llm::new(sampler, sink, Instant::now));
    let labels = Labels::new(llm.clone(), c)?;
    llm.set(c.enabled);
    layer.set_llm(llm);
    call::spawn(c, rx, labels.clone())?;
    tracing::info!(
        msg = "llm labels ready",
        protocol = ?c.protocol,
        model = %c.model,
        triggers = c.triggers.len(),
        sampling = c.enabled,
    );
    Ok(Some(labels))
}
