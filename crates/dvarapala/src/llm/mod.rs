//! RFC 0023: the LLM labels worker. Samples come from the rate limiter
//! through a bounded queue; calls run off the request path, and their
//! answers go to logs, metrics, `GET /llm`, the export file and the
//! store (RFC 0024).

mod call;
mod labels;
#[cfg(feature = "postgres")]
mod persist;

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
    #[cfg(feature = "postgres")]
    if c.persist {
        let _ = labels.persist.set(persist::Persist::start(cfg)?);
    }
    #[cfg(not(feature = "postgres"))]
    if c.persist {
        return Err("ml.llm.persist needs a binary built with the postgres feature".into());
    }
    llm.set(c.enabled);
    layer.set_llm(llm);
    call::spawn(c, rx, labels.clone())?;
    tracing::info!(
        msg = "llm labels ready",
        protocol = ?c.protocol,
        model = %c.model,
        triggers = c.triggers.len(),
        sampling = c.enabled,
        persist = c.persist,
    );
    Ok(Some(labels))
}
