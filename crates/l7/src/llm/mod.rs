//! RFC 0023: LLM labels for sampled traffic.

mod sample;
#[cfg(feature = "llm")]
mod wire;

pub(crate) use sample::Seen;
pub use sample::{Llm, LlmConfig, MAX_PATH, On, Probe, Sample, Sink, Trigger, cut, redact};
#[cfg(feature = "llm")]
pub use wire::{
    Answer, MAX_REPLY, Protocol, features, fuzz_llm_reply, parse_reply, request_body, sample_json,
};
