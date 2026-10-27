//! Optional scoring: per-client online features and a model that turns
//! them into a score.

mod features;
#[cfg(feature = "ml")]
mod tree;

pub use features::{ClientStats, FEATURE_NAMES, FEATURES, Features};
#[cfg(feature = "ml")]
pub use tree::{ModelError, TreeEnsemble};

/// Turns a feature vector into a score in `[0, 1]`; higher is more likely
/// an attack.
pub trait Scorer: Send + Sync {
    fn score(&self, features: &Features) -> f64;
}
