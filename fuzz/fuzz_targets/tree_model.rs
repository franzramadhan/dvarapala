//! Operator-supplied model files: parsing never panics, and an accepted
//! model scores any feature vector to a probability.
#![no_main]

use dvarapala_engine::{FEATURES, Scorer, TreeEnsemble};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(model) = TreeEnsemble::from_json(data) {
        for f in [[0.0; FEATURES], [f64::NAN; FEATURES], [1e9; FEATURES]] {
            let s = model.score(&f);
            assert!((0.0..=1.0).contains(&s) || s.is_nan());
        }
    }
});
