use std::fmt;

use serde::Deserialize;

use crate::score::{FEATURE_NAMES, Features, Scorer};

/// Model limits: the file is input, parsed once at start.
pub const MAX_BYTES: usize = 16 << 20;
pub const MAX_TREES: usize = 1024;
pub const MAX_DEPTH: usize = 16;
pub const MAX_NODES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelError(pub String);

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "model: {}", self.0)
    }
}

impl std::error::Error for ModelError {}

/// Gradient-boosted trees from an XGBoost JSON model
/// (`Booster.save_model("m.json")`), objective `binary:logistic`.
#[derive(Debug, Clone)]
pub struct TreeEnsemble {
    base_margin: f64,
    trees: Vec<Tree>,
}

#[derive(Debug, Clone)]
struct Tree {
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, Copy)]
enum Node {
    Split {
        /// index into [`Features`]
        feature: usize,
        threshold: f32,
        left: u32,
        right: u32,
        default_left: bool,
    },
    Leaf(f32),
}

#[derive(Deserialize)]
struct Json {
    learner: Learner,
}

#[derive(Deserialize)]
struct Learner {}

impl TreeEnsemble {
    pub fn from_json(_bytes: &[u8]) -> Result<Self, ModelError> {
        let _ = (FEATURE_NAMES, MAX_TREES, MAX_DEPTH, MAX_NODES, MAX_BYTES);
        todo!("rfc 0002")
    }
}

impl Scorer for TreeEnsemble {
    fn score(&self, _features: &Features) -> f64 {
        todo!("rfc 0002")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL: &str = include_str!("../../tests/fixtures/xgb_stumps.json");
    const EXPECTED: &str = include_str!("../../tests/fixtures/xgb_stumps_expected.json");

    fn model_json() -> serde_json::Value {
        serde_json::from_str(MODEL).unwrap()
    }

    fn load(v: &serde_json::Value) -> Result<TreeEnsemble, ModelError> {
        TreeEnsemble::from_json(v.to_string().as_bytes())
    }

    fn tree0(v: &mut serde_json::Value) -> &mut serde_json::Value {
        &mut v["learner"]["gradient_booster"]["model"]["trees"][0]
    }

    #[test]
    #[ignore = "rfc 0002 case 22"]
    fn matches_xgboost_predict() {
        let m = TreeEnsemble::from_json(MODEL.as_bytes()).unwrap();
        let exp: serde_json::Value = serde_json::from_str(EXPECTED).unwrap();
        let rows = exp["rows"].as_array().unwrap();
        let want = exp["predict"].as_array().unwrap();
        for (row, want) in rows.iter().zip(want) {
            let mut f = [0.0; 10];
            for (i, v) in row.as_array().unwrap().iter().enumerate() {
                f[i] = v.as_f64().unwrap_or(f64::NAN);
            }
            let got = m.score(&f);
            let want = want.as_f64().unwrap();
            assert!((got - want).abs() < 1e-6, "{row}: {got} vs {want}");
        }
    }

    #[test]
    #[ignore = "rfc 0002 case 23"]
    fn unknown_feature_is_named() {
        let mut v = model_json();
        v["learner"]["feature_names"][9] = "dst_port".into();
        let e = load(&v).unwrap_err().to_string();
        assert!(e.contains("dst_port"), "{e}");
    }

    #[test]
    #[ignore = "rfc 0002 case 24"]
    fn rejects_out_of_range_child() {
        let mut v = model_json();
        tree0(&mut v)["right_children"][0] = 99.into();
        assert!(load(&v).is_err());
    }

    #[test]
    #[ignore = "rfc 0002 case 24"]
    fn rejects_cycle() {
        let mut v = model_json();
        tree0(&mut v)["left_children"][0] = 0.into();
        assert!(load(&v).is_err());
    }

    #[test]
    #[ignore = "rfc 0002 case 24"]
    fn rejects_too_many_trees() {
        let mut v = model_json();
        let t = tree0(&mut v).clone();
        v["learner"]["gradient_booster"]["model"]["trees"] = vec![t; MAX_TREES + 1].into();
        let e = load(&v).unwrap_err().to_string();
        assert!(e.contains("trees"), "{e}");
    }

    #[test]
    #[ignore = "rfc 0002 case 24"]
    fn rejects_too_deep() {
        // a chain: node i splits into leaf 2i+1... as a left spine
        let n = 2 * (MAX_DEPTH + 1) + 1;
        let (mut left, mut right) = (vec![-1i64; n], vec![-1i64; n]);
        let mut id = 0;
        for d in 0..=MAX_DEPTH {
            left[id] = (2 * d + 1) as i64;
            right[id] = (2 * d + 2) as i64;
            id = 2 * d + 1;
        }
        let mut v = model_json();
        let t = tree0(&mut v);
        t["left_children"] = left.into();
        t["right_children"] = right.into();
        for k in [
            "split_indices",
            "split_conditions",
            "default_left",
            "base_weights",
            "split_type",
        ] {
            t[k] = vec![0; n].into();
        }
        let e = load(&v).unwrap_err().to_string();
        assert!(e.contains("depth"), "{e}");
    }

    #[test]
    #[ignore = "rfc 0002 case 24"]
    fn rejects_other_objectives() {
        let mut v = model_json();
        v["learner"]["objective"]["name"] = "reg:squarederror".into();
        assert!(load(&v).is_err());
    }

    #[test]
    #[ignore = "rfc 0002"]
    fn rejects_garbage_and_oversize() {
        assert!(TreeEnsemble::from_json(b"").is_err());
        assert!(TreeEnsemble::from_json(b"{\"learner\":1}").is_err());
        assert!(TreeEnsemble::from_json(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
}
