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

// The subset of XGBoost's JSON model schema this reads.
#[derive(Deserialize)]
struct Json {
    learner: Learner,
}

#[derive(Deserialize)]
struct Learner {
    #[serde(default)]
    feature_names: Vec<String>,
    gradient_booster: Booster,
    learner_model_param: Param,
    objective: Objective,
}

#[derive(Deserialize)]
struct Booster {
    name: String,
    model: Model,
}

#[derive(Deserialize)]
struct Model {
    trees: Vec<JsonTree>,
}

#[derive(Deserialize)]
struct JsonTree {
    left_children: Vec<i64>,
    right_children: Vec<i64>,
    split_indices: Vec<i64>,
    split_conditions: Vec<f32>,
    default_left: Vec<Flag>,
    #[serde(default)]
    split_type: Vec<i64>,
}

/// `default_left` is `0`/`1` in current XGBoost, `true`/`false` in older.
#[derive(Deserialize, Clone, Copy)]
#[serde(untagged)]
enum Flag {
    Bool(bool),
    Int(i64),
}

#[derive(Deserialize)]
struct Param {
    /// `"4E-1"`, or `"[4E-1]"` since XGBoost 3
    base_score: String,
    #[serde(default)]
    num_class: Option<String>,
}

#[derive(Deserialize)]
struct Objective {
    name: String,
}

fn err(msg: impl Into<String>) -> ModelError {
    ModelError(msg.into())
}

impl TreeEnsemble {
    /// Parses and validates a model. Never panics, whatever the bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() > MAX_BYTES {
            return Err(err(format!("file over {MAX_BYTES} bytes")));
        }
        let j: Json = serde_json::from_slice(bytes).map_err(|e| err(e.to_string()))?;
        let l = j.learner;
        if !matches!(
            l.objective.name.as_str(),
            "binary:logistic" | "reg:logistic"
        ) {
            return Err(err(format!(
                "objective {:?} not supported, train with binary:logistic",
                l.objective.name
            )));
        }
        if l.gradient_booster.name != "gbtree" {
            return Err(err(format!(
                "booster {:?} not supported, use gbtree",
                l.gradient_booster.name
            )));
        }
        if l.learner_model_param
            .num_class
            .as_deref()
            .is_some_and(|n| n != "0" && n != "1")
        {
            return Err(err("multi-class models are not supported"));
        }
        if l.feature_names.is_empty() {
            return Err(err("model has no feature names; train on named columns"));
        }
        // model column index -> dvarapala feature index
        let columns = l
            .feature_names
            .iter()
            .map(|n| {
                FEATURE_NAMES.iter().position(|f| f == n).ok_or_else(|| {
                    err(format!(
                        "unknown feature {n:?}, expected one of {FEATURE_NAMES:?}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let trees = &l.gradient_booster.model.trees;
        if trees.len() > MAX_TREES {
            return Err(err(format!("{} trees, limit {MAX_TREES}", trees.len())));
        }
        let total: usize = trees.iter().map(|t| t.left_children.len()).sum();
        if total > MAX_NODES {
            return Err(err(format!("{total} nodes, limit {MAX_NODES}")));
        }
        let p: f64 = l
            .learner_model_param
            .base_score
            .trim_matches(['[', ']'])
            .parse()
            .map_err(|_| err("base_score is not a number"))?;
        if !(p > 0.0 && p < 1.0) {
            return Err(err("base_score must be in (0, 1) for a logistic model"));
        }
        Ok(Self {
            base_margin: (p / (1.0 - p)).ln(),
            trees: trees
                .iter()
                .enumerate()
                .map(|(i, t)| tree(t, &columns).map_err(|e| err(format!("tree {i}: {}", e.0))))
                .collect::<Result<_, _>>()?,
        })
    }
}

fn tree(t: &JsonTree, columns: &[usize]) -> Result<Tree, ModelError> {
    let n = t.left_children.len();
    if n == 0 {
        return Err(err("no nodes"));
    }
    let lens = [
        t.right_children.len(),
        t.split_indices.len(),
        t.split_conditions.len(),
        t.default_left.len(),
    ];
    if lens.iter().any(|&l| l != n) || !(t.split_type.is_empty() || t.split_type.len() == n) {
        return Err(err("node arrays differ in length"));
    }
    let mut depth = vec![0usize; n];
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let (l, r) = (t.left_children[i], t.right_children[i]);
        if l == -1 && r == -1 {
            nodes.push(Node::Leaf(t.split_conditions[i]));
            continue;
        }
        // children after their parent: no cycles, and depth in one pass
        let child = |c: i64| usize::try_from(c).ok().filter(|&c| c > i && c < n);
        let (Some(l), Some(r)) = (child(l), child(r)) else {
            return Err(err(format!("node {i}: child index out of range")));
        };
        if t.split_type.get(i).is_some_and(|&s| s != 0) {
            return Err(err(format!(
                "node {i}: categorical splits are not supported"
            )));
        }
        let feature = usize::try_from(t.split_indices[i])
            .ok()
            .and_then(|c| columns.get(c).copied())
            .ok_or_else(|| err(format!("node {i}: split feature out of range")))?;
        let d = depth[i] + 1;
        if d > MAX_DEPTH {
            return Err(err(format!("depth over {MAX_DEPTH}")));
        }
        depth[l] = d;
        depth[r] = d;
        nodes.push(Node::Split {
            feature,
            threshold: t.split_conditions[i],
            left: l as u32,
            right: r as u32,
            default_left: match t.default_left[i] {
                Flag::Bool(b) => b,
                Flag::Int(v) => v != 0,
            },
        });
    }
    Ok(Tree { nodes })
}

impl Tree {
    fn eval(&self, f: &Features) -> f32 {
        let mut i = 0;
        loop {
            match self.nodes[i] {
                Node::Leaf(v) => return v,
                Node::Split {
                    feature,
                    threshold,
                    left,
                    right,
                    default_left,
                } => {
                    // XGBoost compares in f32; NaN is a missing value
                    let x = f[feature] as f32;
                    let go_left = if x.is_nan() {
                        default_left
                    } else {
                        x < threshold
                    };
                    i = if go_left { left } else { right } as usize;
                }
            }
        }
    }
}

impl Scorer for TreeEnsemble {
    fn score(&self, features: &Features) -> f64 {
        let margin = self.base_margin
            + self
                .trees
                .iter()
                .map(|t| f64::from(t.eval(features)))
                .sum::<f64>();
        1.0 / (1.0 + (-margin).exp())
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
    fn unknown_feature_is_named() {
        let mut v = model_json();
        v["learner"]["feature_names"][9] = "dst_port".into();
        let e = load(&v).unwrap_err().to_string();
        assert!(e.contains("dst_port"), "{e}");
    }

    #[test]
    fn rejects_out_of_range_child() {
        let mut v = model_json();
        tree0(&mut v)["right_children"][0] = 99.into();
        assert!(load(&v).is_err());
    }

    #[test]
    fn rejects_cycle() {
        let mut v = model_json();
        tree0(&mut v)["left_children"][0] = 0.into();
        assert!(load(&v).is_err());
    }

    #[test]
    fn rejects_too_many_trees() {
        let mut v = model_json();
        let t = tree0(&mut v).clone();
        v["learner"]["gradient_booster"]["model"]["trees"] = vec![t; MAX_TREES + 1].into();
        let e = load(&v).unwrap_err().to_string();
        assert!(e.contains("trees"), "{e}");
    }

    #[test]
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
    fn rejects_other_objectives() {
        let mut v = model_json();
        v["learner"]["objective"]["name"] = "reg:squarederror".into();
        assert!(load(&v).is_err());
    }

    #[test]
    fn rejects_garbage_and_oversize() {
        assert!(TreeEnsemble::from_json(b"").is_err());
        assert!(TreeEnsemble::from_json(b"{\"learner\":1}").is_err());
        assert!(TreeEnsemble::from_json(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
}
