# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy", "pandas", "xgboost"]
# ///
"""Dummy training run for dvarapala learned scoring (examples/ml/).

DUMMY DATA. The rows are synthetic, drawn from hand-picked ranges that look
like the ten [ml] features. They are not real traffic. The model trained on
them shows the file format and the loop. Do not enforce it in production:
train your own model on labels from your own traffic.

    uv run examples/ml/train.py            # write labels.jsonl and model.json
    uv run examples/ml/train.py --labels my-labels.jsonl   # train on real labels

Without --labels, the script first writes the synthetic labels.jsonl, in the
same format as ml.llm.export, then trains on it like on a real export.
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb

HERE = Path(__file__).parent

# The feature names dvarapala scores. A model with any other column name
# does not load.
FEATURES = [
    "window_requests", "rate_ewma", "iat_mean", "iat_var", "size_mean",
    "no_ua_share", "distinct_paths", "status_4xx_share", "global_rate_z",
    "source_entropy",
]

# label: (rows, {feature: (low, high)}), uniform in each range.
PROFILES = {
    "benign": (160, {
        "window_requests": (0, 4), "rate_ewma": (0.1, 4), "iat_mean": (0.3, 30),
        "iat_var": (1, 200), "size_mean": (0, 2000), "no_ua_share": (0, 0.05),
        "distinct_paths": (1, 3), "status_4xx_share": (0, 0.1),
        "global_rate_z": (-1, 1), "source_entropy": (0.8, 0.95),
    }),
    "scraper": (40, {
        "window_requests": (4, 10), "rate_ewma": (3, 9), "iat_mean": (0.1, 0.3),
        "iat_var": (0, 0.01), "size_mean": (0, 0), "no_ua_share": (0, 0.2),
        "distinct_paths": (6, 8), "status_4xx_share": (0, 0.2),
        "global_rate_z": (0.5, 3), "source_entropy": (0.8, 0.95),
    }),
    "scanner": (30, {
        "window_requests": (1, 6), "rate_ewma": (1, 5), "iat_mean": (0.1, 0.8),
        "iat_var": (0, 0.05), "size_mean": (0, 100), "no_ua_share": (0.3, 1),
        "distinct_paths": (8, 8), "status_4xx_share": (0.4, 0.9),
        "global_rate_z": (0, 2), "source_entropy": (0.8, 0.95),
    }),
    "flood": (30, {
        "window_requests": (20, 100), "rate_ewma": (20, 80), "iat_mean": (0.01, 0.05),
        "iat_var": (0, 0.001), "size_mean": (0, 0), "no_ua_share": (0, 1),
        "distinct_paths": (1, 1), "status_4xx_share": (0, 0.1),
        "global_rate_z": (3, 8), "source_entropy": (0.3, 0.7),
    }),
    "credential_stuffing": (30, {
        "window_requests": (1, 3), "rate_ewma": (0.5, 2.5), "iat_mean": (0.4, 2),
        "iat_var": (0, 0.02), "size_mean": (100, 400), "no_ua_share": (0, 0.1),
        "distinct_paths": (1, 2), "status_4xx_share": (0.5, 0.95),
        "global_rate_z": (0, 2), "source_entropy": (0.8, 0.95),
    }),
}
INTEGER = {"window_requests", "distinct_paths"}


def synthesize(path: Path, seed: int = 7) -> None:
    rng = np.random.default_rng(seed)
    at = 1793520000000  # a fixed timestamp, so the file is reproducible
    rows = []
    for label, (n, ranges) in PROFILES.items():
        for _ in range(n):
            row = {}
            for name in FEATURES:
                lo, hi = ranges[name]
                v = rng.uniform(lo, hi)
                row[name] = int(round(v)) if name in INTEGER else round(float(v), 4)
            row["label"] = label
            row["confidence"] = round(float(rng.uniform(0.7, 0.99)), 2)
            row["trigger"] = "route" if label == "benign" else "attack"
            row["at"] = at
            at += 1000
            rows.append(row)
    rng.shuffle(rows)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    print(f"wrote {len(rows)} synthetic rows to {path}")


def train(labels: Path, out: Path) -> xgb.Booster:
    df = pd.read_json(labels, lines=True).dropna()
    df = df[df.confidence >= 0.8]  # drop answers the LLM was unsure of
    y = (df.label != "benign").astype(int)
    X = df[FEATURES]
    print(f"training on {len(df)} rows: {int(y.sum())} attack, {int((1 - y).sum())} benign")

    booster = xgb.train(
        {"objective": "binary:logistic", "max_depth": 3, "eta": 0.3,
         "colsample_bynode": 0.5, "seed": 7},
        xgb.DMatrix(X, label=y),
        num_boost_round=20,
    )
    booster.save_model(out)
    print(f"wrote {out}")
    return booster


def report(booster: xgb.Booster) -> None:
    # A model that splits on one feature only is a fixed limit in disguise.
    print("splits per feature:", booster.get_score(importance_type="weight"))

    # The two clients from site/docs/ml.md: a reader and a path walker.
    reader = [1, 1.0, 6.8, 11.2, 0, 0, 1, 0, 0.3, 0.91]
    walker = [7, 5.6, 0.16, 0.002, 0, 0, 8, 0.42, 2.1, 0.88]
    scores = booster.predict(xgb.DMatrix(pd.DataFrame([reader, walker], columns=FEATURES)))
    print(f"reader score {scores[0]:.3f}, path walker score {scores[1]:.3f}")
    assert scores[0] < 0.5 < scores[1], "dummy model does not split the two clients"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", type=Path, help="an ml.llm.export file; default: synthesize one")
    ap.add_argument("--out", type=Path, default=HERE / "model.json")
    args = ap.parse_args()

    labels = args.labels
    if labels is None:
        labels = HERE / "labels.jsonl"
        synthesize(labels)
    report(train(labels, args.out))
