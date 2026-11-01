---
title: Learned scoring
---

dvarapala can learn what an attack looks like on your own site and score
every client with that model. The loop has three steps, all with tools
you already run:

1. **Collect.** LLM labels ([RFC 0023](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0023-llm-labels.md))
   sample suspicious requests, ask an LLM what they look like, and write
   each answer next to the client's numeric features as one JSON line.
2. **Train.** You train an XGBoost classifier on those lines (or on your
   own access logs) and save it as XGBoost JSON.
3. **Score.** The gateway loads the model with `ml.model` and scores each
   client on every request
   ([RFC 0002](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0002-adaptive-detection.md)).
   A score above `ml.threshold` answers `429`.

The LLM never sits on the request path and never changes a verdict: it
only labels samples, off to the side. The model does the scoring, in
process, in microseconds.

## How scoring works

For each client (the rate limiter's key: source IP, or the address from
`trusted_proxies`), dvarapala keeps ten numbers, updated on every request:

| Name | Meaning |
|---|---|
| `window_requests` | Requests in the current window |
| `rate_ewma` | Average requests per window |
| `iat_mean` | Average seconds between requests |
| `iat_var` | Variance of the seconds between requests |
| `size_mean` | Average request body size in bytes (`Content-Length`; chunked counts as 0) |
| `no_ua_share` | Share of requests without `User-Agent`, 0 to 1 |
| `distinct_paths` | Distinct paths in the window, at most 8 |
| `status_4xx_share` | Share of `4xx` responses, 0 to 1 |
| `global_rate_z` | Instance rate z-score (0 with `detection.enabled = false`) |
| `source_entropy` | Instance source entropy, 0 to 1 (0 without detection) |

The window is `detection.window` (default 1 s). The averages move 10%
toward each new value, so they follow a client within a few requests.

When the client's bucket, detection and the challenge all allow a
request, the model reads the client's features and returns a score
between 0 (normal) and 1 (attack):

```
  rate limit  token bucket per client      -> 429 + Retry-After
    |
    v
  detection   heavy hitters, baseline       -> enforce: 403
    |
    v
  challenge   no pass during an attack      -> proof-of-work page
    |
    v
  model       score of the client's features
    |         score > ml.threshold         -> 429 + Retry-After
    v
  waf, pool, upstream (see Architecture)
```

Only requests that reach the model update the features, so a client
that is already throttled does not raise its own score.

The model is a tree ensemble: each tree asks a few questions such as
"is `rate_ewma` above 1.05?" and adds its leaf value; the sum goes
through a logistic function. That is cheap enough to run on every
request, and you can read what the model learned by opening the JSON.

### Sample input and output

The features of two clients at the moment of a request:

```json
{"window_requests": 1, "rate_ewma": 1.0, "iat_mean": 6.8, "iat_var": 11.2,
 "size_mean": 0, "no_ua_share": 0, "distinct_paths": 1, "status_4xx_share": 0,
 "global_rate_z": 0.3, "source_entropy": 0.91}
```

```json
{"window_requests": 7, "rate_ewma": 5.6, "iat_mean": 0.16, "iat_var": 0.002,
 "size_mean": 0, "no_ua_share": 0, "distinct_paths": 8, "status_4xx_share": 0.42,
 "global_rate_z": 2.1, "source_entropy": 0.88}
```

What the gateway does with them, with `threshold = 0.9`:

| Client | Score | Verdict | Response |
|---|---|---|---|
| first (a reader) | 0.03 | allow | sent upstream |
| second (a scraper walking paths, many `404`s) | 0.99 | throttle | `429`, `Retry-After: 1` (one detection window) |

Every score lands in the `dvarapala_ml_score` histogram, so you can see
the split before you enforce anything.

## Collect training data

Turn on LLM labels with a trigger that picks the traffic you care about.
`ml.llm.export` writes one JSON line per answer; with `ml.llm.persist`,
`GET /llm/export` on the admin API streams the same lines from every
replica.

```toml
[ml.llm]
endpoint = "http://<host>:4000/v1"
protocol = "chat"
model = "<model>"
instructions = "A public calculator API. Normal clients call /api/ a few times a minute."
export = "/var/lib/dvarapala/labels.jsonl"

[[ml.llm.triggers]]
on = "attack"      # detection in Attack

[[ml.llm.triggers]]
on = "waf"         # a WAF match
```

The features are computed for the samples even without `ml.model` or the
`ml` feature, so you can collect before you have any model. Each line is
the ten features plus the answer:

```json
{"window_requests": 7, "rate_ewma": 5.6, "iat_mean": 0.16, "iat_var": 0.002,
 "size_mean": 0, "no_ua_share": 0, "distinct_paths": 8, "status_4xx_share": 0.42,
 "global_rate_z": 2.1, "source_entropy": 0.88,
 "label": "scraper", "confidence": 0.86, "trigger": "attack", "at": 1793520000000}
```

Sampling only picks suspicious traffic, so add normal traffic too: a
`route` trigger on a path real users hit, or rows from your access logs
with the same feature definitions, labeled `benign`. A model that never
saw normal clients cannot tell them apart.

## Train

Review the labels first: the LLM is good at "attack or not" and less
reliable on the exact type, so train a binary model.

```python
import pandas as pd, xgboost as xgb

df = pd.read_json("labels.jsonl", lines=True).dropna()
df = df[df.confidence >= 0.8]
y = (df.label != "benign").astype(int)
X = df.drop(columns=["label", "confidence", "trigger", "at"])

booster = xgb.train(
    {"objective": "binary:logistic", "max_depth": 4},
    xgb.DMatrix(X, label=y),
    num_boost_round=50,
)
booster.save_model("model.json")
```

The model must be XGBoost JSON with objective `binary:logistic` and
booster `gbtree`, at most 1024 trees, 65 536 nodes, depth 16 and 16 MiB,
trained on columns named after the features above (any subset, any
order). A model trained on another dataset's columns does not load:
`unknown feature "Flow Duration"`.

Before you deploy, look at what it learned: count which features the
splits use (`booster.get_score(importance_type="weight")`). A model that
splits on one feature only is a fixed limit in disguise, and its split
value tells you which real clients would cross it.

## Score

```toml
[ml]
model = "/etc/dvarapala/model.json"
threshold = 1.0  # watch only: a score is never above 1
```

- The model needs a build with the `ml` feature: the container image
  (and so the operator's gateways, with the model mounted from a
  ConfigMap through `gateway.mounts`), or a binary built with
  `--features ml`. The release tarballs and the SDKs do not have it.
- Reverse mode with `[rate_limit]` enabled: scoring runs inside the rate
  limiter.
- The model is read once at start. A bad one stops the start with the
  reason, for example
  `model: objective "reg:squarederror" not supported, train with binary:logistic`.
  A new model needs a restart.

There is no observe mode, so start with `threshold = 1.0` and read
`dvarapala_ml_score` for a few days. An `ml_band` trigger
(`band = [0.5, 1.0]`) sends the high scorers to the LLM, so you can check
who they are before you lower the threshold. Retrain on the new labels
and repeat.

Keys: [`[ml]`](configuration.html#ml), [`[ml.llm]`](configuration.html#mlllm).
