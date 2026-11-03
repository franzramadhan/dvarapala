---
title: Learned scoring
---

dvarapala can learn what an attack looks like on your own site. It then
scores every client with that model. The loop has three steps, and each
step uses tools that you already run:

1. Collect: LLM labels ([RFC 0023](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0023-llm-labels.md))
   sample suspicious requests and ask an LLM what they look like. They
   write each answer next to the numeric features of the client as one
   JSON line.
2. Train: you train an XGBoost classifier on those lines (or on your own
   access logs). You save it as XGBoost JSON.
3. Score: the gateway loads the model with `ml.model` and scores each
   client on every request
   ([RFC 0002](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0002-adaptive-detection.md)).
   If a score is above `ml.threshold`, the gateway answers `429`.

The LLM is never on the request path and never changes a verdict. It only
labels samples, to the side of the traffic. The model does the scoring in
process, in microseconds.

## How scoring works

For each client, dvarapala keeps ten numbers and updates them on every
request. The client is the key of the rate limiter: the source IP, or the
address from `trusted_proxies`.

| Name | Meaning |
|---|---|
| `window_requests` | Requests in the current window |
| `rate_ewma` | Average requests per window |
| `iat_mean` | Average seconds between requests |
| `iat_var` | Variance of the seconds between requests |
| `size_mean` | Average request body size in bytes (from `Content-Length`, and a chunked body counts as 0) |
| `no_ua_share` | Share of requests without `User-Agent`, 0 to 1 |
| `distinct_paths` | Distinct paths in the window, at most 8 |
| `status_4xx_share` | Share of `4xx` responses, 0 to 1 |
| `global_rate_z` | Instance rate z-score (0 with `detection.enabled = false`) |
| `source_entropy` | Instance source entropy, 0 to 1 (0 without detection) |

The window is `detection.window` (default 1 s). The averages move 10%
toward each new value, so they follow a client within a few requests.

If the bucket of the client, detection and the challenge all allow a
request, the model reads the features of the client. It returns a score
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

Only requests that reach the model update the features. Thus a client
that is already throttled does not raise its own score.

The model is a tree ensemble (a sum of many small decision trees). Each
tree asks a few questions such as "is `rate_ewma` above 1.05?" and adds
its leaf value. The sum goes through a logistic function. This is cheap
enough to run on every request. You can open the JSON to read what the
model learned.

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

Every score goes into the `dvarapala_ml_score` histogram. Thus you can see
the split before you enforce anything.

## Collect training data

Turn on LLM labels with a trigger that selects the traffic you care about.
`ml.llm.export` writes one JSON line per answer. If `ml.llm.persist` is
on, `GET /llm/export` on the admin API streams the same lines from every
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

dvarapala computes the features for the samples even without `ml.model` or
the `ml` feature. Thus you can collect data before you have a model. Each
line is the ten features plus the answer:

```json
{"window_requests": 7, "rate_ewma": 5.6, "iat_mean": 0.16, "iat_var": 0.002,
 "size_mean": 0, "no_ua_share": 0, "distinct_paths": 8, "status_4xx_share": 0.42,
 "global_rate_z": 2.1, "source_entropy": 0.88,
 "label": "scraper", "confidence": 0.86, "trigger": "attack", "at": 1793520000000}
```

Sampling selects only suspicious traffic, so add normal traffic too. Use a
`route` trigger on a path that real users hit. Or add rows from your
access logs with the same feature definitions, labeled `benign`. A model
that never saw normal clients cannot tell them apart.

## Train

Review the labels first. The LLM is good at "attack or not" and less
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

[`examples/ml/`](https://github.com/franzramadhan/dvarapala/tree/main/examples/ml)
has this script as `train.py`, with synthetic labels and the dummy model
it writes. The data is not real traffic: use it to learn the format, not
to enforce.

The model must be XGBoost JSON with objective `binary:logistic` and
booster `gbtree`. It can have at most 1024 trees, 65 536 nodes, depth 16
and 16 MiB. Train it on columns named after the features above (any
subset, any order). A model trained on the columns of another dataset does
not load: `unknown feature "Flow Duration"`.

Before you deploy, look at what the model learned. Count which features
the splits use (`booster.get_score(importance_type="weight")`). If the
model splits on one feature only, it is a fixed limit in disguise. Its
split value tells you which real clients will cross it.

## Score

```toml
[ml]
model = "/etc/dvarapala/model.json"
threshold = 1.0  # watch only: a score is never above 1
```

- The model needs a build with the `ml` feature. The container image has
  it, and so do the gateways of the operator (with the model mounted from
  a ConfigMap through `gateway.mounts`). A binary built with
  `--features ml` also has it. The release tarballs and the SDKs do not
  have it.
- Scoring runs inside the rate limiter, so it needs reverse mode with
  `[rate_limit]` enabled.
- If the model is bad, dvarapala does not start and gives the reason, for
  example
  `model: objective "reg:squarederror" not supported, train with binary:logistic`.
- A new model needs no restart
  ([RFC 0029](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0029-ml-model-reload.md)).
  Replace the file and reload (`SIGHUP`, `POST /reload`), or let
  `config_watch` see the change. Every reload reads the file again and
  swaps the model if its bytes changed. `ml.threshold` reloads too. Each
  client keeps its features across the swap. If the new file is bad,
  dvarapala refuses the reload with the reason, and the running model
  continues to score.
- `dvarapala_ml_model_info{sha256}` and `GET /status` (`ml`) show which
  model each replica runs. Compare them with `sha256sum model.json`. With
  the operator, update the ConfigMap of the model. The gateways poll it
  ([`kubernetes-ml.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/kubernetes-ml.yaml)).

There is no observe mode. Thus start with `threshold = 1.0` and read
`dvarapala_ml_score` for a few days. An `ml_band` trigger
(`band = [0.5, 1.0]`) sends the high scorers to the LLM, so you can see
who they are before you lower the threshold. Lower the threshold with a
reload. Then retrain on the new labels, replace the file, and do these
steps again.

Keys: [`[ml]`](configuration.html#ml), [`[ml.llm]`](configuration.html#mlllm).
