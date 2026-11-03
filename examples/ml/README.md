# Dummy model for learned scoring

> Disclaimer: Everything in this directory is dummy data for learning.
> The rows in `labels.jsonl` are synthetic: `train.py` draws them from
> hand-picked ranges. They are not real traffic, and no LLM labeled them.
> `model.json` was trained on those rows. It shows the file format and the
> loop, and it scores the two sample clients of the
> [learned scoring page](../../site/docs/ml.md) correctly. Do not enforce it
> on a real site: it does not know what your normal clients look like.
> Train your own model on labels from your own traffic.

| File | Contents |
|---|---|
| `train.py` | Writes the synthetic labels, trains a binary XGBoost model and prints what it learned |
| `labels.jsonl` | 290 synthetic rows in the `ml.llm.export` format: the ten features, `label`, `confidence`, `trigger`, `at` |
| `model.json` | The model `train.py` wrote: XGBoost JSON, `binary:logistic`, 20 trees of depth 3 |

## Try the model

Use [`../ml.toml`](../ml.toml) and point `ml.model` at this file. You need a
build with the `ml` feature (the container image has it).

```sh
cp examples/ml/model.json /etc/dvarapala/model.json
dvarapala serve --config examples/ml.toml
```

Keep `threshold = 1.0`. Then the model only writes scores to the
`dvarapala_ml_score` histogram and throttles nobody.

## Train it again

`train.py` declares its dependencies inline, so [uv](https://docs.astral.sh/uv/)
runs it without a virtual environment:

```sh
uv run examples/ml/train.py                          # synthetic labels, new model.json
uv run examples/ml/train.py --labels labels.jsonl    # your own ml.llm.export file
```

On macOS, the XGBoost wheel needs OpenMP: `brew install libomp`. As an
alternative, run the script in a Linux container:

```sh
docker run --rm -v "$PWD/examples/ml:/w" -w /w \
  ghcr.io/astral-sh/uv:python3.12-bookworm-slim uv run train.py
```

The script prints the number of splits on each feature and the scores of
the two sample clients:

```
training on 172 rows: 82 attack, 90 benign
splits per feature: {'iat_mean': 7.0, 'iat_var': 9.0, 'size_mean': 8.0, 'status_4xx_share': 1.0, 'global_rate_z': 3.0}
reader score 0.027, path walker score 0.991
```

If a model splits on one feature only, it is a fixed limit in disguise.
The first version of this dummy data had that problem: every attack class
had a higher `rate_ewma` than every benign client, so the model split on
`rate_ewma` only. The current profiles overlap on rate, so the model must
use the spacing, size and `4xx` features too.

## What to change for real data

- Collect labels with `[ml.llm]` and `export`, as in `../ml.toml`. Add
  benign rows from a `route` trigger or from your access logs.
- Review the labels. `train.py` keeps rows with `confidence >= 0.8` and
  trains "attack or not" (`label != "benign"`).
- Keep the column names. A model trained on other column names does not
  load: `unknown feature "Flow Duration"`.
- Stay in the limits: `binary:logistic`, `gbtree`, at most 1024 trees,
  65 536 nodes, depth 16 and 16 MiB.
- Replace the model file and reload (`SIGHUP`, `POST /reload` or
  `config_watch`). A bad file is refused and the running model continues.
