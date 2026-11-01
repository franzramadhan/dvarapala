# 0029: Reload the scoring model in place

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-11-01 | #259 | |

> Apply `ml.model` and `ml.threshold` on a reload (`SIGHUP`,
> `POST /reload`, `config_watch`) instead of only at start, keep every
> client's features across the swap, and refuse a bad model while the
> running one keeps scoring. The model in force is visible by its
> SHA-256 in a metric and the admin API.

## Problem

Learned scoring (RFC 0002, `site/docs/ml.md`) is a loop: watch with
`threshold = 1.0`, collect labels (RFC 0023), retrain, lower the
threshold, repeat. Every step needs a restart today: `ml` is a restart
key in `crates/dvarapala/src/reload.rs` (only `ml.llm.retention` reloads).

- A restart drops open connections and tunnels, and empties the rate
  limiter table: every client's buckets and its ten scoring features
  start from zero, so the first windows after a model change score
  clients on almost no history.
- Behind the operator (RFC 0019, 0025), the model is a ConfigMap
  mounted through `gateway.mounts`. Kubelet updates the file in place,
  but nothing rereads it: a new model needs a rollout of every gateway
  pod.
- Nothing tells which model a replica runs. After a partial rollout, or
  a ConfigMap that did not propagate yet, replicas score with different
  models and the `dvarapala_ml_score` histogram mixes them.

## Proposal

- A reload applies `ml.model` and `ml.threshold` in place. The model
  file is read and parsed off the request path, with the same parser
  and limits as at start (`TreeEnsemble::from_json`: 16 MiB, 1024
  trees, 65 536 nodes, depth 16, named features).
- Every reload rereads the model file, even when the config file did
  not change: a new model under the same path is applied when its bytes
  differ from the running one (SHA-256). The same bytes keep the running
  model (no swap, no log line).
- `config_watch` (RFC 0019) also polls the `ml.model` file at the same
  interval and reloads when its bytes change, so a ConfigMap update
  reaches the gateways without a rollout.
- A model that fails to read or parse refuses the whole reload, as an
  invalid config file does today: nothing changes, the running model
  keeps scoring, `POST /reload` answers `422` with the reason
  (`ml.model <path>: <error>`), and the log line names it. Fail closed:
  never no model, never half of one.
- Each client's features (`ClientStats`) stay in the limiter table
  across the swap. The next request is scored by the new model on the
  history it already has.
- Every transition reloads: a model set, changed or removed. Without a
  model, scoring falls back to the features-only scorer when `[ml.llm]`
  is on (RFC 0023), or turns off. Turning scoring on starts each
  client's features at its next request.
- A model in a build without the `ml` feature stays an error, at start
  and on reload.
- The swap is one pointer: the scorer and the threshold move into the
  policy the rate limiter already reads once per request (RFC 0014). A
  request in flight finishes with the model it started with.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/l7/src/detection.rs` | `Scoring` carries the model's SHA-256 (`ring`, already a dependency) next to the scorer |
| `crates/l7/src/rate_limit.rs` | reads the scorer from the policy instead of `Shared` |
| `crates/l7/src/control.rs` | `Reload` gains `scoring`: the scorer and threshold to swap in |
| `crates/dvarapala/src/layer.rs` | loads the model and hashes it, at start and on reload |
| `crates/dvarapala/src/reload.rs` | `ml.model`, `ml.threshold` leave the restart list; keeps the running model when the hash is the same |
| `crates/dvarapala/src/watch.rs` | polls the model file next to the config file |
| `crates/dvarapala/src/admin/` | `GET /status` gains `ml` |
| `crates/operator/src/policy.rs` | `ml.model`, `ml.threshold` join `RELOADABLE`, so a policy change to them no longer rolls the gateway pods |
| `ui/` | the health page shows the model hash and load time |
| `examples/ml.toml`, `site/docs/ml.md`, `CONFIG.md` | a scoring config with the reload loop; the docs drop "a new model needs a restart" |

### Configuration

No new key. Two keys change from restart to reload:

| Key | Default | |
|---|---|---|
| `ml.model` | unset | Applied on reload, file reread on every reload and by `config_watch` |
| `ml.threshold` | `0.9` | Applied on reload |

The other `[ml]` keys keep their current reload behavior.

### Logs and metrics

| | |
|---|---|
| `msg="model loaded" sha256=<hex>` | at start and on each swap |
| `msg="model changed on disk"` | `config_watch` saw new model bytes, followed by the reload lines |
| `msg="config reload failed" error="ml.model <path>: <reason>"` | the existing refusal line, with the model's reason |
| `dvarapala_ml_model_info{sha256}` | `1` for the model in force (first 12 hex digits), `0` for the one it replaced |
| `dvarapala_ml_model_loaded_timestamp_seconds` | Unix time of the last load or swap |
| `GET /status` `ml` | `{"sha256": "<hex>", "threshold": f, "loaded_at": unix}`, `null` without a model |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a model scoring a client 0.2 under threshold 0.9 | a reload sets `ml.threshold = 0.1` | the next request from that client is throttled, no restart key is reported | integration |
| 2 | model A scoring a client 0.2 | the file at the same path is replaced by model B scoring 0.99, then a reload | the next request is throttled; `dvarapala_ml_model_info` names B only | integration |
| 3 | a client with 20 requests of history | the model is swapped | its features keep the history: B's score matches B scored on the same 20 requests, not on 1 | unit (l7) |
| 4 | a running model | the file is replaced by invalid JSON, a `reg:squarederror` model, or a model over the limits, then `POST /reload` | `422` naming `ml.model` and the reason; the running model's verdicts and info metric are unchanged | integration |
| 5 | the same model bytes | a reload | no swap: no `model loaded` line, `loaded_at` unchanged | integration |
| 6 | `config_watch = "100ms"`, the config file unchanged | the model file changes | the new model scores within a few intervals | integration |
| 7 | no model, `[ml.llm]` off | a reload sets `ml.model` | scoring starts; clients get features from their next request | integration |
| 8 | a model, `[ml.llm]` on | a reload removes `ml.model` | no throttles from scoring, samples still carry features (NaN score) | integration |
| 9 | a build without `ml` | a reload sets `ml.model` | refused with `needs a build with the ml feature` | integration |
| 10 | requests in flight on 8 threads | 100 swaps between two models | no panic, every verdict comes from one of the two models | unit (l7) |
| 11 | a reload | `GET /config` | `ml.model` and `ml.threshold` show `reload: true` | integration |
| 12 | a policy whose `ml.threshold` changes | the operator renders it | the restart hash is unchanged | unit (operator) |
| 13 | `examples/ml.toml` | `example_configs_load` | loads | integration |

## Alternatives

| Option | Why not |
|---|---|
| A separate admin call to upload a model (`PUT /model`) | a model that is not in the config file is lost on restart and differs per replica; the file stays the source of truth |
| Watch the model file with inotify | `config_watch` already polls for the same reason (symlink swaps of mounted ConfigMaps), and works on every platform |
| Keep the restart, document a rolling restart | loses every client's history and connections on each step of the loop the docs recommend |
| Compare by modification time instead of a hash | kubelet's symlink swap and `cp -p` make it unreliable; hashing 16 MiB at most per reload is cheap |
| Several models at once (shadow scoring) | worth its own RFC once one model swaps cleanly |

## Security and resource limits

- The model file is trusted input (an operator file, as the config), but
  the parser keeps its limits: 16 MiB read cap, 1024 trees, 65 536
  nodes, depth 16. A reload holds at most two models in memory, the
  running one and the candidate, so 32 MiB at the cap.
- Parsing runs in the reload task, never on a request thread; the swap
  is a pointer under the policy lock the rate limiter already takes.
- `config_watch` reads the model file once per interval (at least
  100 ms), as it reads the config file.
- A refused model leaves the protection path as it was (fail closed).
- `GET /status` shows a hash, never the model.

## Rollout

- **Rollout:** v0.21.0. No new key, no default change. A config that
  restarted to change the model keeps working; a reload now applies it.
  Operator gateways already run with `config_watch = "10s"` and mounts
  never roll pods, so a model ConfigMap update reaches them within about
  a minute (kubelet sync plus one interval). A policy change to
  `ml.threshold` or `ml.model` reloads instead of rolling the pods.
- **Off switch:** none needed: an unchanged model file never swaps. To
  roll back a model, put the old file back and reload.

## Implementation notes

- The hash lives in the binary, not in l7: `crates/dvarapala/src/model.rs`
  holds the running model (`Model`: scorer, SHA-256, load time), loads it
  at start and on reload, and moves the features-only scorer (RFC 0023)
  out of `layer.rs`. `Scoring` in l7 is unchanged; it moved from the
  layer's `Shared` into its `Policy`, and `Reload.scoring` is
  `Option<Option<Scoring>>` (`None` keeps it, as `routes` does).
- The `metrics` crate cannot remove a series, so the replaced model's
  `dvarapala_ml_model_info` goes to `0` instead.
- The `model loaded` line has no tree count: the engine does not expose
  it, and the hash identifies the model.
- The model is loaded only with the rate limiter on, as before: scoring
  runs inside it, and `rate_limit.enabled` needs a restart.
- Case 4 checks invalid JSON, a non-object and `reg:squarederror`; the
  size and shape limits are the engine's own tests (RFC 0002).
- Case 3 and 10 run at the l7 layer with stub scorers
  (`crates/l7/tests/scoring_reload.rs`), cases 1, 2, 4, 5, 7, 8, 9 and
  11 through the reloader (`crates/dvarapala/src/model_tests.rs`), case
  6 against the binary (`crates/dvarapala/tests/watch.rs`).
- The console's Detection page shows the hash, the threshold and the
  load time, and lists the `dvarapala_ml_*` series.
