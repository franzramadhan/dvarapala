# 0002: Adaptive detection

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-27 | #2 | v0.2.0 |

> Detect floods from the traffic itself, without training data: heavy
> hitters per prefix, a learned rate baseline, and source entropy drive a
> per-instance attack state that tightens the limits. An optional scoring
> hook evaluates a small tree-ensemble model for operators who train one.

## Problem

RFC 0001's token bucket uses fixed limits. A fixed limit is either too
loose during a flood or too tight on a busy day, and it cannot tell a
distributed flood (many clients, each under the limit) from a traffic peak.

The ML approach in arXiv 2308.15674 (classifiers trained on CICDDoS2019)
does not fit here:

- Its features describe completed flows, computed after the flow ends. A
  proxy needs a verdict per packet or request.
- Its top features (`Inbound`, `Source Port`, `Destination Port`) describe
  the dataset's testbed, and the reported 99.9999% accuracy comes from a
  split of the same dataset. That does not carry over to other networks.
- Most of its attack classes are reflection floods (DNS, NTP, LDAP, SSDP)
  that saturate the uplink before they reach a proxy.

What carries over: per-flow statistics as features, and tree ensembles as
a cheap classifier. This RFC keeps both behind an optional hook and makes
the default detection statistical, bounded and training-free.

## Proposal

- Every request (and every connection, once the L4 RFC lands) is an
  observation for the detector: client prefix, source port, size, time.
- Three detectors run per window (`detection.window`, default 1 s):
  - **Heavy hitters:** a count-min sketch (conservative update) plus a
    top-k list finds the prefixes sending the most traffic, in fixed
    memory whatever the number of sources.
  - **Rate baseline:** an exponentially weighted mean and variance of the
    total request rate. A window more than `z_threshold` standard
    deviations above the mean is anomalous.
  - **Source entropy:** Shannon entropy of client prefixes over a fixed
    number of hashed buckets. A sharp drop means few sources dominate. A
    spoofed or botnet flood (entropy up with the rate) is the rate
    baseline's job.
- An attack state machine: `Normal`, `Suspect`, `Attack`, `Cooldown`.
  `Suspect` after one anomalous window, `Attack` after `trigger_windows`
  in a row, `Cooldown` on the first normal window, then `Normal` after
  `cooldown_windows` normal ones (an anomalous window in `Cooldown` goes
  straight back to `Attack`). The baseline does not learn during `Attack`,
  so a long flood cannot become the new normal.
- In `Attack` (not `Cooldown`):
  - Top-k heavy-hitter prefixes get `Drop`.
  - Every other client's bucket rate is multiplied by
    `attack_rate_factor` (default `0.25`).
  - Once a challenge RFC lands, new clients get `Challenge` instead.
- Optional scoring hook (cargo feature `ml`, off by default):
  - A `Scorer` trait in `engine` turns a fixed feature vector into a score
    in `[0, 1]`. A score above `ml.threshold` turns `Allow` into
    `Throttle`.
  - `TreeEnsemble` implements it by evaluating gradient-boosted trees
    loaded from an XGBoost JSON model (`Booster.save_model("m.json")`), in
    pure Rust with no runtime dependency.
  - The feature vector is dvarapala's own (below), computed online. A
    model trained on CICDDoS2019 CSV columns does not load: the feature
    names in the model must match.
- The detector is advisory first: `detection.mode = "observe"` (default)
  logs and exports metrics without changing verdicts. `"enforce"` applies
  them. Operators watch a baseline settle before enforcing.

### Online features (for `ml`)

| # | Feature | Per |
|---|---|---|
| 0 | requests in the current window | client |
| 1 | request rate EWMA | client |
| 2 | mean inter-arrival time | client |
| 3 | inter-arrival time variance | client |
| 4 | mean request size | client |
| 5 | share of requests with no `User-Agent` | client |
| 6 | distinct paths in the window (bounded set) | client |
| 7 | 4xx share of responses | client |
| 8 | global rate z-score | instance |
| 9 | source entropy | instance |

Per-client features live in the RFC 0001 limiter table entry, so they share
its capacity and eviction.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/detect/sketch.rs` | count-min sketch, conservative update, window rotation |
| `crates/engine/src/detect/heavy.rs` | top-k heavy hitters on top of the sketch |
| `crates/engine/src/detect/baseline.rs` | EWMA mean and variance, z-score |
| `crates/engine/src/detect/entropy.rs` | hashed-bucket Shannon entropy |
| `crates/engine/src/detect/state.rs` | `Normal`, `Suspect`, `Attack`, `Cooldown` transitions |
| `crates/engine/src/detect/mod.rs` | `Detector`: feeds observations to the three detectors, exposes the state |
| `crates/engine/src/score/features.rs` | online feature vector per client |
| `crates/engine/src/score/tree.rs` | `TreeEnsemble`: XGBoost JSON parse, validate, evaluate (feature `ml`) |
| `crates/engine/src/score/mod.rs` | `Scorer` trait |
| `crates/l7/src/rate_limit.rs` | records observations, applies the state to verdicts |
| `crates/dvarapala/src/config.rs` | `detection.*` and `ml.*` keys |
| `fuzz/fuzz_targets/tree_model.rs` | model parser fuzzing |

### Configuration

| Key | Default | |
|---|---|---|
| `detection.enabled` | `true` | Turn detection off entirely |
| `detection.mode` | `"observe"` | `observe` logs only, `enforce` changes verdicts |
| `detection.window` | `"1s"` | Window length |
| `detection.prefix_v4` | `32` | IPv4 prefix length for aggregation; per address by default, shorten (for example `24`) to group subnets |
| `detection.prefix_v6` | `64` | IPv6 prefix length for aggregation; per /64 by default (one host or LAN), shorten (for example `48`) to group sites |
| `detection.sketch_width` | `2048` | Count-min columns |
| `detection.sketch_depth` | `4` | Count-min rows (hash functions) |
| `detection.top_k` | `64` | Heavy hitters tracked |
| `detection.ewma_alpha` | `0.05` | Baseline learning rate per window |
| `detection.warmup_windows` | `300` | Windows before the baseline can alarm |
| `detection.z_threshold` | `4.0` | Anomalous window threshold |
| `detection.entropy_buckets` | `1024` | Hashed buckets for entropy |
| `detection.entropy_drop` | `0.5` | Relative entropy drop that counts as anomalous |
| `detection.trigger_windows` | `3` | Anomalous windows in a row to enter `Attack` |
| `detection.cooldown_windows` | `30` | Normal windows to leave `Cooldown` |
| `detection.attack_rate_factor` | `0.25` | Bucket rate multiplier in `Attack` |
| `ml.model` | none | Path to an XGBoost JSON model; unset turns scoring off |
| `ml.threshold` | `0.9` | Score above which `Allow` becomes `Throttle` |

### Logs and metrics

| | |
|---|---|
| `dvarapala_detection_state` | 0 `Normal`, 1 `Suspect`, 2 `Attack`, 3 `Cooldown` |
| `dvarapala_detection_rate_zscore` | Current window z-score |
| `dvarapala_detection_source_entropy` | Current window entropy, normalized to `[0, 1]` |
| `dvarapala_detection_heavy_hitters` | Prefixes currently in the top-k above the per-client limit |
| `dvarapala_detection_transitions_total{from,to}` | State changes |
| `dvarapala_ml_score` | Histogram of scores (feature `ml`) |
| `msg=attack_started zscore=... entropy=... top=<prefix>,...` | Info, once per transition |
| `msg=attack_ended duration=...` | Info, once per transition |

## Test cases

All engine tests take time as an input; none sleep.

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | sketch w=2048 d=4 | 10k keys with known counts | every estimate >= true count, error within e/w of total for 99% | unit (`sketch`) |
| 2 | sketch with counts | window rotates twice | old counts gone | unit (`sketch`) |
| 3 | 1 key at 50% of traffic, 10k keys at noise | top-k k=8 | the key is first | unit (`heavy`) |
| 4 | 1M distinct keys | observe all | sketch and top-k memory unchanged | unit (`heavy`) |
| 5 | constant rate 100/window for warmup | window at 100 | z-score near 0 | unit (`baseline`) |
| 6 | Poisson rate 100 after warmup | window at 1000 | z-score above 4 | unit (`baseline`) |
| 7 | before `warmup_windows` | window at 1000 | no alarm | unit (`baseline`) |
| 8 | state `Attack` | 1 hour of flood windows (360 windows of 10 s) | baseline mean unchanged | unit (`baseline`, `state`) |
| 9 | uniform sources over 1024 buckets | entropy | near 1.0 normalized | unit (`entropy`) |
| 10 | one source | entropy | 0.0 | unit (`entropy`) |
| 11 | `Normal` | 1 anomalous window | `Suspect` | unit (`state`) |
| 12 | `Suspect` | normal window | back to `Normal` | unit (`state`) |
| 13 | `Normal` | `trigger_windows` anomalous in a row | `Attack`, transition counted | unit (`state`) |
| 14 | `Attack` | `cooldown_windows` normal | `Cooldown` then `Normal` | unit (`state`) |
| 15 | `Cooldown` | anomalous window | `Attack` again, no `Suspect` step | unit (`state`) |
| 16 | synthetic trace: 10 min baseline, then 200 prefixes at 50x | replay through `Detector` | `Attack` within `trigger_windows + 1` windows, top-k holds attack prefixes | integration (`engine/tests/replay.rs`) |
| 17 | synthetic trace: baseline that doubles over 1 hour | replay | never `Attack` | integration (`replay`) |
| 18 | synthetic trace: one /24 at 30% of traffic, rate normal, `prefix_v4 = 24` | replay | entropy drop flags it, `Attack` | integration (`replay`) |
| 29 | defaults, heavy hitter 192.0.2.10 in `Attack`, `enforce` | request from 192.0.2.11 | not dropped (own group) | integration (`l7`) |
| 30 | `prefix_v4 = 24`, same case | request from 192.0.2.11 | dropped | integration (`l7`) |
| 19 | `mode = "observe"`, `Attack` | heavy-hitter request | `Allow`, metrics and log still emitted | integration (`l7`) |
| 20 | `mode = "enforce"`, `Attack` | heavy-hitter request | `Drop` | integration (`l7`) |
| 21 | `mode = "enforce"`, `Attack` | other client over `rate * attack_rate_factor` | 429 | integration (`l7`) |
| 22 | XGBoost JSON with 2 stumps, known inputs | evaluate | score equals XGBoost's `predict` output to 1e-6 | unit (`tree`), fixture from `xgboost` |
| 23 | model naming a feature dvarapala does not compute | load | error names the feature | unit (`tree`) |
| 24 | model over limits (trees, depth, nodes) or with out-of-range child index | load | error, no panic | unit (`tree`), fuzz |
| 25 | arbitrary bytes as model | load | `Err`, never panic or unbounded allocation | fuzz (`tree_model`) |
| 26 | `ml.threshold` 0.9, score 0.95 | request otherwise allowed | 429 | integration (`l7`, feature `ml`) |
| 27 | detection on, 100k req/s synthetic | `Detector::observe` | under 200 ns per observation | bench (`criterion`) |
| 28 | detection on, defaults | engine memory | under 256 KB beyond the limiter table | bench |

## Implementation notes

Found while building, folded back from the PRs:

- One sketch window, cleared when the window closes, instead of two
  rotating ones: detection only reads the current window.
- Entropy is judged as a relative drop of perplexity (`2^H`) against its
  own EWMA baseline, only when the window has at least 256 samples and the
  rate z-score is above `-z_threshold` (a quiet window is not an attack).
- The baselines learn only from non-anomalous windows outside `Attack`.
  Known limit: a lasting legitimate step change (a launch) stays in
  `Attack` until the operator restarts or raises `z_threshold`; `observe`
  mode is the guard while baselines settle.
- Idle gaps close up to `trigger_windows + cooldown_windows` empty
  windows, so time without traffic still moves the state machine.
- The heavy-hitter threshold is the limiter's allowance per window: a
  prefix under the normal rate limit is never a heavy hitter.
- `RateLimitLayer::new` returns `Result`: it validates the detector config
  and `attack_rate_factor` in `(0, 1]`. `RateLimitConfig` gained a `now`
  clock so tests drive time.
- The binary has an `ml` feature; setting `ml.model` in a build without it
  is a start-up error, not a silent no-op.

## Alternatives

| Option | Why not |
|---|---|
| Classifiers from arXiv 2308.15674 as the default | needs completed flows, dataset-specific features, a training pipeline; see Problem |
| ONNX runtime (`ort`, `tract`) for models | MBs of binary and memory for what a tree walk does in KB |
| Exact per-prefix counters (`HashMap`) | memory grows with the number of sources, which the attacker controls |
| Space-Saving instead of count-min plus top-k | comparable; count-min also gives estimates for any key, which per-client features use |
| CUSUM instead of EWMA z-score | sharper on small shifts, but one more tuning knob per signal; can be added behind the same `baseline` module later |
| Exact entropy over all sources | unbounded memory; hashed buckets give a bounded approximation |

## Security and resource limits

- The attacker controls source addresses, ports, sizes and timing. Sketch,
  top-k and entropy buckets are fixed-size arrays allocated at start;
  nothing grows with input.
- Hash seeds are random per process, so an attacker cannot pick keys that
  collide in every sketch row.
- An attacker can try to raise the baseline slowly. `ewma_alpha` bounds
  how fast it moves, and it is frozen during `Attack`.
- An attacker inside a shared prefix causes `Drop` for that prefix in
  `enforce` mode. The defaults keep groups small (one IPv4 address, one
  IPv6 /64) so neighbors in the same subnet are not dropped with it.
  Clients behind one shared address (CGNAT, a campus NAT) still share a
  fate; `observe` mode and the per-client limiter are the guard there.
- Small groups let a flood spread across a subnet stay under the
  per-group threshold. Operators who see that set `prefix_v4` to `24` or
  `prefix_v6` to `48`; entropy and the rate baseline still catch the flood
  at the instance level.
- The model file is input from disk: parsed once at start with limits on
  trees (`1024`), depth (`16`) and nodes (`65536`), and fuzzed.
- Defaults: about 32 KB for one sketch window, 4 KB for entropy, a few KB
  for top-k. Per observation: one hash and `sketch_depth` increments
  (double hashing), O(k) for top-k, O(1) for the rest. Per-client features
  are boxed in the limiter table entry and allocated only with `ml`
  scoring on.

## Rollout

- **Rollout:** v0.2.0, after RFC 0001. Detection on in `observe` mode, so
  upgrading changes no verdicts.
- **Off switch:** `detection.enabled = false`, or `detection.mode =
  "observe"` to stop enforcing. Unset `ml.model` disables scoring; builds
  without the `ml` feature do not contain it.
- **Evaluation:** a later RFC can add `dvarapala replay <pcap>` to run
  public datasets (including CICDDoS2019) through the detector offline.
