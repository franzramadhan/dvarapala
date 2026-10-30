# 0023: LLM labels for sampled traffic

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-30 | #193 | v0.16.0 |

> An operator turns on sampling from the console for a while; requests
> that hit a worthwhile trigger (a WAF match, a failed challenge, an
> attack, an uncertain model score) are sent off the request path to a
> decision model (System One: Cloudflare Clef, TypeSafe Jev) or an
> OpenAI-compatible chat model, which answers a label. The
> labels feed logs, metrics, a console page and a training file for the
> `[ml]` model. They never change a verdict.

## Problem

The layers that decide verdicts are fast and blind to intent: a rate
limit sees counts, the WAF sees signatures, the `[ml]` model (RFC 0002)
sees per-client numbers and needs labeled traffic the operator rarely
has. When something odd shows up (a WAF rule firing in `observe`, a burst
of failed challenges, an attack window), the operator reads logs by hand
to tell a scanner from a scraper from credential stuffing.

A language model can do that reading. It is too slow (100 ms to seconds),
too costly and too easy to steer (the request is attacker input) to sit
in the request path, but it is good at naming a pattern after the fact.
Operators already run gateways such as LiteLLM that put many models
behind one OpenAI-compatible API, with budgets and rate limits per key.

## Use cases

| Use | Trigger | What the labels answer |
|---|---|---|
| Moving the WAF from `observe` to `enforce` | `waf` | Mostly `scanner`: enforce is safe. `benign` labels are false positives, and the sample's rule IDs name the rules to tune |
| Training data for `[ml]` (RFC 0002) | any, with `export` | Features plus a label per client, the labeled traffic the model needs; once trained, the inline model scores and the LLM is rarely needed |
| Incident triage | `attack` | `flood`, `scraper` or `credential_stuffing`, which picks the response: a route rate, a JA4 rule, the challenge |
| Tuning the challenge | `challenge_failed` | Bots that fail the proof of work against real browsers that do, so `difficulty` or `mode` can change |
| Checking the `[ml]` threshold | `ml_band` | What the uncertain scores near `ml.threshold` are |

Labels do not help in real time (they never block) or on quiet traffic
where no trigger fires.

## Proposal

- **Labels, not verdicts.** The model's answer goes to a log line,
  metrics, a console page and an optional training file. No verdict,
  block, challenge or header depends on it. Nothing in the request path
  waits for it.
- **On demand.** `ml.llm.endpoint` configures the model; sampling stays
  off until an operator turns it on from the console (`POST /llm`) for a
  duration (default 30 min, at most 24 h). It turns itself off when the
  duration ends, on reload and on restart. `ml.llm.enabled = true` turns
  it on from the file instead, for a deployment that wants it always.
- **Worthwhile triggers only.** A request is a candidate only when it
  hits a configured trigger: `waf` (a WAF `block` or `would_block`),
  `challenge_failed`, `attack` (detection in `Attack`), `ml_band` (a
  `[ml]` score inside a band, the uncertain ones) or `route` (a named
  route). Each trigger has its own sampling rate. One client is sampled
  at most once per `per_client` (10 min) per trigger.
- **Budget at the provider.** dvarapala does not count tokens or money:
  the provider or the gateway in front of it (LiteLLM `max_budget`,
  `rpm_limit`) owns the budget and answers `429` when it is spent;
  dvarapala counts that as an error and carries on. Locally there is only
  a bounded queue and a concurrency cap, which bound memory, not cost.
- **Two protocols, chosen by `protocol`.**
  - `"systemone"` (the default): decision models in the System One
    format, such as Cloudflare Clef (`@cf/cloudflare/clef`) and TypeSafe
    Jev, called directly or through LiteLLM's `/v1/systemone`. One
    `choice` question whose criteria are `ml.llm.labels` (label to
    description); the sample is the `state`. The answer is the label with
    the highest probability in `answers.label.probabilities` and that
    probability as the confidence (Cloudflare's `{"result": ...}` wrapper
    is unwrapped). No free text, so `pattern` stays empty.
  - `"chat"`: `POST <endpoint>/chat/completions`, the OpenAI-compatible
    API that LiteLLM, OpenAI, vLLM, Ollama and others serve; Claude and
    other chat models through such a gateway. The model must answer JSON
    `{"label": <one of the labels>, "confidence": 0..1, "pattern":
    <text>}` (sent as `response_format` with a JSON schema). `pattern` is
    cut to 200 characters and only ever shown as text.
  - Either way, an answer that does not give one of the labels counts as
    `invalid`. No per-provider client beyond these two.
- **Minimal, redacted samples.** The prompt carries the trigger, method,
  host, path (the query's keys only, values replaced by `_`, cut to 512
  bytes), allowlisted headers (`user-agent`, `accept`,
  `accept-language`, `content-type`, `referer` by default), the client's
  `[ml]` features, the WAF rule IDs that matched and the JA4 if any. No
  client address, no cookies, no `authorization`, no body unless
  `body_bytes` is set (cut to that many bytes, at most 4096).
- **Training data.** With `ml.llm.export`, each labeled sample is
  appended as one JSON line with the `[ml]` feature names, `label` and
  `confidence`, ready for the XGBoost training snippet in the docs (map
  `benign` to 0, the rest to 1). The cheap inline model learns from the
  expensive one.
- Reverse mode only, inside the rate limiter. Not in the SDKs or the
  forward proxy. Per instance, like `POST /mode`.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/sample.rs` | Pure sampling decision: trigger match, per-trigger rate, per-client dedupe table (bounded, least recently seen evicted). No I/O |
| `crates/l7/src/llm.rs` | Builds the redacted sample from a request and the verdict context; hands it to a bounded channel, never waits |
| `crates/dvarapala/src/llm/` | The worker: the HTTP client (existing hyper and rustls), the prompt, the reply parser, the labels ring, the export writer, the switch and its timer |
| `crates/dvarapala/src/config/llm.rs` | `[ml.llm]` and its validation |
| `crates/dvarapala/src/admin/llm.rs` | `GET /llm`, `POST /llm` |
| `ui/src/pages/Llm.tsx` | Console page: switch with a duration, counts by label and trigger, recent labels |

Cargo feature `llm`, in the defaults if the `footprint` job shows the
release binary grows by less than 150 KiB (it reuses the upstream client
and `serde_json`), otherwise opt-in like `ml`.

### Configuration

`[ml.llm]`:

| Key | Default | |
|---|---|---|
| `endpoint` | unset | `systemone`: the full URL, for example `"http://litellm:4000/v1/systemone"` or Cloudflare's `.../ai/run/@cf/cloudflare/clef`. `chat`: the base URL, for example `"http://litellm:4000/v1"`. Unset turns the feature off and `POST /llm` answers `409` |
| `protocol` | `"systemone"` | `"systemone"` (Clef, Jev) or `"chat"` (OpenAI-compatible chat completions) |
| `model` | required with `endpoint` | Model name as the endpoint knows it, for example `"clef"`, `"clef-flash"`, `"jev"` |
| `api_key` | `""` | Bearer token; set it with `DVARAPALA__ML__LLM__API_KEY`. Redacted in `GET /config` |
| `enabled` | `false` | Sample from start, without the console switch |
| `labels` | the seven below | Table of label to description, 2 to 32 entries; the only labels the model may answer. The descriptions are the `choice` criteria (`systemone`) or listed in the prompt (`chat`). Defaults: `benign`, `scanner` (probing paths and known exploits), `scraper` (bulk reads of content), `credential_stuffing` (login attempts with many credentials), `flood` (volume without intent to use the site), `spam` (posting unsolicited content), `other` |
| `instructions` | `""` | Extra text for the question (`systemone`) or the system prompt (`chat`): what the site is, what is normal |
| `per_client` | `"10m"` | One sample per client and trigger in this time |
| `queue` | `256` | Samples waiting; a full queue drops new ones (`dropped`) |
| `concurrency` | `4` | Calls in flight |
| `timeout` | `"20s"` | Per call |
| `headers` | the five above | Request headers sent, by name |
| `body_bytes` | `0` | Body bytes sent, at most 4096; `0` sends none |
| `export` | unset | JSON lines file for training; stops (with a warning) at `export_max` |
| `export_max` | `"64MiB"` | |
| `max_duration` | `"24h"` | Longest `POST /llm` duration |

`[[ml.llm.triggers]]`, none by default (then nothing is sampled):

| Key | Default | |
|---|---|---|
| `on` | required | `"waf"`, `"challenge_failed"`, `"attack"`, `"ml_band"` or `"route"` |
| `rate` | `1.0` | Share of candidates sampled, in (0, 1] |
| `route` | | With `on = "route"`: a `[[routes]]` name |
| `band` | | With `on = "ml_band"`: `[low, high]` scores, needs `ml.model` |

`admin.mode_switch` also allows `POST /llm`; off, it answers `403`.

### Admin API

| Call | |
|---|---|
| `GET /llm` | `sampling` (bool), `until` (ms or null), counts by label and trigger, the last 200 labels (time, trigger, route, method, path, label, confidence, pattern) |
| `POST /llm?on=<duration>` | Samples until now plus the duration (at most `max_duration`); `POST /llm?off` stops. `403` without `mode_switch`, `409` without `endpoint` |

### Logs and metrics

| | |
|---|---|
| `msg="llm label"` | `label`, `confidence`, `pattern`, `trigger`, `route`, `method`, `path` per answer |
| `msg="llm sampling"` | `on` with `until` and `by` (the console subject), or `off` with the reason (`expired`, `console`, `reload`) |
| `dvarapala_llm_sampling` | 1 while sampling |
| `dvarapala_llm_samples_total{trigger,result}` | `sent`, `skipped_rate`, `deduped`, `dropped` (queue full) |
| `dvarapala_llm_calls_total{result}` | `ok`, `invalid`, `timeout`, `error`, `limited` (`429` from the provider) |
| `dvarapala_llm_labels_total{label,trigger}` | Answers by label |
| `dvarapala_llm_call_seconds` | Histogram of call time |
| `dvarapala_llm_tokens_total{kind}` | `prompt` and `completion`, from the reply's `usage` when present |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | Sampling off, a `waf` trigger | A WAF `would_block` | No call, `skipped` nothing counted as sent | unit (l7) |
| 2 | Sampling on, trigger `waf` rate 1 | A WAF `would_block` | One call; the request's verdict and latency are those of sampling off | integration |
| 3 | Trigger `waf` rate 0.25 | 4000 candidates from distinct clients | 1000 ± 100 sent | unit (engine) |
| 4 | `per_client = "10m"` | The same client triggers 50 times in a minute | One sample, 49 `deduped` | unit (engine) |
| 5 | A fake endpoint that never answers, `queue = 4`, `concurrency = 1` | 100 candidates | 5 in flight or queued, the rest `dropped`; requests still answered at normal speed | integration |
| 6 | A fake endpoint | A sample with `cookie`, `authorization`, a query `?token=abc` and a body | The prompt has none of the cookie, the token value or the body; the path reads `?token=_` | integration |
| 7 | `protocol = "chat"`, the endpoint answers `{"label":"scanner","confidence":0.8,"pattern":"..."}` | A sample | `llm label` logged, `labels_total{label="scanner"}` +1, in `GET /llm` | integration |
| 7b | `protocol = "systemone"`, the endpoint answers `answers.label.probabilities` `{"benign":0.1,"scanner":0.7,...}`, bare or wrapped in `{"result": ...}` | A sample | Label `scanner`, confidence 0.7; the request had one `choice` question with the labels as criteria | integration |
| 8 | The endpoint answers a label not in `labels`, plain text, probabilities that are all 0, or 10 KiB of JSON | A sample | `calls_total{result="invalid"}` +1, nothing labeled | unit (parser) + fuzz |
| 9 | `pattern` of 5000 characters with `<script>` | Shown in the console | Cut to 200 characters, rendered as text | unit (parser) + ui |
| 10 | The endpoint answers `429` | A sample | `calls_total{result="limited"}` +1, no retry | integration |
| 11 | `POST /llm?on=5m` | 5 minutes pass | Sampling off, `llm sampling off reason=expired` | unit (timer) |
| 12 | Sampling on from the console | `POST /reload` | Off unless `enabled = true` | integration |
| 13 | `mode_switch = false` | `POST /llm?on=5m` | `403` | integration |
| 14 | `export` set | 3 labeled samples | 3 JSON lines with the `[ml]` feature names, `label`, `confidence`; the XGBoost snippet loads them | integration |
| 15 | `api_key` from the environment | `GET /config` | The key is redacted | integration |
| 16 | Trigger `route` naming an unknown route, `ml_band` without `ml.model` | Start | An error naming the key | unit (config) |
| 17 | `[ml.llm]` in forward mode or with `rate_limit.enabled = false` | Start | A warning that it is ignored, like the other reverse-only sections | unit (config) |

A fuzz target `fuzz_llm_reply` feeds the reply parser.

## Alternatives

| Option | Why not |
|---|---|
| Inline verdicts from the model | 100 ms to seconds per request, a cost per request an attacker controls, and a prompt an attacker writes. The model may name a pattern; the fixed layers decide |
| Local budget accounting (tokens, money per day) | Prices differ per model and change; the provider or gateway already enforces budgets and rate limits per key. dvarapala only bounds its own memory |
| A client per provider (Anthropic, OpenAI, Cloudflare) | System One covers the decision models (Clef, Jev) and one OpenAI-compatible client covers chat models; LiteLLM fronts both |
| Chat only | Decision models such as Clef score fixed options in one call, cost a fraction of a chat model (Clef: input tokens only) and give no free text an attacker could steer |
| Always on from the file | Operators want it while investigating, not every day; the switch with an expiry keeps a forgotten setting from running for weeks. `enabled = true` stays for those who do |
| A sidecar like the WAF agent | Nothing to inspect inline, only an HTTP call off the path; a sidecar adds a deployment for no gain |
| Batching several samples per call | Fewer calls, but one bad sample can spoil a batch's answers and the reply parser gets harder. Revisit if call counts matter |

## Security and resource limits

- **Attacker input in the prompt.** The sample is the `state`
  (`systemone`) or data in the user message with the instructions in the
  system message (`chat`), but the model may still be steered. Its answer
  can only be one of `labels`, a confidence and, with `chat`, 200
  characters of text; it has no effect on any
  verdict, so the worst case is a wrong label in a log, a metric and the
  training file. The training file is for an operator to review.
- **Cost amplification.** An attacker who floods a trigger gets at most
  one sample per client per trigger per `per_client`, times `rate`,
  through a queue of `queue`; the provider's budget caps the money, and
  the switch expires. Sampling is off by default.
- **Memory.** Queue `queue` × sample size (at most about 8 KiB with
  `body_bytes = 4096`): 2 MiB at the defaults. The dedupe table is capped
  at `rate_limit.max_clients` entries. The labels ring holds 200 entries.
  A reply over 64 KiB is cut and counts as `invalid`.
- **Privacy.** No client address, cookies, credentials or bodies by
  default; header allowlist; query values redacted. Sending samples to a
  third-party model is still the operator's decision and subject to the
  provider's data terms; a local model through LiteLLM or Ollama keeps
  them in house.
- **Secrets.** The API key comes from the environment and is redacted in
  `GET /config` and the logs.
- **Console.** `pattern` is model output and shown as text only.

## Future work

Suggested config changes (a route, a fingerprint rule, a rate) from the
labels need their own RFC. The likely shape: deterministic rules over
label counts per path, JA4 and window (a label share over a threshold
suggests a change), with an LLM at most for the wording or patterns the
rules miss; never raw requests in a prompt. Every suggestion is a diff
the config validation checks, is run against logged traffic with
`dvarapala replay` (RFC 0016) to show what it would refuse and how much
of that is labeled `benign`, and applies only after an operator approves
it, with an audit log. Attackers write the traffic, so an unchecked
suggestion could be steered into blocking real users.

## Rollout

- **Rollout:** v0.16.0. Nothing changes without
  `ml.llm.endpoint` and at least one trigger; sampling stays off until
  the console switch or `enabled = true`.
- **Off switch:** `POST /llm?off`, a reload, or removing `endpoint`.

## Implementation notes

- The request body and the reply parser live in `dvarapala-l7`
  (`llm/wire.rs`, feature `llm`), not in the binary, so the fuzz target
  (`llm_reply`) can reach the parser. The binary's `llm` feature (in the
  default build) turns it on; the calls themselves stay in the binary.
- The sampler reaches the rate limiter through
  `RateLimitLayer::set_llm` after start, not through a `RateLimitConfig`
  field: the worker needs the runtime and the admin state.
- Only the WAF trigger sends the body (`body_bytes`): it is the only
  layer that buffers it.
- `[ml]` and `[ml.llm]` stay restart keys. A reload ends the console
  switch (unless `enabled`) and changes nothing else.
- Without `ml.model`, a features-only scorer computes the features for
  the samples and the export and never throttles (its score is `NaN`,
  kept out of `dvarapala_ml_score`).
- `GET /status` gains `llm` (`{"sampling": bool}` or `null`), so the
  console hides its LLM page when the feature is off.
- `GET /llm` answers `configured: false` without `endpoint` rather than
  `409`; `until` is in Unix ms. `POST /llm?on` without a duration samples
  for 30 minutes.
- The `llm` feature adds 113 KiB to the release binary (no new
  dependency), under the 150 KiB budget, so it is in the default build.
