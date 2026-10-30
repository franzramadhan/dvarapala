# 0021: Admin console: running config, WAF, mode switch, health pages

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-10-30 | #168 | |

> The console (RFC 0018) shows rates, top talkers and blocks, but not how
> the gateway is configured, what the WAF is doing, or the state of the
> layers around it (upstream pools, the shared store, routes, the forward
> proxy, XDP, TLS). Add a read-only view of the running config (secrets
> redacted), a WAF page with the rules that matched and the agent's rule
> files, a switch between `observe` and `enforce` for detection and the
> WAF that lasts until the next reload (off unless `admin.mode_switch`),
> and a health page per enabled feature, all drawn from the metrics the
> gateway already keeps.

## Problem

An operator in the console during an incident cannot answer basic
questions without a shell on the host or a Prometheus:

- **What is running?** The limits, the detection mode, the challenge,
  the routes and the WAF settings live in a TOML file plus
  `DVARAPALA__*` environment overrides plus defaults. The console shows
  none of them. After a reload, "applied" and "needs a restart" name
  keys, not values, so the operator cannot tell whether a new limit is
  in force.
- **What is the WAF doing?** RFC 0017 counts matches by rule ID in
  `dvarapala_waf_rule_matches_total{rule}` and logs `waf match` lines.
  Moving from `observe` to `enforce` is a judgement made from exactly
  that data ("which rules fired, on what, are they false positives"),
  and the console has none of it.
- **Which rules are enabled?** The rules live in the agent
  (`coraza-spoa`: the CRS, its paranoia level, the operator's exclusions
  and own rules). SPOP carries verdicts, not rule sets, so the gateway
  cannot ask the agent. Operators keep these in a file next to the
  gateway config (`coraza.yaml` in `examples/waf`) that the console never
  shows.
- **Changing mode** (`observe` to `enforce`, or back when a rule starts
  blocking real users) means editing the file and `POST /reload`. In a
  GitOps setup (Flux, the RFC 0019 operator) that is a commit, a review
  and a sync: minutes, while a bad rule blocks customers now.
- **Is it them or us?** Every layer already exports its state, but only
  to `/metrics`, which needs a Prometheus and a dashboard someone has to
  build. The console cannot show that two of three upstreams are ejected
  (RFC 0015), that the shared store is down and the cluster limit fell
  back to local counting (RFC 0010, a fail-open that is otherwise
  silent), which route takes the flood (RFC 0013), why detection says
  `attack` (RFC 0002), whether the challenge is being solved (RFC 0012),
  what XDP drops (RFC 0011), when the certificate expires (RFC 0003), or
  how many tunnels are open (RFC 0005). In forward mode (RFC 0007) the
  console is nearly empty: the reverse proxy's limiter is off there, and
  the egress queues and provider pauses are only in metrics.

## Proposal

### Config page

`GET /config` answers the running config as JSON: every section and key
with its effective value (file, environment and defaults merged, as the
gateway uses it), plus per key whether a reload applies it in place or
it needs a restart (the RFC 0014 split), and whether it differs from the
default. Secrets are replaced by `"<redacted>"` when set and `""` when
not: `admin.token`, `admin.oidc.client_secret`, `store.url` and
`challenge.secret`. The page shows the sections collapsed, the
non-default keys first, with a filter. After a reload the page
highlights what changed.

### WAF page

`GET /waf` answers:

- the `[waf]` settings (`enabled`, `mode`, `endpoint`, `app`, `timeout`,
  `on_error`, `max_body`, `body_limit_action`), the running mode and
  whether it was switched (below);
- the matched rules: rule ID, count since start, last seen time, and
  the last match's method, path (no query string) and anomaly score.
  The same 256 IDs as the metric, then `other`. The console groups them
  by CRS family from the ID (`920` protocol, `930` LFI, `932` RCE, `941`
  XSS, `942` SQLi and so on, unknown prefixes as "custom");
- the agent's rule files, when `waf.rules_files` names them: each path
  with its size, modification time and content, read when the call is
  made, for display only. The gateway never parses or applies them; the
  agent does. In Kubernetes the ConfigMap the agent mounts is mounted
  read-only into the gateway container too.

The verdict and error rates (`dvarapala_waf_requests_total`,
`dvarapala_waf_errors_total`) and the inspect latency come from
`GET /metrics` below.

### Mode switch

`POST /mode?layer=<detection|waf>&mode=<observe|enforce>` changes the
running mode of that layer in place, the way a reload of
`detection.mode` or `waf.mode` does today (buckets, baseline and the
agent connections kept). The switch:

- is refused with `403` unless `admin.mode_switch = true`, so the
  default keeps every change in the config file;
- is held in memory only and lasts until the next reload or restart. A
  reload applies the file and clears every switch, with a log line per
  cleared switch. The console shows a switched layer with a banner on
  every page ("WAF switched to observe by <actor> 12 min ago; the file
  says enforce; a reload reverts it") and offers "revert to file", which
  is a reload;
- applies to this instance only. With several replicas, or gateways
  managed by the RFC 0019 operator, each one is switched on its own; the
  console says so next to the switch;
- confirms with the target and the effect named ("WAF to observe: the
  agent's verdicts are logged and no longer block"), is audited as any
  state changing call (`msg="admin action" actor=... call=mode`), and
  needs the CSRF header with a cookie as RFC 0018 already requires.

Nothing else becomes editable. The file stays the source of truth; the
switch is a temporary lever, not a config editor.

### Health pages

`GET /metrics` on the admin listener answers the same Prometheus text as
the metrics listener, behind the same login. The gateway installs its
metrics recorder when `admin.listen` or `metrics.listen` is set (today
only the latter), so the console works without a metrics listener. The
console parses the text, keeps 15 minutes of history in the browser as
RFC 0018 does for `/status`, and shows a page or a card only for the
features whose series are present:

| Page | From | Shows |
|---|---|---|
| Upstreams (RFC 0015) | `dvarapala_upstream_*` | per backend: healthy or ejected, in flight, request results, ejections; retries and degraded answers; `upstream_errors_total` without a pool |
| Store (RFC 0010) | `dvarapala_store_*` | up or failing open (a red banner on every page while `store_up` is `0`), replicas, sync latency, sync errors, keys dropped |
| Routes (RFC 0013) | `dvarapala_route_*` | per route: requests by verdict, keys tracked |
| Detection (RFC 0002) | `dvarapala_detection_*`, `dvarapala_ml_score` | z-score and source entropy against the threshold, heavy hitters, state transitions, the ML score when on; the Overview card links here |
| Challenge and JA4 (RFC 0012, 0003) | `dvarapala_challenges_total`, `dvarapala_fingerprint_matches_total` | issued, passed, failed rates; matches per fingerprint rule |
| XDP (RFC 0011) | `dvarapala_xdp_*` | attached mode, packets by action and reason, block list size |
| TLS and QUIC (RFC 0003, 0006) | `dvarapala_tls_*`, `dvarapala_quic_*` | days to certificate expiry (warning under 14), handshake results, resumptions, open QUIC connections |
| Tunnels (RFC 0005, 0004) | `dvarapala_tunnels_*`, `dvarapala_grpc_local_responses_total` | open WebSocket and HTTP/2 tunnels, rejections, bytes; gRPC local answers by status |
| Egress (RFC 0007) | `dvarapala_egress_*` | per destination: queue, in flight, wait time, results, provider pauses. In forward mode this replaces Top talkers and Blocks in the navigation |
| Limiter (RFC 0001, 0014) | `dvarapala_limiter_*`, `dvarapala_blocks` | clients in the table, evictions, blocks |

Overview gains one line per enabled layer with its health (ok, degraded,
failing) linking to its page, and the WAF state next to detection.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/dvarapala/src/config/*.rs` | `Serialize` next to `Deserialize` on every section; durations and sizes written back in the form the file accepts; secret fields serialized through one `redact` helper |
| `crates/dvarapala/src/config/view.rs` | the config as JSON with the per key flags (`reload` or `restart`, `default`), from the same key lists `reload.rs` uses |
| `crates/dvarapala/src/reload.rs` | the key lists shared with `view.rs`; clears the switches on reload |
| `crates/l7/src/waf/rules.rs` | the matched rules table: bounded map of rule ID to count, last seen and last match, fed in `waf/layer.rs` where the metric is |
| `crates/dvarapala/src/admin/switch.rs` | the switches: layer, mode, actor, time; applied through the existing reload paths of the layers |
| `crates/dvarapala/src/metrics.rs` | the recorder installed for the admin listener too; the handle shared with it |
| `crates/l7/src/admin.rs` | parsing of `GET /config`, `GET /waf`, `POST /mode`, `GET /metrics` |
| `crates/dvarapala/src/admin/api.rs` | the answers |
| `ui/src/prom.ts` | Prometheus text parser (counters, gauges, histograms with labels) and the rate history |
| `ui/src/pages/*.tsx` | `Config`, `Waf`, `Upstreams`, `Store`, `Routes`, `Detection`, `Challenge`, `Xdp`, `Tls`, `Tunnels`, `Egress`; the switch on Overview and the WAF page |

### Configuration

| Key | Default | |
|---|---|---|
| `admin.mode_switch` | `false` | `true` allows `POST /mode`. Needs a restart, like every `[admin]` key |
| `waf.rules_files` | `[]` | paths of the agent's rule files to show on the WAF page; display only, read on each `GET /waf`, at most 8 files of 256 KiB each. Reloaded in place |

### Logs and metrics

| | |
|---|---|
| `msg="admin action" call=mode` | `actor`, `layer`, `mode`, the previous mode, the answer status |
| `msg="mode switch cleared"` | on reload: `layer`, the switched mode, the file's mode |
| `msg="waf rules file unreadable"` | `path`, `error`; the WAF page shows the error for that file |
| `dvarapala_mode_switched{layer}` | `1` while a switch is in force, else `0`, so an alert can catch a switch left on |
| `dvarapala_admin_requests_total{endpoint,status}` | existing; gains `config`, `waf`, `mode`, `metrics` |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a config with `admin.token`, `admin.oidc.client_secret`, `store.url` with a password and `challenge.secret` set | `GET /config` | each is `"<redacted>"`; none of the values appears anywhere in the body | integration (`dvarapala/tests`) |
| 2 | every config struct | serialize a config with every string field set to a marker | only the fields in the redaction list show the marker as `"<redacted>"`; a new secret field cannot be added without the test naming it | unit (`config::view`) |
| 3 | `rate_limit.rate = 50` in the file, `DVARAPALA__RATE_LIMIT__BURST=7` in the environment | `GET /config` | `rate = 50` and `burst = 7` marked non-default and `reload`; `listen` marked `restart` | integration (`dvarapala/tests`) |
| 4 | any valid config | serialize it to TOML and load that again | the same `Config` (round trip), secrets aside | unit (`config::view`) |
| 5 | a mock agent answering `deny` with rule IDs `942100` twice and `941100` once | `GET /waf` | `942100` count 2, `941100` count 1, last seen set, the path without its query | integration (`dvarapala/tests`) |
| 6 | 300 distinct rule IDs matched | read the table | 256 IDs and `other` with the rest; memory bounded | unit (`l7::waf::rules`) |
| 7 | `waf.rules_files` with one readable file, one missing, one over 256 KiB | `GET /waf` | the content of the first; an error for each of the others; `200` | integration (`dvarapala/tests`) |
| 8 | `admin.mode_switch = false` | `POST /mode?layer=waf&mode=observe` | `403`, the mode unchanged | integration (`dvarapala/tests`) |
| 9 | `mode_switch = true`, `waf.mode = "enforce"`, the agent answers `deny` | switch the WAF to `observe`, send a request | `200` from the upstream, `would_block` counted, `msg="admin action" call=mode actor=token` | integration (`dvarapala/tests`) |
| 10 | the switch of case 9 | `POST /reload` with the file unchanged | the WAF back to `enforce`, `msg="mode switch cleared"`, `dvarapala_mode_switched{layer="waf"} 0` | integration (`dvarapala/tests`) |
| 11 | `mode_switch = true`, `detection.mode = "observe"`, a flood over the attack threshold | switch detection to `enforce` | the flood throttled; the baseline and the client table kept | integration (`dvarapala/tests`) |
| 12 | a session cookie | `POST /mode` without the CSRF header | `403` | integration (`dvarapala/tests`) |
| 13 | bad queries: unknown `layer`, unknown `mode`, missing either, `layer=waf` with `[waf]` off | `POST /mode` | `400`, `400`, `400`, `409`; nothing changed | unit (`l7::admin`) and integration |
| 14 | arbitrary query strings | parse `POST /mode` | no panic | fuzz (`admin_query`, existing target, new seeds) |
| 15 | `admin.listen` set, `metrics.listen` empty, a pool of two upstreams with one down | `GET /metrics` with the token; without it | `200` with `dvarapala_upstream_healthy` `1` and `0`; `401` | integration (`dvarapala/tests`) |
| 16 | `metrics.listen` and `admin.listen` both set | scrape both | the same series from both | integration (`dvarapala/tests`) |
| 17 | Prometheus text with labels holding escaped quotes, `NaN`, `+Inf` buckets, comments, a counter reset | parse, compute rates | values and labels exact, a reset gives no negative rate | unit (`ui`, Vitest) |
| 18 | the console against a mocked API | open Config, filter a key; open WAF with matches and a switched mode; switch back | non-default keys first; rules grouped by CRS family; the banner names the actor and the file's mode; the confirmation names the effect | unit (`ui`, Vitest) |
| 19 | mocked metrics: a store down, an ejected upstream, a certificate 5 days from expiry, forward mode | render | the store banner on every page; the upstream red on Upstreams and degraded on Overview; the TLS warning; Egress in the navigation instead of Top talkers and Blocks | unit (`ui`, Vitest) |
| 20 | mocked metrics without `[xdp]`, `[store]` or a pool | render the navigation | no XDP, Store or Upstreams page | unit (`ui`, Vitest) |
| 21 | the built bundle | measure | still at most 120 KiB gzip (RFC 0018 budget) | CI (`ui`) |
| 22 | the console | an axe scan of every new page in both themes | no violation | CI (`ui`) |

## Alternatives

| Option | Why not |
|---|---|
| Edit any key from the console and write the file back | the file is often read-only (a ConfigMap, the operator's CRD, a package-managed path), and a second writer fights GitOps. A full editor also needs validation UX for every key. The switch covers the one change that is urgent; everything else waits for the file |
| Persist the switch (a state file, or the shared store) across reloads and restarts | then the file is no longer the truth and nothing says when the switch ends. Clearing on reload makes "revert" one action and keeps GitOps converging |
| Switch every replica at once through the shared store (RFC 0010) | the store holds counters, not control state; a cluster-wide switch is a new protocol with its own failure modes. Per instance, plus the operator editing the policy, covers it for now |
| Ask the agent for its loaded rules | SPOP has no such message, and `coraza-spoa` exposes none. Showing the files the agent reads is what an operator would `cat` anyway |
| Parse the CRS and the exclusions to show "enabled rules" per ID | re-implements SecLang in the gateway and is wrong the moment the agent's version differs. The matched rules are the ones that matter for tuning |
| Show the raw config file instead of the effective config | misses environment overrides and defaults, which is where surprises hide (a secret or a limit set by `DVARAPALA__*`) |
| A JSON endpoint per layer (`GET /upstreams`, `GET /store`, ...) | a dozen endpoints and JSON shapes to keep in step with the metrics they duplicate. The metrics are already the stable, documented surface (`CONFIG.md`); one call serves them all and a new metric shows up with no Rust change |
| Point the console at the metrics listener | it is a separate port without authentication, usually bound to loopback or a scrape network the browser cannot reach, and CORS would have to open it |
| Keep metrics history in the gateway | new state and memory in the binary; the browser keeps 15 minutes, Prometheus keeps the rest (as RFC 0018 decided) |
| Allow the switch for `[challenge] mode` and route rules too | out of scope; detection and WAF are the two layers with an `observe` mode built for this decision. Others can follow in their own RFC |
| A console page for replay (RFC 0016) or the operator (RFC 0019) | replay is an offline run over log files; the operator acts on the cluster, where `kubectl` and the policy CRD are the interface |

## Security and resource limits

- `GET /config` and `GET /metrics` expose the running config and every
  series to anyone logged in: upstream addresses, egress destinations,
  routes, trusted proxies. That is the same people who can reload and
  block today, but it is new information, so both need a login and none
  of it is shown before one. Secrets are redacted by an explicit list,
  and case 2 fails when a new secret-like field is added without being
  listed. Redaction happens in serialization, so no code path builds a
  JSON with the secret in it. Metrics carry no secrets today (labels are
  route names, upstream addresses, destinations, rule IDs).
- `waf.rules_files` reads files named in the config, never in the
  request: no path comes from the client. Bounded to 8 files of
  256 KiB, read per call; the page polls it every 30 s and the admin
  listener's 16 connection cap bounds the rest. Rule files can hold
  internal paths and hostnames, so they are shown only after login.
- The switch weakens protection when it goes to `observe`. It is off by
  default, audited with the actor, visible on every console page while
  in force, exported as a metric for alerting, and undone by any reload.
  A stolen session can already reload and block; with `mode_switch` on
  it can also turn the WAF to `observe` until the next reload.
- `GET /metrics` renders the registry per call. Its size is bounded by
  the existing label caps (256 WAF rules, the routes, the pool members,
  the egress destinations), tens of KiB at most. The console polls it
  every 5 s, and only while a health page or Overview is visible.
  Installing the recorder with the admin listener on and the metrics
  listener off costs the registry's memory, which every deployment with
  metrics already pays.
- Memory: the matched rules table is at most 257 entries of about
  200 bytes (ID, count, time, method, path capped at 256 bytes, score).
  The switches are two entries. The config JSON is built per call from
  the running config, a few KiB.
- No new Rust dependency (`serde`, `toml` and the Prometheus exporter
  are in the lock file). The Prometheus text parser in the UI is
  hand-written, no npm package.

## Rollout

- **Rollout:** a minor release. New calls and pages appear for consoles
  that are on; `GET /config`, `GET /waf` and `GET /metrics` need no new
  key. The switch needs `admin.mode_switch = true`. `examples/waf`
  mounts the agent's `coraza.yaml` into the gateway and sets
  `waf.rules_files`.
- **Off switch:** `admin.mode_switch = false` (the default) removes the
  switch; `waf.rules_files = []` shows no files; the pages go with
  `admin.ui_enabled = false`, and the JSON calls with
  `admin.listen = ""`.
