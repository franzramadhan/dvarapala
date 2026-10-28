# Configuration reference

`dvarapala serve --config <file>` reads a TOML file. Every key can also be
set, or overridden, by an environment variable: `DVARAPALA__` followed by
the key path with `__` between parts, for example
`DVARAPALA__RATE_LIMIT__RATE=5` for `rate_limit.rate`. Unknown keys are an
error. The log level comes from `RUST_LOG` (default `info`).

A commented example is in [examples/dvarapala.toml](examples/dvarapala.toml).

Durations are strings: `"<n>ms"` or `"<n>s"`, for example `"500ms"` or
`"10s"`.

## Top level

Top-level keys go above the first `[section]` in the file.

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | address | `"0.0.0.0:8080"` | Proxy listen address |
| `upstream` | URL | required | Upstream base URL, `http://` or `https://` |
| `trusted_proxies` | list of CIDRs | `[]` | Peers allowed to set `X-Forwarded-For`; others are keyed by their own address |

## `[metrics]`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | address | `"127.0.0.1:9090"` | Prometheus endpoint; empty turns it off |

## `[rate_limit]`

Token bucket per client ([RFC 0001](rfc/0001-foundation.md)).

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Turn the limiter off |
| `rate` | integer | `20` | Tokens refilled per second per client |
| `burst` | integer | `40` | Bucket size |
| `max_clients` | integer | `100000` | Table capacity before the least recently seen client is evicted; at least 1 |

## `[detection]`

Adaptive detection ([RFC 0002](rfc/0002-adaptive-detection.md)). Starts in
`observe` mode: logs and metrics only.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Turn detection off entirely |
| `mode` | `"observe"` or `"enforce"` | `"observe"` | `observe` logs only, `enforce` changes verdicts |
| `window` | duration | `"1s"` | Window length |
| `prefix_v4` | integer | `32` | IPv4 prefix length for aggregation; shorten (for example `24`) to group subnets |
| `prefix_v6` | integer | `64` | IPv6 prefix length for aggregation; shorten (for example `48`) to group sites |
| `sketch_width` | integer | `2048` | Count-min columns |
| `sketch_depth` | integer | `4` | Count-min rows (hash functions) |
| `top_k` | integer | `64` | Heavy hitters tracked |
| `ewma_alpha` | float | `0.05` | Baseline learning rate per window |
| `warmup_windows` | integer | `300` | Windows before the baseline can alarm |
| `z_threshold` | float | `4.0` | Rate z-score that marks a window anomalous |
| `entropy_buckets` | integer | `1024` | Hashed buckets for source entropy |
| `entropy_drop` | float | `0.5` | Relative entropy drop that marks a window anomalous |
| `trigger_windows` | integer | `3` | Anomalous windows in a row to enter `Attack` |
| `cooldown_windows` | integer | `30` | Normal windows to leave `Cooldown` |
| `attack_rate_factor` | float | `0.25` | Bucket rate multiplier while in `Attack` |

## `[ml]`

Optional tree model scoring, in builds with the `ml` feature (off by
default).

| Key | Type | Default | Description |
|---|---|---|---|
| `model` | path | unset | XGBoost JSON model; unset turns scoring off |
| `threshold` | float | `0.9` | Score above which `Allow` becomes `Throttle` |

## `[tls]`

HTTPS on the listener ([RFC 0003](rfc/0003-tls.md)), in builds with the
`tls` feature (on by default). Set `cert` and `key` together to turn TLS
on; one without the other is an error. `SIGHUP` reloads the pair; a bad
file keeps the old one. ALPN offers `h2` and `http/1.1`.

| Key | Type | Default | Description |
|---|---|---|---|
| `cert` | path | unset | PEM certificate chain |
| `key` | path | unset | PEM private key |
| `handshake_timeout` | duration | `"10s"` | Handshakes slower than this are dropped |
| `max_handshakes` | integer | `1024` | Handshakes in progress at once; new connections over it are closed. At least 1 |

## `[upstream_tls]`

Verification of `https://` upstreams. There is no switch to turn
verification off.

| Key | Type | Default | Description |
|---|---|---|---|
| `ca_file` | path | system roots | PEM CA bundle to trust instead of the system roots |
| `server_name` | string | upstream host | Name to send in SNI and verify the certificate against |

## Metrics

Served on `metrics.listen` at `/metrics`.

| Metric | Description |
|---|---|
| `dvarapala_requests_total{verdict}` | Requests by verdict |
| `dvarapala_limiter_clients` | Clients in the limiter table |
| `dvarapala_limiter_evictions_total` | Evictions; a steady rise means `max_clients` is too small or a spoofed flood |
| `dvarapala_upstream_errors_total` | Upstream connect or response failures |
| `dvarapala_detection_state` | 0 `Normal`, 1 `Suspect`, 2 `Attack`, 3 `Cooldown` |
| `dvarapala_detection_rate_zscore` | Current window z-score |
| `dvarapala_detection_source_entropy` | Current window entropy, normalized to `[0, 1]` |
| `dvarapala_detection_heavy_hitters` | Prefixes in the top-k above the per-client limit |
| `dvarapala_detection_transitions_total{from,to}` | State changes |
| `dvarapala_ml_score` | Histogram of model scores (feature `ml`) |
| `dvarapala_tls_handshakes_total{result}` | Handshakes by `ok`, `failed`, `timeout`, `rejected` |
| `dvarapala_tls_handshakes_in_progress` | Handshakes running now |
| `dvarapala_tls_resumed_total` | Resumed sessions |
| `dvarapala_tls_cert_expiry_timestamp_seconds` | `notAfter` of the served certificate, Unix seconds |
