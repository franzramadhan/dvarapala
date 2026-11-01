# Configuration reference

`dvarapala serve --config <file>` reads a TOML file. Every key can also be
set, or overridden, by an environment variable: `DVARAPALA__` followed by
the key path with `__` between parts, for example
`DVARAPALA__RATE_LIMIT__RATE=5` for `rate_limit.rate`. Unknown keys are an
error. The log level comes from `RUST_LOG` (default `info`).

Lists and arrays of tables take an inline TOML value, which replaces the
whole list from the file:

```sh
DVARAPALA__TRUSTED_PROXIES='["192.0.2.0/24", "198.51.100.1/32"]'
DVARAPALA__ROUTES='[{name = "api", path = "/api", rate = 5, burst = 10}]'
```

### Build features and published artifacts

Some sections need a cargo feature. A key of a section whose feature is
not in the binary is an error at start that names the feature (for
example `ml.model <path> needs a build with the ml feature`), not a key
that is silently ignored.

| Feature | Sections | Release tarballs, Homebrew, `install.sh` | Container image | Build from source |
|---|---|---|---|---|
| `tls`, `ui`, `waf`, `replay`, `llm` (default) | `[tls]`, `[upstream_tls]`, the console (`admin.ui_enabled`), `[waf]`, `dvarapala replay`, `[ml.llm]` | yes | yes | default |
| `redis` | `store.backend = "redis"` | no | yes | `--features redis` |
| `postgres` | `store.backend = "postgres"` | no | yes | `--features postgres` |
| `http3` | `[quic]` | no | yes | `--features http3` |
| `ml` | `[ml]` | no | yes | `--features ml` |
| `xdp` | `[xdp]` (Linux) | no | yes | `--features xdp` |

The operator's gateways (RFC 0019) run the container image. With
`gateway.admin` and `gateway.waf` in the policy (RFC 0025) the operator
sets `admin.listen` and `waf.endpoint` itself; the policy's `[admin]` and
`[waf]` hold the other keys.

A commented example is in [examples/dvarapala.toml](examples/dvarapala.toml).

The SDKs ([RFC 0008](rfc/0008-sdk.md), [sdk/](sdk/README.md)) take the same
names and defaults for the keys that apply in process: `rate_limit.rate`,
`rate_limit.burst`, `rate_limit.max_clients`, `detection.*`,
`trusted_proxies`, the connection keys of `[l4]` (not its timeouts) and,
since [RFC 0028](rfc/0028-sdk-parity.md), `routes` and
`forward.destinations` (each a JSON array with the field names below;
route `key = "ja4"`, `challenge` and `waf` and destination
`max_concurrent` are refused), `admin.max_blocks` and
`admin.max_block_ttl`. The exact list is on the
[SDK page](site/docs/sdk.md#keys).

A reload (`SIGHUP`, `POST /reload`) applies only some keys in place; the
rest need a restart. The list is under [Reload](#reload), and the console's
configuration page (`GET /config`) marks each key.

Durations are strings: `"<n>ms"`, `"<n>s"`, `"<n>m"` or `"<n>h"`, for
example `"500ms"`, `"10s"` or `"24h"`.

## Top level

Top-level keys go above the first `[section]` in the file.

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | `"reverse"` or `"forward"` | `"reverse"` | `"forward"` runs an egress forward proxy ([RFC 0007](rfc/0007-forward-proxy.md)), see [`[forward]`](#forward) |
| `listen` | address | `"0.0.0.0:8080"` | Proxy listen address |
| `upstream` | URL | required in reverse mode without `pool.upstreams` | Upstream base URL, `http://` or `https://`; ignored in forward mode. Not together with `pool.upstreams` |
| `upstream_protocol` | `"http1"`, `"http2"` or `"auto"` | `"http1"` | Protocol to the upstream ([RFC 0004](rfc/0004-http2-grpc.md)): `http2` is h2c with prior knowledge for `http://` and ALPN `h2` for `https://` (an upstream that cannot speak it gets 502); `auto` lets ALPN choose for `https://` and keeps HTTP/1.1 for `http://` |
| `trusted_proxies` | list of CIDRs | `[]` | Peers allowed to set `X-Forwarded-For`; others are keyed by their own address |
| `config_watch` | duration | unset | Reread `--config` at this interval (at least `100ms`) and reload when its bytes change, as `SIGHUP` does ([RFC 0019](rfc/0019-operator.md)); for a file Kubernetes mounts from a ConfigMap. Needs `--config`; restart-only |

## `[metrics]`

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | address | `"127.0.0.1:9090"` | Prometheus endpoint; empty turns it off. The admin listener serves the same text at `GET /metrics` behind its login ([RFC 0021](rfc/0021-admin-ui-config-waf.md)), with or without this one |

## `[rate_limit]`

Token bucket per client ([RFC 0001](rfc/0001-foundation.md)).

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Turn the limiter off. In reverse mode this also turns off everything that runs inside it: `[detection]`, `[ml]`, the `[store]` sync, `[challenge]`, `[fingerprint]` and `[[routes]]` (a warning at start names them) |
| `rate` | integer | `20` | Tokens refilled per second per client. At least 1: a rate below one request per second is not possible here (forward destinations take fractions) |
| `burst` | integer | `40` | Bucket size. At least 1 |
| `max_clients` | integer | `100000` | Table capacity before the least recently seen client is evicted; at least 1 |

## `[detection]`

Adaptive detection ([RFC 0002](rfc/0002-adaptive-detection.md)). Starts in
`observe` mode: logs and metrics only.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Turn detection off entirely |
| `mode` | `"observe"` or `"enforce"` | `"observe"` | `observe` logs only, `enforce` changes verdicts |
| `window` | duration | `"1s"` | Window length. Above 0 |
| `prefix_v4` | integer | `32` | IPv4 prefix length for aggregation; shorten (for example `24`) to group subnets. At most 32 |
| `prefix_v6` | integer | `64` | IPv6 prefix length for aggregation; shorten (for example `48`) to group sites. At most 64: client keys keep only the /64 |
| `sketch_width` | integer | `2048` | Count-min columns. At least 1 |
| `sketch_depth` | integer | `4` | Count-min rows (hash functions). At least 1 |
| `top_k` | integer | `64` | Heavy hitters tracked. At least 1 |
| `ewma_alpha` | float | `0.05` | Baseline learning rate per window, in (0, 1] |
| `warmup_windows` | integer | `300` | Windows before the baseline can alarm |
| `z_threshold` | float | `4.0` | Rate z-score that marks a window anomalous. Above 0 |
| `entropy_buckets` | integer | `1024` | Hashed buckets for source entropy. At least 2 |
| `entropy_drop` | float | `0.5` | Relative entropy drop that marks a window anomalous, in (0, 1] |
| `trigger_windows` | integer | `3` | Anomalous windows in a row to enter `Attack`. At least 1 |
| `cooldown_windows` | integer | `30` | Normal windows to leave `Cooldown`. At least 1 |
| `attack_rate_factor` | float | `0.25` | Bucket rate multiplier while in `Attack` |

## `[ml]`

Optional per-client scoring with your own XGBoost model
([RFC 0002](rfc/0002-adaptive-detection.md)), in builds with the `ml`
feature: the container image (and so the operator's gateways) has it
since v0.19.1; the release tarballs do not, so build those from source
with `--features ml`. Reverse mode only, inside the rate limiter. Not in
the SDKs. How to train a model: [Protection layers](site/docs/protection.md#scoring-model).

Every request the other layers allow is scored; a score above `threshold`
answers `429` with `Retry-After` of one detection window. There is no
observe mode: to watch scores first, set `threshold = 1.0` (a score is
never above 1) and read `dvarapala_ml_score`.

| Key | Type | Default | Description |
|---|---|---|---|
| `model` | path | unset | XGBoost JSON model (`binary:logistic`, `gbtree`, named features); unset turns scoring off. Read once at start: a bad model is an error naming the problem. Restart |
| `threshold` | float | `0.9` | Score above which `Allow` becomes `Throttle`. Restart |

### `[ml.llm]`

LLM labels for sampled traffic ([RFC 0023](rfc/0023-llm-labels.md)), in
the default build (the `llm` feature), off by default. Requests a trigger
picks are sent, redacted, to an LLM endpoint off the request path; the
answer is one label from `labels`, a confidence and a short pattern. A
label never changes a verdict: it goes to the logs, the metrics,
`GET /llm`, the console and the `export` file. Reverse mode with the rate
limiter on only (otherwise a warning at start and nothing is sampled).
`[ml]` does not need the `ml` feature for this: without `ml.model` the
features are still computed for the samples, and nothing is scored.

Sampling runs while `enabled` or while the console switch is on
(`POST /llm`, which needs `admin.mode_switch`). A reload or a restart
ends the switch. Never sent: `Cookie`, `Authorization`,
`Proxy-Authorization`, query values (keys only, as `key=_`), and the body
unless `body_bytes` is set (WAF trigger only). Header values and the path
are cut to 512 bytes. All `[ml.llm]` keys need a restart.

| Key | Type | Default | Description |
|---|---|---|---|
| `endpoint` | string | unset | `systemone`: the full URL, for example `"http://<host>:4000/v1/systemone"`. `chat`: the base URL, for example `"http://<host>:4000/v1"` (`/chat/completions` is appended). Unset turns the feature off and `POST /llm` answers `409` |
| `protocol` | string | `"systemone"` | `"systemone"` (System One models such as Clef) or `"chat"` (OpenAI-compatible chat completions with a JSON schema answer) |
| `model` | string | `""` | Model name as the endpoint knows it; required with `endpoint` |
| `api_key` | string | `""` | Bearer token; set it with `DVARAPALA__ML__LLM__API_KEY`. Redacted in `GET /config` |
| `enabled` | bool | `false` | Samples from start, without the console switch; a reload keeps it |
| `labels` | table | seven labels | Label to description, 2 to 32 entries; the only answers taken. Defaults: `benign`, `scanner`, `scraper`, `credential_stuffing`, `flood`, `spam`, `other` |
| `instructions` | string | `""` | Extra text for the question (`systemone`) or the system prompt (`chat`): what the site is, what is normal |
| `per_client` | duration | `"10m"` | One sample per client and trigger in this time |
| `queue` | integer | `256` | Samples waiting for a call; a full queue drops new ones (`dropped`) |
| `concurrency` | integer | `4` | Calls in flight |
| `timeout` | duration | `"20s"` | Per call, no retry |
| `headers` | list | `user-agent`, `accept`, `accept-language`, `content-type`, `referer` | Request headers sent, by name |
| `body_bytes` | integer | `0` | Body bytes sent with a WAF sample, at most 4096; `0` sends none |
| `export` | path | unset | JSON lines file for training: the 10 feature columns of [`[ml]`](#ml) plus `label`, `confidence`, `trigger`, `at` (Unix ms) |
| `export_max` | size | `"64MiB"` | The export stops, with a warning, at this size |
| `max_duration` | duration | `"24h"` | Longest `POST /llm?on=` duration |
| `persist` | bool | `false` | Write each label as a row of `dvarapala.llm_labels` in the PostgreSQL store ([RFC 0024](rfc/0024-llm-label-store.md)): `GET /llm` then covers every replica of `store.cluster`, and `GET /llm/export` streams the rows. Needs `store.backend = "postgres"` (an error otherwise) and a build with the `postgres` feature (the container image has it). Writes fail open: `llm store unavailable` is logged once and labels stay in memory. Rows keep the redacted path, which can hold personal data for `retention`. Restart |
| `persist_queue` | integer | `1024` | Rows waiting for the writer, 1 to 65536; a full queue drops new rows. Batches of up to 100 rows, at most 5 s apart. Restart |
| `retention` | duration | `"30d"` | Stored rows older than this are deleted, at most 10 000 per hourly sweep, one replica at a time. `"<n>d"` days or a duration, at least `1h`. Reload |

`[[ml.llm.triggers]]`, none by default (then nothing is sampled):

| Key | Type | Default | Description |
|---|---|---|---|
| `on` | string | required | `"waf"` (a WAF match), `"challenge_failed"`, `"attack"` (detection in `Attack`), `"ml_band"` or `"route"` |
| `rate` | float | `1.0` | Share of candidates sampled, in (0, 1] |
| `route` | string | | With `on = "route"`: a `[[routes]]` name |
| `band` | `[float, float]` | | With `on = "ml_band"`: `[low, high]` scores; needs `ml.model` |

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

## `[quic]`

HTTP/3 over QUIC ([RFC 0006](rfc/0006-http3.md)), experimental, in builds
with the `http3` feature (no published binary or image has it: build
from source). Set `listen` to open a UDP
socket next to the TCP listener, reverse mode only. It needs `[tls]`: the
same certificate (reloaded by `SIGHUP` too), TLS 1.3 only, ALPN `h3`, no
0-RTT. The handshake timeout is `tls.handshake_timeout`. HTTP/3 requests go
through the same rate limiter, detection and upstream as TCP ones.

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | `ip:port` | unset | UDP address for HTTP/3; unset turns QUIC off. Usually the TCP port, over UDP |
| `advertise` | bool | `true` | `Alt-Svc: h3=":<port>"; ma=86400` on TCP responses, so clients find HTTP/3 |
| `retry` | `"under_load"`, `"always"` or `"never"` | `"under_load"` | When a new client must prove its address with a Retry first (one more round trip). `never` is for labs: spoofed Initials then cost handshakes |
| `retry_threshold` | integer | `256` | Handshakes in progress before `under_load` starts sending Retry |
| `max_connections` | integer | `10000` | Open connections, handshakes included; over it, new ones are refused before any crypto. At least 1 |
| `max_streams` | integer | `100` | Concurrent requests per connection; more wait for credit. At least 1 |
| `idle_timeout` | duration | `"30s"` | Idle connections are closed. Above 0 |

## `[upstream_tls]`

Verification of `https://` upstreams. There is no switch to turn
verification off.

| Key | Type | Default | Description |
|---|---|---|---|
| `ca_file` | path | system roots | PEM CA bundle to trust instead of the system roots |
| `server_name` | string | upstream host | Name to send in SNI and verify the certificate against |

## `[http2]`

HTTP/2 listener limits ([RFC 0004](rfc/0004-http2-grpc.md)), applied to
every HTTP/2 client connection, cleartext (h2c) or TLS.

| Key | Type | Default | Description |
|---|---|---|---|
| `max_concurrent_streams` | integer | `100` | Streams open at once per connection; more are refused with `REFUSED_STREAM`. At least 1 |
| `max_pending_reset_streams` | integer | `20` | Streams the client resets before they are served; over it, `GOAWAY` (rapid reset) |
| `max_local_error_resets` | integer | `1024` | Streams the server resets for client errors before it closes the connection |
| `max_header_list_size` | integer | `16384` | Bytes of headers per request, CONTINUATION frames included |
| `keepalive_interval` | duration | `"30s"` | PING interval; `"0s"` turns keepalive off |
| `keepalive_timeout` | duration | `"10s"` | Close the connection when a PING is not answered in time |

## `[upgrade]`

WebSocket and other HTTP/1.1 upgrades ([RFC 0005](rfc/0005-websocket.md)).
The upgrade request goes through the rate limit, detection and model score
like any request. On an upstream `101` the proxy copies bytes both ways
until either side closes; it never parses WebSocket frames. Upgrades need
HTTP/1.1 on both sides: with `upstream_protocol = "http2"` they are
stripped, and WebSocket over HTTP/2 or HTTP/3 is not supported.

| Key | Type | Default | Description |
|---|---|---|---|
| `protocols` | list of strings | `["websocket"]` | `Upgrade` tokens passed to the upstream, case-insensitive; others are stripped. `[]` turns upgrades off |
| `max_tunnels` | integer | `10000` | Open tunnels at once; over it, the upgrade gets `503` before it reaches the upstream. At least 1 |
| `idle_timeout` | duration | `"300s"` | Close a tunnel with no bytes in either direction for this long. Above 0 |
| `max_lifetime` | duration | `"24h"` | Close any tunnel after this long, so clients reconnect through the current limits; `"0s"` turns it off |

An idle tunnel costs about 19 KB in the proxy (two 8 KB copy buffers plus
connection state), so the default `max_tunnels` bounds tunnels to about
200 MB. Shutdown closes open tunnels and waits for them within the 30 s
drain.

## `[forward]`

Forward proxy mode (`mode = "forward"`, [RFC 0007](rfc/0007-forward-proxy.md)):
egress rate compliance for calls to third-party APIs. Clients set
`HTTP_PROXY` (or their HTTP client's proxy) to `listen`. Only listed
destinations are reachable, each shaped to its own rate shared by every
client: a request waits for its slot, or gets a local `429` with
`Retry-After` when the slot is more than `max_wait` away. The proxy never
sends above the rate. When a destination answers `429` or `503` with
`Retry-After` (seconds), it pauses for that long, capped by `max_pause`.

`[rate_limit]`, `[detection]` and `[ml]` do not apply in forward mode: the
callers are your own services. `[challenge]`, `[fingerprint]` and
`[[routes]]` do not apply either (a warning at start names them), and
`[pool]` is ignored: destinations come from `[[forward.destinations]]`. `[upstream_tls]` verifies `https://`
destinations, `[upgrade]` limits `CONNECT` tunnels (`max_tunnels`,
`idle_timeout`, `max_lifetime`), `[tls]` and `[http2]` apply to the
listener as in reverse mode.

| Key | Type | Default | Description |
|---|---|---|---|
| `clients` | list of CIDRs | `["127.0.0.0/8", "::1/128"]` | Peers allowed to use the proxy; others get `403` |
| `connect` | bool | `true` | Allow `CONNECT` to listed destinations; `false` accepts absolute-form requests only |

Each `[[forward.destinations]]` (at least one):

| Key | Type | Default | Description |
|---|---|---|---|
| `origin` | URL | required | `https://host[:port]` or `http://host[:port]`, no path. Matched on scheme, host and port; `CONNECT` matches host and port |
| `name` | string | the host | Label in logs and metrics |
| `rate` | number | required | Requests (or new `CONNECT` tunnels) per second, at least 0.001 |
| `burst` | integer | `1` | Requests that may go at once after an idle period; at least 1 |
| `max_concurrent` | integer | `0` (off) | Requests or tunnels in flight at once; a request waits for a place within `max_wait`, then gets `429` with `Retry-After: 1` |
| `max_queue` | integer | `100` | Requests waiting at once; `0` refuses instead of waiting |
| `max_wait` | duration | `"2s"` | Longest wait for a slot or a place |
| `max_pause` | duration | `"60s"` | Cap on a destination's `Retry-After`; `"0s"` ignores it |

Two ways in. An absolute-form request (`GET https://host/path` sent to the
proxy as plain HTTP) is sent by the proxy itself, opening TLS for
`https://` destinations, so every request is shaped; keep that hop on a
trusted network. Most clients send `https://` URLs through a proxy as
`CONNECT` instead: the tunnel keeps TLS end to end and takes one slot per
tunnel, not per request. Hop-by-hop headers (`Proxy-Authorization`
included) are removed and no `X-Forwarded-For` is added. A waiting request costs about 5.5 KB.

## `[l4]`

Connection limits and timeouts ([RFC 0009](rfc/0009-l4-limits.md)), checked
on every accepted connection before TLS or HTTP: total cap, then the
per-client cap and accept bucket, then the TLS handshake, then HTTP. A
refused connection is closed at once, with no response and nothing read.
A client is the peer address grouped by `prefix_v4` / `prefix_v6`;
`X-Forwarded-For` does not apply, so put a load balancer in front in
`exempt` (or turn the limits off). Applies in reverse and forward mode,
cleartext and TLS. WebSocket and `CONNECT` tunnels count as connections
until they close.

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | `false` keeps only the timeouts |
| `max_connections` | integer | `0` (off) | Open connections in total |
| `max_per_client` | integer | `256` | Open connections per client; `0` off |
| `accept_rate` | integer | `0` (off) | New connections per second per client |
| `accept_burst` | integer | `64` | Bucket size for `accept_rate`; at least 1 |
| `prefix_v4` | integer | `32` | Group IPv4 clients by this prefix, 1 to 32 |
| `prefix_v6` | integer | `64` | Group IPv6 clients by this prefix, 1 to 128 |
| `max_clients` | integer | `100000` | Per-client table capacity, least recently seen evicted (an evicted client's count starts again). At least 1 |
| `exempt` | list of CIDRs | `[]` | Peers never limited (load balancers, health checks) |
| `header_timeout` | duration | `"30s"` | Time to receive each request head on a connection, the first and every keep-alive one. Above 0 |
| `idle_timeout` | duration | `"60s"` | Close a connection with no bytes either way and no request in flight for this long; `"0s"` off. A request is in flight until its response body ends |
| `min_body_rate` | integer | `0` (off) | Bytes per second a request body must keep up, measured over 10 s windows; slower bodies are cut with `408` |

Between requests on a keep-alive HTTP/1.1 connection, `header_timeout`
also bounds the wait for the next head, so the lower of the two timeouts
closes an idle connection. The per-client table costs about 106 bytes per
client, so the default `max_clients` holds about 11 MB.

## `[store]`

Shared state across replicas ([RFC 0010](rfc/0010-shared-state.md)), so N
replicas behind a load balancer act as one gateway. Each backend is in
builds with its cargo feature (`redis`, `postgres`): the container image
has both, the release tarballs (and so Homebrew and `install.sh`) have
neither (see [Build features](#build-features-and-published-artifacts)).
Nothing on the request path waits for the store: each replica keeps its
local limits and syncs in the background every `sync_interval`.

- Per-client limit: each replica adds the requests it allowed per client
  to a cluster count for the window (10 sync intervals). A client over
  `rate x window + burst` in the cluster is throttled on every replica
  until the window ends. Overshoot is at most `replicas x rate x 2 x
  (sync_interval + timeout)` per window: a count reaches the other
  replicas within two sync periods.
- Forward mode: each destination's `rate`, `burst` and `max_concurrent`
  are divided by the live replica count, and a provider `Retry-After`
  seen by one replica pauses the destination on all.
- Detection: heavy hitters found in `enforce` mode are dropped on every
  replica for `cooldown_windows` windows.
- Lost store: fail open to local limits, logged once as `store
  unavailable` and `store recovered`; reconnects back off up to
  `sync_interval x 10`. Forward mode keeps the last replica count, so
  egress stays under the agreement.

| Key | Type | Default | Description |
|---|---|---|---|
| `backend` | `"memory"`, `"redis"` or `"postgres"` | `"memory"` | `"memory"` shares nothing: no task, no socket |
| `url` | string | unset | Required with a shared backend: `redis://<host>:6379/0` (`rediss://` for TLS) or `postgres://<user>@<host>:5432/<db>?sslmode=verify-full`. Put the password in `DVARAPALA__STORE__URL`; it is never logged |
| `cluster` | string | `"dvarapala"` | Key prefix (Redis) or `cluster` column (PostgreSQL); replicas with the same store and name share state |
| `sync_interval` | duration | `"1s"` | How often each replica syncs. Above 0 |
| `max_keys` | integer | `10000` | Clients synced per interval at most, busiest first; the rest count in `dvarapala_store_keys_dropped_total`. At least 1 |
| `timeout` | duration | `"500ms"` | A round slower than this fails (PostgreSQL also sets `statement_timeout`); connecting, migrations included, may take 10 times as long. Above 0 |
| `migrate` | bool | `true` | PostgreSQL only: apply missing schema migrations at start. `false` only checks the version, for a role without DDL rights |
| `ca_file` | path | system roots | PEM roots for `rediss://` and PostgreSQL TLS |

PostgreSQL keeps `UNLOGGED` tables in the `dvarapala` schema; a failover
empties them, which is the same as a short store outage. With
CloudNativePG, point `url` at the `<cluster>-rw` service or a `Pooler`
in transaction mode (PgBouncer with `max_prepared_statements = 0` works).
`dvarapala store schema [--from <version>]` prints the migration SQL to
apply by hand, with no config and no database. A database at another
schema version than the binary's counts as a store failure.

## `[xdp]`

XDP fast path ([RFC 0011](rfc/0011-xdp.md)), Linux only, in builds with
the `xdp` feature (no published binary or image has it: build from
source). Not for the operator's gateway pods, which run without
privileges. An eBPF program on `interface` drops
blocked sources and per-source packet floods in the driver, before the
kernel builds a socket buffer. It needs `CAP_BPF` and `CAP_NET_ADMIN` (or
root) and only looks at packets to the TCP `listen` port and the UDP
`quic.listen` port; every other packet passes untouched.

- Per packet to a protected port: `allow` passes, then `block` (static
  and dynamic) drops, then the per-source rates, then pass.
- Dynamic blocks, with `mode = "enforce"` and `block_ttl` above 0:
  clients refused by the `[l4]` accept rate and heavy hitters that
  detection finds in its own `enforce` mode are blocked for `block_ttl`.
  Both completed a TCP handshake, so a spoofed address cannot get a
  victim blocked.
- An `interface` that cannot be attached is a start-up error. The
  program is detached when the process exits or is killed; `ip link set
  dev <iface> xdp off` detaches it at once.
- Kernel SYN cookies stay the backlog defence: keep
  `net.ipv4.tcp_syncookies = 1`.

| Key | Type | Default | Description |
|---|---|---|---|
| `interface` | string | unset | Network interface to attach to; unset turns XDP off |
| `mode` | `"observe"` or `"enforce"` | `"observe"` | `"observe"` counts `would_drop` and passes everything |
| `attach` | `"auto"`, `"native"` or `"generic"` | `"auto"` | `"auto"`: native driver mode, else generic (skb) mode, logged as `xdp generic mode`; `"native"` makes a driver without support a start-up error |
| `allow` | list of CIDRs | `[]` | Never dropped; wins over `block`. Load balancers and health checkers |
| `block` | list of CIDRs | `[]` | Always dropped |
| `block_ttl` | duration | `"10m"` | How long a dynamic block lasts; `"0s"` turns dynamic blocks off |
| `max_blocks` | integer | `65536` | Entries in the block list, static and dynamic; a full list replaces the dynamic entry that expires first |
| `pps` | integer | `0` (off) | Packets per second per source prefix to protected ports |
| `syn_pps` | integer | `100` | TCP SYNs per second per source prefix |
| `udp_pps` | integer | `0` (off) | UDP packets per second per source prefix |
| `burst` | integer | `200` | Bucket size for the rates above. At least 1 while a rate is on |
| `prefix_v4` / `prefix_v6` | integer | `32` / `64` | Source grouping for the rates |
| `max_sources` | integer | `1048576` | Sources tracked, least recently seen evicted first: about 40 MB of kernel memory at the default, outside the process RSS |

## `[challenge]`

Proof-of-work challenge ([RFC 0012](rfc/0012-challenges.md)), in the
reverse proxy's rate limiter (`rate_limit.enabled`). A browser without a
pass gets a `403` page whose script finds a nonce such that
`SHA-256(seed ":" nonce)` starts with `difficulty` zero bits, then loads
`/.well-known/dvarapala/verify`. A right answer sets the pass cookie
`dvarapala_pass` (HMAC, bound to the client key: the IPv4 address or IPv6
/64) and redirects back. No state is kept on the server.

- The client's bucket comes first: over its limit it gets `429` as before.
- Heavy hitters in `enforce` mode are dropped, pass or not.
- A client that does not accept `text/html` gets `429` without
  `Retry-After`, gRPC gets `grpc-status: 8`. Exempt API paths from the
  challenge with a route (`routes[].challenge = false`).
- A `POST` answered with the page is not replayed: the browser comes
  back with a `GET` to the same URL.
- When only some paths reach dvarapala (an ingress or gateway route per
  path), route `/.well-known/dvarapala/` to it as well. Otherwise the
  upstream answers the verify request, no pass is set and the page
  challenges again in a loop.

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | `"off"`, `"attack"` or `"always"` | `"off"` | `"attack"`: requests without a pass are challenged while detection is in `Attack` and `detection.mode = "enforce"`; a pass keeps the normal limit instead of `attack_rate_factor`. Needs `detection.enabled`. `"always"`: every request without a pass |
| `difficulty` | integer | `16` | Leading zero bits of work, 8 to 24; 16 is about 65 000 hashes, under a second in a browser |
| `timeout` | duration | `"60s"` | How long a page's seed can be solved |
| `pass_ttl` | duration | `"1h"` | How long a pass is valid |
| `secret` | string | `""` | HMAC key, at least 32 bytes. Empty: a random key per process, so passes do not survive a restart or cross replicas (a warning when `store.backend` is not `"memory"`). Set it with `DVARAPALA__CHALLENGE__SECRET` |
| `cookie_secure` | bool | `true` | `Secure` on the cookie; `false` for plain-HTTP labs |

## `[fingerprint]`

JA4 TLS fingerprints ([RFC 0012](rfc/0012-challenges.md)). With any key
set, the TLS listener reads each ClientHello (up to 16 KiB, inside
`tls.handshake_timeout`), computes its JA4 and replays the bytes to the
handshake. Entries are a full JA4 (`"t13d1516h2_8daaf6152771_e5627efa2ab1"`)
or a prefix ending in `*` (`"t13d1516h2_*"`). HTTP/3 and cleartext
requests have no fingerprint and match no rule.

| Key | Type | Default | Description |
|---|---|---|---|
| `deny` | list of strings | `[]` | Matching requests get `403` and the connection is closed |
| `challenge` | list of strings | `[]` | Matching requests need a pass whatever the detector says; needs `challenge.mode` other than `"off"` |
| `header` | string | `""` | Request header that carries the JA4 to the upstream, for example `"x-ja4"`; the client's own copy is removed. Empty sends none |

## `[[routes]]`

Per-route policy ([RFC 0013](rfc/0013-routes.md)), in the reverse proxy's
rate limiter (`rate_limit.enabled`). Routes are tried in order; the first
whose every condition matches applies, and no match leaves the global
policy alone. A route can tighten the limits, never loosen them: the
global bucket, detection, heavy-hitter drops and `fingerprint.deny`
apply to every request. Raise `rate_limit.rate` for a looser default.

```toml
[[routes]]
name = "probes"
path = "/wp-admin"
deny = true

[[routes]]
name = "login"
path = "=/login"
methods = ["POST"]
rate = 1
burst = 5

[[routes]]
name = "api"
host = "api.example.com"
path = "/v1/"
rate = 50
key = "header:x-api-key"
challenge = false
```

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Label in metrics, unique |
| `host` | string | unset | Exact host (`"api.example.com"`) or a suffix (`"*.example.com"`, names under it, not itself); case-insensitive, port and trailing dot ignored. From the URI authority, else `Host` |
| `path` | string | unset | Prefix (`"/api/"`), or exact with a leading `=` (`"=/login"`). Compared on the raw path, before any decoding: `/%61dmin` and `//admin` do not match `/admin` |
| `methods` | list of strings | `[]` | Any method when empty |
| `clients` | list of CIDRs | `[]` | Networks of the client key (after `trusted_proxies`); any client when empty. IPv6 keys are /64, so use prefixes of 64 bits or shorter |
| `deny` | bool | `false` | `403` and the connection closed (gRPC: status 7), before any bucket |
| `rate` | integer | `0` | Requests per second in the route's own bucket, on top of the global one; `0` adds none. Over it: `429` with `Retry-After` |
| `burst` | integer | `0` | The route bucket's size; `0` means `rate` |
| `key` | string | `"client"` | What the route's bucket counts per: `"client"`, `"header:<name>"` (the first value, hashed with a per-process seed; the client without it) or `"ja4"` (the client without a fingerprint; turns JA4 on at the TLS listener) |
| `challenge` | bool | `true` | `false` never shows the challenge; during an attack these requests get the attack limit, as a request without a pass |
| `max_keys` | integer | `10000` | Keys in the route's table, least recently seen evicted |
| `waf` | bool | `true` | `false` sends the route's requests on without asking the `[waf]` agent, for example a gRPC or upload endpoint the rules do not fit |

## `[admin]`

Admin API and config reload ([RFC 0014](rfc/0014-admin.md)), off by default.
JSON over HTTP/1.1 on its own listener; every call needs
`Authorization: Bearer <token>`.

| Key | Type | Default | Description |
|---|---|---|---|
| `listen` | address | `""` | Admin listener, for example `"127.0.0.1:9091"`; empty turns it off. Bind it to loopback or a management network |
| `token` | string | `""` | Bearer token, at least 32 bytes, required when `listen` is set. Set it with `DVARAPALA__ADMIN__TOKEN` |
| `max_blocks` | integer | `4096` | Manual blocks at most; a block over it gets `507` |
| `max_block_ttl` | duration | `"24h"` | Longest block `ttl`, also the default |
| `ui_enabled` | bool | `false` | Serves the web console at `/ui/` ([RFC 0018](rfc/0018-admin-ui.md)); needs `listen` |
| `session_ttl` | duration | `"8h"` | Console session lifetime, at most `"24h"` |
| `max_sessions` | integer | `64` | Console sessions at most; the oldest is dropped for a new one |
| `mode_switch` | bool | `false` | Allows `POST /mode` ([RFC 0021](rfc/0021-admin-ui-config-waf.md)); off, it answers `403` and every mode change goes through the file |
| `public_url` | string | `""` | The console's origin as the browser sees it, for example `"https://<host>"`. Required with OIDC (the redirect URI is `<public_url>/session/oidc/callback`); `https` also sets `Secure` on the session cookie |

| Call | Answer |
|---|---|
| `GET /status` | `version`, `mode`, `detection` state, `clients`, `blocks`, `last_reload`, `waf` (the WAF's running mode, `null` when off), `llm` (`{"sampling": bool}`, `null` when `[ml.llm]` is off) and `switches` (the mode switches in force: `layer`, `mode`, `file_mode`, `actor`, `at`) |
| `GET /config` | the running config ([RFC 0021](rfc/0021-admin-ui-config-waf.md)): `keys`, each with `key` (dotted), `value`, `reload` (`true` when a reload applies it in place; a `false` key shows the value the process started with) and `default`. `admin.token`, `admin.oidc.client_secret`, `challenge.secret` and `store.url` show as `"<redacted>"` when set |
| `GET /waf` | the `[waf]` `settings`, the running `mode` and its `switch`, the matched `rules` (`rule`, `count`, `last_seen`, the last match's `method`, `path` without the query and `anomaly_score`; 256 IDs, then the `other` count) and the `files` of `waf.rules_files` read now (`path`, `size`, `modified`, `content`, or `error`) |
| `GET /metrics` | the Prometheus text of the metrics listener |
| `GET /history?range=<15m\|1h\|6h\|24h\|7d>` | the traffic history ([RFC 0022](rfc/0022-traffic-history.md)), default `15m`: `interval_ms`, `source` (`memory` or `store`) and `samples` (`t` in Unix ms, the rate per second of `allow`, `throttle`, `challenge`, `drop`, `error`, and `detection`, `null` for a store point). See [`[history]`](#history); `400` for another range |
| `POST /mode?layer=<detection\|waf>&mode=<observe\|enforce>` | switches the layer's running mode in place, on this instance, until the next reload or restart (a reload logs `mode switch cleared` per switch). `403` unless `mode_switch`, `409` when the layer is off. Answers `layer`, `mode`, `previous` |
| `GET /llm` | the LLM labels ([RFC 0023](rfc/0023-llm-labels.md)): `configured` (`false` and nothing else without `ml.llm.endpoint`), `sampling`, `until` (Unix ms, `null` without a console switch), `enabled`, `max_duration_secs`, `counts` (`label`, `trigger`, `count` since start) and `recent` (the last 200, newest first: `at` in Unix ms, `trigger`, `route`, `method`, `path`, `label`, `confidence`, `pattern`) |
| `GET /llm/export` | the stored labels as JSON lines ([RFC 0024](rfc/0024-llm-label-store.md)), the `ml.llm.export` columns, oldest first, streamed. `since` and `until` (RFC 3339 or Unix ms, inclusive), `label` and `trigger` (repeatable, at most 32 each). With `ml.llm.persist`, `GET /llm` answers from the store (`counts` over the last 24 h of every replica, `recent` the cluster's last 200) with `"source":"store"`, else `"source":"memory"`. `409` without `persist`, `400` naming a bad parameter |
| `POST /llm?on=<duration>` | samples until now plus the duration (default `30m`, at most `ml.llm.max_duration`); `POST /llm?off` stops. `403` unless `mode_switch`, `409` without `ml.llm.endpoint`, `400` for a bad duration |
| `POST /reload` | the same as `SIGHUP`: `restart` lists the changed keys that need a restart; `422` with `error` when the file is refused |
| `GET /top` | the heavy hitters of the last closed window, `cidr` and `count` |
| `GET /blocks` | manual blocks in force, `cidr` and `ttl_secs` |
| `POST /blocks?cidr=<net>&ttl=<duration>` | blocks `net` (a CIDR or an address; `/` may be sent as `%2F`): `403` and the connection closed before any bucket, and the XDP block list when `[xdp]` is on |
| `DELETE /blocks?cidr=<net>` | removes the block, `404` when not listed. An XDP entry stays until its own expiry |

Admin connections: at most 16, one request each, a 5 s header timeout,
the query string at most 1 KiB, no body read. Every call that changes
state is logged as `admin action` with its `actor` (`token`, or the
console user).

### Console

With `ui_enabled = true` the admin listener serves a web console at
`/ui/` ([RFC 0018](rfc/0018-admin-ui.md)): the detection state and live
request rates, top talkers, manual blocks and reload. It is embedded in
the binary (the `ui` feature, in the default build). The listener stays
plain HTTP: off loopback, put a TLS terminator in front (a reverse proxy,
a Kubernetes `HTTPRoute`, a Tailscale ingress) and set an `https`
`public_url`.

The console logs in with the admin token or, with `[admin.oidc]`, through
an OIDC issuer, and then holds an `HttpOnly`, `SameSite=Lax` session
cookie. The API calls above accept that cookie in place of the bearer
header; with the cookie, `POST` and `DELETE` also need
`X-Dvarapala-Csrf` set to the session's `csrf`.

| Call | Answer |
|---|---|
| `GET /ui/...` | the console; unknown paths under `/ui/` get the page so deep links work |
| `GET /session/methods` | unauthenticated: `token` and `oidc` (`null` or its `label`) |
| `POST /session` | with the bearer header: `204` and the session cookie |
| `GET /session` | `subject`, `method` (`token`, `oidc`), `expires_in`, `csrf`; `401` without a session |
| `DELETE /session` | logs out |
| `GET /session/oidc` | `302` to the issuer |
| `GET /session/oidc/callback` | the issuer's redirect: `302` to `/ui/` with the cookie, or `303` to `/ui/login?error=<reason>` |

`GET /status` also answers `requests`: the totals of
`dvarapala_requests_total` per verdict since start.

### `[admin.oidc]`

OIDC login for the console: the authorization code flow with PKCE, the
gateway as a confidential client. The ID token comes straight from the
token endpoint over verified TLS, so its claims are checked (`iss`,
`aud`, `exp`, `nonce`) and its signature is not (OIDC Core 3.1.3.7).

| Key | Type | Default | Description |
|---|---|---|---|
| `issuer` | string | `""` | Issuer URL, `https` (`http` only on a loopback host); empty turns OIDC off. Needs `ui_enabled` and `public_url` |
| `client_id` | string | `""` | Required with `issuer` |
| `client_secret` | string | `""` | Required with `issuer`; set it with `DVARAPALA__ADMIN__OIDC__CLIENT_SECRET` |
| `scopes` | list | `["openid", "email"]` | Add the scope that carries groups when using `allow_groups` |
| `allow_emails` | list | `[]` | Verified emails allowed in (case does not matter) |
| `allow_groups` | list | `[]` | Groups allowed in. One of the two lists must name someone |
| `groups_claim` | string | `"groups"` | The ID token claim holding the groups |
| `require_email_verified` | bool | `true` | `false` (RFC 0020): an `email` claim without `email_verified` counts as verified for `allow_emails`; an explicit `false` still denies. Logs `oidc email trusted without email_verified` at start |
| `label` | string | `"SSO"` | The login button: "Sign in with SSO" |

Set `require_email_verified = false` only for an issuer that verifies
every address itself and never sends the claim, such as Cloudflare Access
in front of Google. With a provider where users can edit their email, it
lets anyone who types an allowed address into a profile log in.

### Reload

`SIGHUP` and `POST /reload` read the `--config` file and the environment
again. A file that does not load or validate is refused whole and the
running config stays. Applied in place, clients keeping their buckets and
the detector its baseline: `rate_limit.rate`, `rate_limit.burst`,
`trusted_proxies`, `history.retention`, `detection.mode`, `detection.attack_rate_factor`,
`[challenge]` (passes stay valid while `secret` is unchanged),
`[fingerprint]`, `[[routes]]` (route tables start empty when the list
changes) and `[waf]` (the agent connections stay while `endpoint`,
`max_body` and `max_concurrent` do). Every other key keeps its running value and is named in the
log line `config reloaded` (`restart=`) until a restart, as are JA4 turned
on after a start without it, and a new rate with a shared `[store]` (the
cluster budget is set at start). `SIGHUP` also reloads the TLS pair.

## `[history]`

The traffic history behind the console graph ([RFC 0022](rfc/0022-traffic-history.md)),
answered by `GET /history`. It runs whenever `admin.listen` is set (and
the section is checked only then): a ring in memory of fixed size, about
`window / interval x 64` bytes (12 KiB at the defaults). With `persist`,
each replica also writes one row per minute to `dvarapala.traffic_history`
in the PostgreSQL store (migration 2), and a range longer than `window`
reads those rows, summed over the replicas of `store.cluster`, as
`"source": "store"` with `interval_ms` 60000; the last `window` still comes
from the ring. A failed write or read is logged once as
`history store unavailable` (then `history store recovered`) and the call
answers from the ring with `"source": "memory"`.

| Key | Type | Default | Description |
|---|---|---|---|
| `interval` | duration | `"5s"` | Sample period of the ring, at least `"1s"`. Restart |
| `window` | duration | `"15m"` | How much the ring keeps, at most 10 000 samples (`window / interval`). Restart |
| `persist` | bool | `false` | Write a row per minute to the store. Needs `store.backend = "postgres"` and a build with the `postgres` feature (the container image). Restart |
| `retention` | duration | `"7d"` | Rows older than this are deleted, by one replica at a time once an hour. At least `"1h"`; also `"<n>d"`. Reload |

## `[pool]`

Several upstreams with health checks, ejection and retries ([RFC 0015](rfc/0015-upstream-pools.md)),
in reverse mode. `pool.upstreams` replaces `upstream`; the endpoints share
`upstream_protocol`, `[upgrade]` and `[upstream_tls]`, and the TCP and
HTTP/3 listeners share one pool and its health. With `upstream` alone,
the proxy sends to it as before: every other `[pool]` key must stay at
its default.

| Key | Type | Default | Description |
|---|---|---|---|
| `upstreams` | list of URLs | `[]` | Base URLs, `http://` or `https://`, each with its own path. At most 64 |
| `balance` | string | `"round_robin"` | Or `"least_requests"`: the endpoint with the fewest requests in flight, ties in turn |
| `health_path` | string | `""` | Path of the active check, for example `"/healthz"`, joined onto each base URL; empty turns active checks off |
| `health_interval` | duration | `"5s"` | Time between two checks of one endpoint |
| `health_timeout` | duration | `"1s"` | One check at most; a `2xx` or `3xx` in time is a pass |
| `unhealthy_after` | integer | `3` | Failed checks in a row that take an endpoint out |
| `healthy_after` | integer | `2` | Passed checks in a row that bring it back |
| `eject_after` | integer | `5` | Failed requests in a row (connect error, timeout, `502` to `504`) that eject an endpoint; `0` turns ejection off |
| `eject_time` | duration | `"30s"` | How long an ejection lasts; one failure after it ejects again |
| `retries` | integer | `1` | Retries on another endpoint of a `GET`, `HEAD` or `OPTIONS` without a body that failed to connect; `0` turns retries off |
| `retry_budget` | float | `0.2` | Retries earned per request, in `[0, 1]`; at most 10 banked |

With no endpoint up, the pool picks among all of them (fail open), logs
`pool degraded` at most once a second and counts it. Health and ejection
state is per process.

## `[waf]`

A web application firewall in an external agent ([RFC 0017](rfc/0017-waf.md)),
off by default. dvarapala sends each request to the agent over SPOP, the
protocol of HAProxy's SPOE, and blocks or forwards on its answer. The
agent is [`coraza-spoa`](https://github.com/corazawaf/coraza-spoa): OWASP
Coraza with the OWASP Core Rule Set built in. The rules, their paranoia
level, exclusions and rule reloads are the agent's config; see
`examples/waf/` for a pod with both containers.

Reverse mode only. The WAF runs after the rate limiter (and after
`[challenge]`, `[fingerprint]` and `[[routes]]`), so a flood is refused
before it costs an inspection, and before the proxy. The agent gets the
client address (after `trusted_proxies`), the method, path, query,
protocol version, headers and up to `max_body` bytes of the body. gRPC
requests are sent without their body. In builds with the `waf` feature
(on by default); a build without it refuses `waf.enabled`.

```toml
[waf]
enabled = true
mode = "observe"
endpoint = "unix:/run/coraza-spoa/coraza.sock"
```

| Key | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Turns the WAF stage on |
| `mode` | string | `"observe"` | `"observe"` logs and counts what the agent would block and forwards; `"enforce"` blocks |
| `endpoint` | string | `""` | The agent: `"host:port"` or `"unix:/absolute/path"`, required when `enabled`. Requests cross it in clear: keep it on loopback or a Unix socket (anything else logs a warning at start) |
| `app` | string | `"default"` | The agent's application, the rule set to apply; `coraza-spoa` falls back to its `default_application` for an unknown name |
| `timeout` | duration | `"250ms"` | Waiting for a connection plus the round trip; over it the request counts as an `error` |
| `on_error` | string | `"block"` | When the agent is down, slow or answers garbage, in `enforce`: `"block"` answers `503`, `"pass"` forwards. `observe` always forwards |
| `max_body` | size | `"16KiB"` | Body bytes buffered and sent at most, as bytes or with `B`, `KiB` or `MiB`, up to 64 MiB; `0` sends headers only. The agent's frame is `max_body` plus 16 KiB |
| `body_limit_action` | string | `"reject"` | A body over `max_body` in `enforce`: `"reject"` answers `413` without asking; `"pass"` sends the request to the agent without its body, then the whole body upstream. `observe` always does as `"pass"` |
| `max_concurrent` | integer | `64` | Connections to the agent, one request each at a time; a request waits for a free one within `timeout` |
| `rules_files` | list of paths | `[]` | The agent's rule files, at most 8, shown by `GET /waf` and the console ([RFC 0021](rfc/0021-admin-ui-config-waf.md)). Display only: the gateway never parses or applies them. A file over 256 KiB or unreadable is listed with its error and logged as `waf rules file unreadable` |

A blocked request gets the agent's status when it is `400` to `599`,
`403` otherwise, with `Connection: close` on a `403` (gRPC: status 7, or
14 for `503`). The body is read before the agent is asked, then sent
upstream as it came. The first match of a client in a second is logged
as `waf match` with the rule, the matched rule IDs, the anomaly score and
the agent's transaction ID; agent failures are logged as `waf agent` at
most once a second.

The agent's time grows with the body: with the CRS at paranoia 1, about
1 ms for a GET and up to 200 ms for a 16 KiB form of many short fields
([RFC 0017](rfc/0017-waf.md) has the numbers). Set `timeout` for the
largest body `max_body` lets through, or skip upload routes with
`waf = false`.

## gRPC

Requests with `content-type: application/grpc` or `application/grpc+<codec>`
get local errors in gRPC form: HTTP 200 with `grpc-status` and
`grpc-message` in a trailers-only response.

| Cause | `grpc-status` |
|---|---|
| Rate limit or model score (`Throttle`) | `8` RESOURCE_EXHAUSTED, with `retry-after` and `grpc-retry-pushback-ms` |
| Challenge without a pass ([RFC 0012](rfc/0012-challenges.md)) | `8` RESOURCE_EXHAUSTED, without pushback |
| Detection `Drop`, `fingerprint.deny`, `routes[].deny` | `7` PERMISSION_DENIED |
| Upstream unreachable | `14` UNAVAILABLE |

Use `upstream_protocol = "http2"` for gRPC upstreams.

## Replay

`dvarapala replay --config <file> [--out <file>] <log | ->`
([RFC 0016](rfc/0016-replay.md)) runs the reverse proxy's protection layer
from the same config over a JSON Lines access log, on a virtual clock taken
from each line's `ts`, and prints the protection metrics. Needs `mode =
"reverse"` and `rate_limit.enabled`; `upstream` may be any URL, nothing is
sent. In builds with the `replay` feature (on by default).

| Field | Default | Description |
|---|---|---|
| `ts` | required | Unix time in seconds, fractions allowed; a `ts` earlier than the previous one keeps the clock where it is |
| `client` | required | Peer address, IPv4 or IPv6 |
| `method` | `"GET"` | |
| `host` | `""` | The `Host` header |
| `path` | `"/"` | Path and query |
| `xff` | none | `X-Forwarded-For`, used only from `trusted_proxies` |
| `ja4` | none | The client's JA4 |
| `headers` | `{}` | Other request headers, name to value |

Unknown fields are ignored. A line that does not parse, is over 64 KiB or
has over 64 headers is skipped and counted; the first ten are logged as
`line skipped` and listed in the report. The report has the line counts,
the virtual time span, then the `dvarapala_requests_total`,
`dvarapala_challenges_total`, `dvarapala_fingerprint_matches_total`,
`dvarapala_route_requests_total`, `dvarapala_detection_*` and
`dvarapala_waf_*` series as `/metrics` shows them. With `[waf]` enabled,
each line is sent to the agent too, without a body: a rule set can be
tried on a past log before `mode = "enforce"`. `--out` writes `{"line":N,"status":S}` per replayed
line. `upstream`, `[pool]`, `[tls]`, `[quic]`, `[l4]`, `[store]`, `[xdp]` and
`[admin]` are ignored, named in one `replay ignores` warning. A config that
does not load or a log that cannot be opened exits with status 2.

## Metrics

Served on `metrics.listen` at `/metrics`.

| Metric | Description |
|---|---|
| `dvarapala_requests_total{verdict,protocol}` | Requests by verdict and client protocol (`http1`, `http2`, `http3`) |
| `dvarapala_requests_total{verdict,protocol,scope="cluster"}` | Requests refused by the shared cluster count or drop list ([RFC 0010](rfc/0010-shared-state.md)), not the local bucket |
| `dvarapala_requests_total{verdict="drop",protocol,scope="block"}` | Requests refused by a manual block ([RFC 0014](rfc/0014-admin.md)) |
| `dvarapala_limiter_clients` | Clients in the limiter table |
| `dvarapala_limiter_evictions_total` | Evictions; a steady rise means `max_clients` is too small or a spoofed flood |
| `dvarapala_upstream_errors_total` | Upstream (or forward destination) connect or response failures |
| `dvarapala_upstream_requests_total{upstream,result}` | Requests per pool endpoint ([RFC 0015](rfc/0015-upstream-pools.md)): `ok`, `error` (connect error, timeout, `502` to `504`); `upstream` is the endpoint's `host:port` |
| `dvarapala_upstream_healthy{upstream}` | 1 when the endpoint is up, 0 when checks or an ejection took it out |
| `dvarapala_upstream_in_flight{upstream}` | Requests in flight per endpoint, until the response headers |
| `dvarapala_upstream_ejections_total{upstream}` | Passive ejections |
| `dvarapala_upstream_retries_total{result}` | Retries `sent`, or refused by the `budget` |
| `dvarapala_upstream_degraded_total` | Picks made with no endpoint up |
| `dvarapala_grpc_local_responses_total{status}` | gRPC errors answered locally: `resource_exhausted`, `permission_denied`, `unavailable` |
| `dvarapala_tunnels_open{protocol}` | Open tunnels (`protocol="connect"` for forward mode `CONNECT`); compare with `upgrade.max_tunnels` |
| `dvarapala_tunnels_total{protocol,end}` | Closed tunnels by `end`: `client` or `upstream` (that side closed first), `idle`, `lifetime`, `shutdown` |
| `dvarapala_tunnel_bytes_total{direction}` | Bytes copied: `in` from clients, `out` from the upstream |
| `dvarapala_tunnels_rejected_total` | Upgrades refused over `upgrade.max_tunnels`; logged as `tunnel limit reached` at most once a second |
| `dvarapala_egress_requests_total{destination,result}` | Forward mode ([RFC 0007](rfc/0007-forward-proxy.md)): `sent`, `delayed` (sent after a wait), `refused` (local `429`, logged as `egress refused` at most once a second), `denied` (`403`; `destination="none"` when no destination is listed for the target) |
| `dvarapala_egress_wait_seconds{destination}` | Histogram of the wait before a delayed send |
| `dvarapala_egress_queue{destination}` | Requests waiting now; compare with `max_queue` |
| `dvarapala_egress_in_flight{destination}` | Requests or `CONNECT` tunnels in flight; compare with `max_concurrent` |
| `dvarapala_egress_provider_pauses_total{destination}` | Provider `429` or `503` with `Retry-After` that paused the destination |
| `dvarapala_http2_goaway_total{reason}` | HTTP/2 connections closed with `GOAWAY`: `flood` (rapid reset, error resets, header floods), `protocol` (other protocol errors) |
| `dvarapala_detection_state` | 0 `Normal`, 1 `Suspect`, 2 `Attack`, 3 `Cooldown` |
| `dvarapala_detection_rate_zscore` | Current window z-score |
| `dvarapala_detection_source_entropy` | Current window entropy, normalized to `[0, 1]` |
| `dvarapala_detection_heavy_hitters` | Prefixes in the top-k above the per-client limit |
| `dvarapala_detection_transitions_total{from,to}` | State changes |
| `dvarapala_ml_score` | Histogram of model scores (feature `ml`) |
| `dvarapala_l4_connections_open` | Open connections; compare with `l4.max_connections` |
| `dvarapala_l4_rejected_total{reason}` | Connections closed on accept: `total`, `per_client`, `rate`; logged as `connection limit` at most once a second |
| `dvarapala_l4_timeouts_total{kind}` | Connections or requests cut by a timeout: `header`, `idle`, `body` (`408`) |
| `dvarapala_l4_clients` | Clients in the per-client connection table |
| `dvarapala_challenges_total{result}` | Challenges ([RFC 0012](rfc/0012-challenges.md)): `issued` (pages), `passed`, `failed` (stale or foreign seed, too little work), `invalid_pass` (a cookie that does not verify); `verdict="challenge"` in `dvarapala_requests_total` counts pages and `429`s for clients without a pass |
| `dvarapala_fingerprint_matches_total{rule}` | Requests matching `fingerprint.deny` or `fingerprint.challenge` |
| `dvarapala_route_requests_total{route,verdict}` | Requests per route ([RFC 0013](rfc/0013-routes.md)): `allow` (sent upstream), `throttle` (the route's bucket), `deny` |
| `dvarapala_route_keys{route}` | Keys in the route's table |
| `dvarapala_waf_requests_total{verdict}` | Requests seen by the WAF ([RFC 0017](rfc/0017-waf.md)): `pass`, `block`, `would_block` (`observe`), `skipped` (a route with `waf = false`), `error` (no answer from the agent), `body_over_limit` (counted besides the verdict with `body_limit_action = "pass"`) |
| `dvarapala_waf_errors_total{reason}` | Agent failures: `connect`, `timeout`, `protocol` (a bad or oversized frame), `disconnect` |
| `dvarapala_waf_rule_matches_total{rule}` | Blocks and would-blocks by the agent's rule ID; the first 256 IDs get a label, later ones count as `other` |
| `dvarapala_waf_inspect_seconds` | Histogram of the round trip to the agent |
| `dvarapala_llm_sampling` | 1 while LLM labels sample ([RFC 0023](rfc/0023-llm-labels.md)) |
| `dvarapala_llm_samples_total{trigger,result}` | Sampling decisions: `sent`, `skipped_rate`, `deduped` (`per_client`), `dropped` (queue full) |
| `dvarapala_llm_calls_total{result}` | Calls: `ok`, `invalid` (an answer outside `labels`, bad JSON or over 64 KiB), `timeout`, `error`, `limited` (`429` from the provider) |
| `dvarapala_llm_labels_total{label,trigger}` | Answers by label |
| `dvarapala_llm_call_seconds` | Histogram of call time |
| `dvarapala_llm_tokens_total{kind}` | `prompt` and `completion`, from the reply's `usage` when present |
| `dvarapala_llm_store_rows_total{result}` | Label rows ([RFC 0024](rfc/0024-llm-label-store.md)): `ok` written, `error` lost with a failed batch, `dropped` on a full `persist_queue` |
| `dvarapala_llm_store_rows_deleted_total` | Label rows removed by `ml.llm.retention` |
| `dvarapala_llm_export_rows_total` | Rows streamed by `GET /llm/export` |
| `dvarapala_config_reloads_total{result}` | Reloads ([RFC 0014](rfc/0014-admin.md)): `ok`, `failed` |
| `dvarapala_admin_requests_total{endpoint,status}` | Admin calls by endpoint (`ui`, `session` and `oidc` for the console, `other` for unknown paths) and status, `401` included |
| `dvarapala_admin_logins_total{method,result}` | Console logins ([RFC 0018](rfc/0018-admin-ui.md)): `method` `token` or `oidc`, `result` `ok`, `denied` (not in the allow lists) or `failed` |
| `dvarapala_admin_sessions` | Console sessions alive |
| `dvarapala_mode_switched{layer}` | 1 while `detection` or `waf` runs in a mode switched by `POST /mode`, 0 after the switch ends ([RFC 0021](rfc/0021-admin-ui-config-waf.md)) |
| `dvarapala_blocks` | Manual blocks in force |
| `dvarapala_tls_ja4_total{result}` | ClientHellos fingerprinted (`ok`) or not (`unparsed`: not a whole ClientHello within 16 KiB) |
| `dvarapala_tls_handshakes_total{result}` | Handshakes by `ok`, `failed`, `timeout`, `rejected` |
| `dvarapala_tls_handshakes_in_progress` | Handshakes running now |
| `dvarapala_tls_resumed_total` | Resumed sessions |
| `dvarapala_tls_cert_expiry_timestamp_seconds` | `notAfter` of the served certificate, Unix seconds |
| `dvarapala_quic_handshakes_total{result}` | QUIC handshakes ([RFC 0006](rfc/0006-http3.md)) by `ok`, `failed`, `timeout`, `refused` (over `quic.max_connections`, before any crypto) |
| `dvarapala_quic_retries_total` | Retry packets sent; `quic retry on` and `quic retry off` are logged when `under_load` starts and stops |
| `dvarapala_quic_connections_open` | Established QUIC connections |
| `dvarapala_store_up` | 1 while the last sync round succeeded, 0 otherwise ([RFC 0010](rfc/0010-shared-state.md)) |
| `dvarapala_store_replicas` | Live replicas seen in the last round |
| `dvarapala_store_sync_seconds` | Histogram of one sync round |
| `dvarapala_store_sync_errors_total` | Failed rounds |
| `dvarapala_store_keys_dropped_total` | Clients left out of a round by `store.max_keys` |
| `dvarapala_history_writes_total{result}` | History minute rows ([RFC 0022](rfc/0022-traffic-history.md)): `ok`, `error`, or `skipped` when the previous write was still running |
| `dvarapala_history_rows_deleted_total` | History rows removed by `history.retention` |
| `dvarapala_xdp_packets_total{action,reason}` | XDP verdicts ([RFC 0011](rfc/0011-xdp.md)): `action` is `pass`, `drop` or `would_drop`; `reason` is `allow`, `block`, `pps`, `syn`, `udp` or `other` (passed every check, or not to a protected port) |
| `dvarapala_xdp_blocks` | Entries in the XDP block list, static and dynamic |
| `dvarapala_xdp_attached{mode}` | 1 while attached, `native` or `generic`; `xdp attached` is logged at start |
