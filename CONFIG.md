# Configuration reference

`dvarapala serve --config <file>` reads a TOML file. Every key can also be
set, or overridden, by an environment variable: `DVARAPALA__` followed by
the key path with `__` between parts, for example
`DVARAPALA__RATE_LIMIT__RATE=5` for `rate_limit.rate`. Unknown keys are an
error. The log level comes from `RUST_LOG` (default `info`).

A commented example is in [examples/dvarapala.toml](examples/dvarapala.toml).

The SDKs ([RFC 0008](rfc/0008-sdk.md), [sdk/](sdk/README.md)) take the same
names and defaults for the keys that apply in process: `rate_limit.*`,
`detection.*`, `trusted_proxies` and the connection keys of `[l4]`.

Durations are strings: `"<n>ms"`, `"<n>s"`, `"<n>m"` or `"<n>h"`, for
example `"500ms"`, `"10s"` or `"24h"`.

## Top level

Top-level keys go above the first `[section]` in the file.

| Key | Type | Default | Description |
|---|---|---|---|
| `mode` | `"reverse"` or `"forward"` | `"reverse"` | `"forward"` runs an egress forward proxy ([RFC 0007](rfc/0007-forward-proxy.md)), see [`[forward]`](#forward) |
| `listen` | address | `"0.0.0.0:8080"` | Proxy listen address |
| `upstream` | URL | required in reverse mode | Upstream base URL, `http://` or `https://`; ignored in forward mode |
| `upstream_protocol` | `"http1"`, `"http2"` or `"auto"` | `"http1"` | Protocol to the upstream ([RFC 0004](rfc/0004-http2-grpc.md)): `http2` is h2c with prior knowledge for `http://` and ALPN `h2` for `https://` (an upstream that cannot speak it gets 502); `auto` lets ALPN choose for `https://` and keeps HTTP/1.1 for `http://` |
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

## `[quic]`

HTTP/3 over QUIC ([RFC 0006](rfc/0006-http3.md)), experimental, in builds
with the `http3` feature (off by default). Set `listen` to open a UDP
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
callers are your own services. `[upstream_tls]` verifies `https://`
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
builds with its cargo feature (`redis`, `postgres`, both off by default).
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
the `xdp` feature (off by default). An eBPF program on `interface` drops
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
  challenge by running them on another listener until per-route rules
  exist.
- A `POST` answered with the page is not replayed: the browser comes
  back with a `GET` to the same URL.

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

## gRPC

Requests with `content-type: application/grpc` or `application/grpc+<codec>`
get local errors in gRPC form: HTTP 200 with `grpc-status` and
`grpc-message` in a trailers-only response.

| Cause | `grpc-status` |
|---|---|
| Rate limit or model score (`Throttle`) | `8` RESOURCE_EXHAUSTED, with `retry-after` and `grpc-retry-pushback-ms` |
| Challenge without a pass ([RFC 0012](rfc/0012-challenges.md)) | `8` RESOURCE_EXHAUSTED, without pushback |
| Detection `Drop`, `fingerprint.deny` | `7` PERMISSION_DENIED |
| Upstream unreachable | `14` UNAVAILABLE |

Use `upstream_protocol = "http2"` for gRPC upstreams.

## Metrics

Served on `metrics.listen` at `/metrics`.

| Metric | Description |
|---|---|
| `dvarapala_requests_total{verdict,protocol}` | Requests by verdict and client protocol (`http1`, `http2`, `http3`) |
| `dvarapala_requests_total{verdict,protocol,scope="cluster"}` | Requests refused by the shared cluster count or drop list ([RFC 0010](rfc/0010-shared-state.md)), not the local bucket |
| `dvarapala_limiter_clients` | Clients in the limiter table |
| `dvarapala_limiter_evictions_total` | Evictions; a steady rise means `max_clients` is too small or a spoofed flood |
| `dvarapala_upstream_errors_total` | Upstream (or forward destination) connect or response failures |
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
| `dvarapala_xdp_packets_total{action,reason}` | XDP verdicts ([RFC 0011](rfc/0011-xdp.md)): `action` is `pass`, `drop` or `would_drop`; `reason` is `allow`, `block`, `pps`, `syn`, `udp` or `other` (passed every check, or not to a protected port) |
| `dvarapala_xdp_blocks` | Entries in the XDP block list, static and dynamic |
| `dvarapala_xdp_attached{mode}` | 1 while attached, `native` or `generic`; `xdp attached` is logged at start |
