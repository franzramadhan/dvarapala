---
title: Protection layers
---

Each layer is optional. Every key is in
[Configuration](configuration.html).

## XDP fast path

An optional eBPF program (builds with the `xdp` feature, Linux only) on
the network interface, before the kernel builds a socket buffer. For
packets to the TCP `listen` port and the UDP `quic.listen` port: `allow`
passes, `block` drops, then per-source rates for all packets (`pps`), TCP
SYNs (`syn_pps`) and UDP (`udp_pps`). Every other packet passes untouched.

With `mode = "enforce"`, clients refused by the `[l4]` accept rate and
heavy hitters dropped by detection get a dynamic block for `block_ttl`.
Both completed a TCP handshake, so a spoofed source cannot get a victim
blocked. Keep kernel SYN cookies on for the backlog. In `observe` mode it
counts `would_drop` and passes everything.

Keys: [`[xdp]`](configuration.html#xdp).

## Connection limits

Checked on every accepted connection, before TLS or any HTTP is read: a
cap on open connections in total (`max_connections`) and per client
(`max_per_client`), and a token bucket on new connections per client
(`accept_rate`, `accept_burst`). A refused connection is closed at once,
with no response. Timeouts cut connections that hold a slot without
sending anything useful: `header_timeout` for each request head,
`idle_timeout` between requests, and `min_body_rate` for bodies that
trickle in (`408`).

A client here is the peer address, grouped by `prefix_v4` / `prefix_v6`;
`X-Forwarded-For` does not apply. Behind a load balancer, list it in
`exempt`.

Keys: [`[l4]`](configuration.html#l4).

## Rate limit

A token bucket per client: `rate` tokens per second, up to `burst`. An
empty bucket answers `429` with `Retry-After`, without contacting the
upstream. The client table holds `max_clients` entries and evicts the
least recently seen one, so a spoofed-source flood cannot grow memory.

Behind a load balancer, list it in `trusted_proxies`: only those peers may
set `X-Forwarded-For`. Everyone else is keyed by their own address.

Keys: [`[rate_limit]`](configuration.html#rate_limit), `trusted_proxies`.

## Adaptive detection

Per-window counts catch what a fixed rate misses: many clients that each
stay under the limit.

- **Heavy hitters**: a count-min sketch with a top-k list finds the
  prefixes sending more than the per-client limit.
- **Baseline**: an EWMA of the request rate; a window above it by
  `z_threshold` standard deviations is anomalous (after `warmup_windows`).
- **Entropy**: a sharp drop in how spread out the sources are
  (`entropy_drop`) is anomalous too.

`trigger_windows` anomalous windows in a row move the state to `Attack`;
`cooldown_windows` normal ones bring it back. Prefixes (`prefix_v4`,
`prefix_v6`) group a subnet into one key.

In `observe` mode none of this changes a verdict: it shows in logs
("would drop") and the `dvarapala_detection_*` metrics. In `enforce` mode
a heavy hitter gets `403` and the connection is closed, and during
`Attack` every client's bucket refills at `attack_rate_factor` of its rate.

Keys: [`[detection]`](configuration.html#detection).

## Scoring model

An optional model of your own scores each client on every request the
other layers allow; a score above `ml.threshold` gets `429` with
`Retry-After`. It is for operators who have labeled traffic of their own
and want a signal the fixed limits miss, such as a slow scraper that
stays under the rate.

### Requirements

- A build with the `ml` feature: the container image since v0.19.1 (so
  the operator's gateways, with the model mounted from a ConfigMap
  through `gateway.mounts`), or a binary built with `--features ml`. The
  release tarballs and the SDKs do not have it: there `ml.model` stops
  the start with `ml.model <path> needs a build with the ml feature`.
- Reverse mode with `[rate_limit]` enabled: scoring runs inside the rate
  limiter.
- An XGBoost JSON model: objective `binary:logistic`, booster `gbtree`, at
  most 1024 trees, 65 536 nodes, depth 16 and 16 MiB, trained on columns
  named after dvarapala's features below (any subset, any order). A model
  trained on another dataset's columns (for example CICDDoS2019) does not
  load: `unknown feature "Flow Duration"`.

### Features

Per client, computed online; the window is `detection.window`, default
1 s:

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

The averages are moving averages that move 10% toward each new value. dvarapala does not export these
vectors: build the training set from your own access logs with the same
definitions, label each row (1 attack, 0 normal), then:

```python
import pandas as pd, xgboost as xgb

df = pd.read_csv("features.csv")  # the columns above plus "label"
d = xgb.DMatrix(df.drop(columns="label"), label=df["label"])
booster = xgb.train({"objective": "binary:logistic", "max_depth": 4}, d, num_boost_round=50)
booster.save_model("model.json")
```

LLM labels ([`[ml.llm]`](configuration.html#mlllm), RFC 0023) can label
the rows for you: `ml.llm.export` writes one JSON line per answer with
these columns plus `label`, `confidence`, `trigger` and `at`. With
`ml.llm.persist`, `GET /llm/export` gives the same lines for every
replica. Review the labels before training on them:

```python
df = pd.read_json("labels.jsonl", lines=True)
df = df[df.confidence >= 0.8]
y = (df.label != "benign").astype(int)
X = df.drop(columns=["label", "confidence", "trigger", "at"])
booster = xgb.train({"objective": "binary:logistic", "max_depth": 4}, xgb.DMatrix(X, label=y), num_boost_round=50)
```

### What to expect

- A bad model stops the start with the reason (for example `model:
  objective "reg:squarederror" not supported, train with
  binary:logistic`). A good one is read once; changing it needs a
  restart.
- `dvarapala_ml_score` is a histogram of every score. There is no observe
  mode: start with `threshold = 1.0` (no score is above 1), read the
  histogram for a few days, then lower it.
- A request scored above the threshold gets `429` with `Retry-After` of
  one detection window, counted as a throttle.

```toml
[ml]
model = "/etc/dvarapala/model.json"
threshold = 1.0  # watch only; lower it once the scores look right
```

Keys: [`[ml]`](configuration.html#ml).

## Challenge

During an attack every client without a pass shares the attack limit
(`attack_rate_factor`). With `challenge.mode = "attack"`, a browser
instead gets a `403` page whose script finds a SHA-256 proof of work
(`difficulty` leading zero bits, under a second at the default 16), then
gets a pass cookie and the normal limit back. `"always"` challenges every
request without a pass.

The pass is an HMAC bound to the client key, so the server keeps no
state. Set `challenge.secret` so passes survive a restart and work on
every replica. The client's bucket still comes first, and heavy hitters
in `enforce` mode are dropped with or without a pass. Clients that do not
accept `text/html`, and gRPC, get `429` instead of the page.

The page sends its answer to `/.well-known/dvarapala/verify`. When an
ingress or gateway sends only some paths to dvarapala, add that prefix
to them, or the upstream answers it and the browser loops on the
challenge.

Keys: [`[challenge]`](configuration.html#challenge).

## JA4 fingerprints

With `[fingerprint]` set, the TLS listener computes the JA4 of each
ClientHello. `deny` drops matching clients, `challenge` makes them solve
the challenge whatever the detector says, and `header` forwards the JA4
to the upstream. Entries are a full JA4 or a prefix ending in `*`.

Keys: [`[fingerprint]`](configuration.html#fingerprint).

## Routes

`[[routes]]` entries apply a policy to the requests they match, first
match wins. A route matches on `host`, `path` (a prefix, `=` for exact),
`methods` and `clients` (CIDRs); every condition set must hold. A route
can `deny` (`403` and the connection closed, before any bucket), add its
own bucket (`rate`, `burst`) keyed by the client, a request header or the
JA4, turn the challenge off with `challenge = false` for clients that
cannot run a script, and skip the WAF with `waf = false`.

Routes only tighten: the global bucket, detection and `fingerprint.deny`
still apply to every request. Each route's table holds at most
`max_keys` keys.

Keys: [`[[routes]]`](configuration.html#routes).

## WAF

With `[waf]`, each request that passed the limits goes to a
`coraza-spoa` sidecar (OWASP Coraza with the Core Rule Set) over SPOP, and
the agent's verdict blocks it (`403`) or forwards it ([RFC 0017](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0017-waf.md)).
Start in `observe`, add exclusions in the agent's config, then enforce.
The protection path fails closed: in enforce, an agent that does not
answer in `timeout` gets the request `503` unless `on_error = "pass"`.
See [WAF](waf.html).

Keys: [`[waf]`](configuration.html#waf).

## LLM labels

With `[ml.llm]` and at least one trigger, requests that hit a WAF rule,
fail a challenge, arrive during an attack, score in an uncertain `[ml]`
band or match a route are sampled, one per client and trigger in
`per_client`, and sent off the request path to an LLM ([RFC 0023](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0023-llm-labels.md)):
a System One decision model (`protocol = "systemone"`) or an
OpenAI-compatible chat model (`"chat"`). The answer is one of `labels`,
a confidence and a short pattern. Labels go to the logs, the
`dvarapala_llm_*` metrics, the console's LLM labels page and the
`export` file; they never change a verdict.

Sampling runs while the console switch is on (`admin.mode_switch`, at
most `max_duration`) or with `enabled = true`. `Cookie` and
`Authorization` are never sent, query values become `_`, and the body is
sent only with `body_bytes`. Use the labels to decide when the WAF can
leave `observe`, or to train the [scoring model](#scoring-model).

With `persist = true` and the PostgreSQL store, every replica writes its
labels as rows ([RFC 0024](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0024-llm-label-store.md)): the console's counts and recent
labels cover all replicas and survive restarts, rows older than
`retention` (30 days) are deleted, and `GET /llm/export` streams them as
JSON lines. A lost store is logged once and labels stay in memory.

Keys: [`[ml.llm]`](configuration.html#mlllm).

## Manual blocks

`POST /blocks?cidr=<net>&ttl=<duration>` on the admin API blocks a
network until the `ttl` ends: `403` and the connection closed before any
other check, and an XDP drop too when `[xdp]` is on. At most
`admin.max_blocks` blocks, each at most `admin.max_block_ttl` long. See
[Operations](operations.html).

Keys: [`[admin]`](configuration.html#admin).

## Across replicas

With a `[store]` (Redis or PostgreSQL, features `redis` and `postgres`),
replicas behind one load balancer hold one per-client limit instead of
one each, drop the heavy hitters any replica finds in `enforce` mode, and
in forward mode split each destination's budget. The request path never
waits for the store; a lost store falls back to local limits and logs
it. See [Clusters](clusters.html).

Keys: [`[store]`](configuration.html#store).

## TLS

Terminates TLS with rustls, negotiates `h2` or `http/1.1` by ALPN, reloads
the certificate on `SIGHUP`, and bounds how many handshakes run at once and
how long each may take, so a handshake flood costs bounded CPU.

Keys: [`[tls]`](configuration.html#tls),
[`[upstream_tls]`](configuration.html#upstream_tls).

## HTTP/3 over QUIC

An optional UDP listener (builds with the `http3` feature, off by
default) that serves HTTP/3 into the same rate limit, detection and
upstream. A spoofed-source flood of QUIC Initials must not cost
handshakes: once `retry_threshold` handshakes are in progress, new
clients must first echo a Retry token (one extra round trip, no state on
the server). `retry = "always"` asks every new client. Over
`max_connections`, new connections are refused before any crypto; each
connection gets `max_streams` concurrent requests. 0-RTT is off, so no
request is processed before the handshake ends. TCP responses advertise
the listener with `Alt-Svc`.

Volumetric UDP floods still need filtering at the network edge.

Keys: [`[quic]`](configuration.html#quic).

## HTTP/2

Limits that stop the cheap HTTP/2 attacks: rapid reset (streams opened and
cancelled), oversized header lists, and idle connections (keepalive).
Over a limit, the connection gets `GOAWAY`.

Keys: [`[http2]`](configuration.html#http2), `upstream_protocol`.

## WebSocket

The upgrade request goes through the rate limit and detection like any
request, so a reconnect storm is throttled. After the `101`, the tunnel
limits apply: `max_tunnels` in total (`503` above it), `idle_timeout`, and
`max_lifetime`, which makes long-lived clients reconnect through the
current limits once an attack starts.

Keys: [`[upgrade]`](configuration.html#upgrade).

## Metrics

Every layer reports on the metrics listener. The list is at the end of
[Configuration](configuration.html#metrics-1).
