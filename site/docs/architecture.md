---
title: Architecture
---

dvarapala has one engine and several entry points. The `engine` crate holds
the protection logic. It decides a verdict (allow, throttle, challenge or drop)
for a connection or a request, and it does no I/O. The proxy and the binary are
thin wrappers that feed the engine and carry out its decisions.

## Request path

```
  client
    |
    v
  xdp        block list, per-source packet and SYN rates -> drop
    |        (optional, Linux, in the NIC driver)
    v
  l4         total cap, PROXY header from trusted     -> close
    |        balancers, per-client caps, accept rate, timeouts
    v
  listener   TCP or TLS (ALPN h2, http/1.1), bounded handshakes,
    |        JA4 of the ClientHello; or QUIC (HTTP/3, Retry under load)
    v
  identity   peer address (or the PROXY header's), X-Forwarded-For
    |        from a trusted proxy; country and ASN from intel.geoip
    v
  blocks     manual blocks from the admin API -> 403, connection closed
    |
    v
  feeds      reputation feeds in enforce: deny -> 403, challenge ->
    |        needs a pass, tag -> route condition only
    v
  ja4 rules  fingerprint deny -> 403, challenge -> needs a pass
    |
    v
  routes     first match on host, path, method, client, country,
    |        ASN, feed: deny -> 403,
    |        own bucket -> 429, challenge exemption
    v
  rate limit token bucket per client          -> 429 + Retry-After
    |
    v
  detection  heavy hitters, baseline, entropy -> observe: log only
    |                                            enforce: 403, slower buckets
    v
  challenge  no pass during an attack (or always) -> proof-of-work page,
    |        then a signed cookie and the normal limit
    v
  model      optional XGBoost score of the client's -> 429 + Retry-After
    |        features, only when every stage above allowed
    v
  waf        optional coraza-spoa sidecar over SPOP  -> observe: log only
    |        (OWASP CRS), body up to max_body           enforce: 403
    v
  concurrency requests in flight to the upstream over  -> 503 + Retry-After
    |        the fixed or latency-learned limit, trusted
    |        clients (pass, low score) admitted first
    v
  pool       round robin or least requests over healthy endpoints,
    |        budgeted retry of an idempotent request on a connect error
    v
  proxy      HTTP/1.1, HTTP/2 (h2c or ALPN) or a WebSocket tunnel
    |
    v
  upstream
```

With `[pool]` ([RFC 0015](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0015-upstream-pools.md)),
one pool serves the TCP and HTTP/3 listeners. Active health checks, and
passive ejection after consecutive errors, take an endpoint out of the
pool. The endpoint stays out until it passes a check again. If every
endpoint is out, the pool still picks one and counts it as degraded. Thus
a wrong health check does not cause an outage. Without `[pool]`,
`upstream` is a pool of one with no checks.

The admin API and its web console ([Operations](operations.html)) run on
their own listener, next to the metrics listener. They change the running
policy in place.

With `[ml]` ([RFC 0002](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0002-adaptive-detection.md)),
the model runs in the rate limiter, under the same lock as the bucket of
the client. It runs only after the bucket, detection and challenge all
allowed the request. Only those requests update the features of the
client, so a throttled client does not feed its own score. The score costs
one walk of the trees in the process, with no I/O.

LLM labels ([RFC 0023](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0023-llm-labels.md))
are not a stage. Samples go to a queue, and the LLM answers off the
request path. The LLM never changes a verdict. See [Learned scoring](ml.html).

With `[waf]` ([RFC 0017](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0017-waf.md)), the agent is a separate
process. You can change its rules without a new dvarapala build, and its
memory and CPU stay out of the proxy. See [WAF](waf.html).

With `l4.proxy_protocol` ([RFC 0030](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0030-proxy-protocol.md)),
every later stage keys on the client address in the PROXY header. That
header must come from a balancer in `l4.proxy_protocol_from`. While this
option is on, the rate limiter sends no dynamic blocks to XDP. The packets
of a carried client come from the balancer, so XDP cannot tell a blocked
address apart.

Reputation feeds ([RFC 0031](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0031-network-intel.md))
refresh off the request path. If a refresh fails, dvarapala keeps the last
good list. Thus an outage of a third-party list changes no verdict.

With `[concurrency]` ([RFC 0032](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0032-adaptive-concurrency.md)),
a shed request (one refused at once with `503`) never reaches the pool. It
does not count toward ejection, and it does not use the retry budget.

Local errors on a gRPC request come back in gRPC form (HTTP 200 with
`grpc-status`). Thus clients see a status code instead of a broken stream.

## Crates

| Crate | Role |
|---|---|
| `engine` | Verdicts, token buckets, detection sketches, route matching. No I/O, no async runtime, so it can embed anywhere |
| `l4` | Listener wrapper: connection caps, accept rate, header, idle and body timeouts |
| `l7` | `tower` layers that run the engine on each request |
| `proxy` | Server loop, TLS, HTTP/2 limits, HTTP/3 over QUIC, reverse and forward proxy, WebSocket and `CONNECT` tunnels |
| `store` | Shared state backends (memory, Redis, PostgreSQL) and the background sync |
| `xdp` | XDP loader (`aya`), dynamic block list, the checked-in eBPF object |
| `xdp-common` | `no_std` packet parser and map layouts shared by the loader and the program |
| `xdp-ebpf` | The eBPF program, its own workspace on a pinned nightly |
| `ffi` | C ABI (`dvarapala.h`) over the engine, for the SDKs |
| `node` | N-API addon over the C ABI for the JavaScript SDK |
| `dvarapala` | The binary: configuration, metrics endpoint, signals |
| `operator` | Kubernetes operator: the `DvarapalaPolicy` CRD, the route rewrite webhook and the gateway controller |

Dependencies point inward. The binary and `ffi` depend on the rest, and
`engine` depends on no other workspace crate. New crates arrive with the
RFC that needs them.

## Clusters

Replicas share state through a store ([RFC 0010](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0010-shared-state.md)),
but never on the request path. Each replica decides from local state, and
a background task syncs the state every `sync_interval`. See
[Clusters](clusters.html).

## Modes

| Mode | Entry point | Status |
|---|---|---|
| Reverse proxy | `dvarapala serve --config <file>` | shipped |
| Forward proxy | `mode = "forward"`: egress rate shaping toward third-party APIs, see [Forward proxy](forward-proxy.html) | shipped |
| Embedded (Rust) | `tower::Layer` and a listener wrapper | shipped |
| Embedded (other) | C ABI with Go, Python and JavaScript packages, see [SDKs](sdk.html) | shipped |
| Cluster | Any proxy mode with `[store]`: replicas share limits, see [Clusters](clusters.html) | shipped |
| Kubernetes | `dvarapala-operator` runs a reverse proxy gateway per labeled route's Service, see [Kubernetes](kubernetes.html) | shipped |

## Failure policy

The protection path fails closed: if dvarapala cannot decide a limit, the
request does not pass. It fails open only where an RFC says so, and it
logs the event. A lost store falls back to local limits and keeps LLM
labels in memory. With `waf.on_error = "pass"`, dvarapala forwards the
request when the WAF agent fails.

On Kubernetes, a new gateway passes traffic straight to the application
until its first pod is ready. After that, it never does so again: if no
gateway pod is ready, the answer is `503`. At shutdown, dvarapala drains
in-flight requests and open tunnels for up to 30 s.

## Stack

dvarapala uses Rust for a small footprint without a garbage collector and
for memory safety at the trust boundary. The stack is
`tokio`, `hyper`, `tower`, `rustls`, `quinn` and `h3` (feature `http3`),
`redis` and `tokio-postgres` (features `redis`, `postgres`), `aya`
(feature `xdp`), `kube` (the operator), and `metrics` with the Prometheus
exporter. The idle binary has an RSS budget, and CI checks it on every
change.
