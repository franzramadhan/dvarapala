---
title: Architecture
---

One engine, several entry points. The protection logic lives in the
`engine` crate, which decides a verdict for a connection or a request and
does no I/O. The proxy and the binary are thin wrappers that feed it and
carry out what it decides.

## Request path

```
  client
    |
    v
  xdp        block list, per-source packet and SYN rates -> drop
    |        (optional, Linux, in the NIC driver)
    v
  l4         connection caps, accept rate, timeouts -> close
    |
    v
  listener   TCP or TLS (ALPN h2, http/1.1), bounded handshakes,
    |        JA4 of the ClientHello; or QUIC (HTTP/3, Retry under load)
    v
  identity   peer address, or X-Forwarded-For from a trusted proxy
    |
    v
  blocks     manual blocks from the admin API -> 403, connection closed
    |
    v
  ja4 rules  fingerprint deny -> 403, challenge -> needs a pass
    |
    v
  routes     first match on host, path, method, client: deny -> 403,
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
  pool       round robin or least requests over healthy endpoints,
    |        budgeted retry of an idempotent request on a connect error
    v
  proxy      HTTP/1.1, HTTP/2 (h2c or ALPN) or a WebSocket tunnel
    |
    v
  upstream
```

With `[pool]` ([RFC 0015](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0015-upstream-pools.md)),
one pool serves the TCP and HTTP/3 listeners. Active health checks and
passive ejection after consecutive errors take an endpoint out until it
passes a check again. With every endpoint out the pool still picks one
and counts it as degraded, so a wrong health check is not an outage.
Without `[pool]`, `upstream` is a pool of one with no checks.

The admin API ([Operations](operations.html)) runs on its own listener,
next to the metrics one, and changes the running policy in place.

Local errors on a gRPC request come back gRPC-shaped (HTTP 200 with
`grpc-status`), so clients see a status code instead of a broken stream.

## Crates

| Crate | Role |
|---|---|
| `engine` | Verdicts, token buckets, detection sketches. No I/O, no async runtime, so it can embed anywhere |
| `l4` | Listener wrapper: connection caps, accept rate, header, idle and body timeouts |
| `l7` | `tower` layers that run the engine on each request |
| `proxy` | Server loop, TLS, HTTP/2 limits, HTTP/3 over QUIC, reverse and forward proxy, WebSocket and `CONNECT` tunnels |
| `store` | Shared state backends (memory, Redis, PostgreSQL) and the background sync |
| `xdp` | XDP loader (`aya`), dynamic block list, the checked-in eBPF object |
| `xdp-common` | `no_std` packet parser and map layouts shared by the loader and the program |
| `xdp-ebpf` | The eBPF program, its own workspace on a pinned nightly |
| `ffi` | C ABI (`dvarapala.h`) over the engine, for the SDKs |
| `node` | N-API addon over the C ABI for the JavaScript SDK |
| `dvarapala` | The binary: config, metrics endpoint, signals |

Dependencies point inward: the binary and `ffi` depend on the rest,
`engine` on no other workspace crate. More crates arrive with the RFC that
needs them.

## Clusters

Replicas share state through a store ([RFC 0010](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0010-shared-state.md)),
never on the request path: each replica decides from local state and a
background task syncs every `sync_interval`. See [Clusters](clusters.html).

## Modes

| Mode | Entry point | Status |
|---|---|---|
| Reverse proxy | `dvarapala serve --config <file>` | shipped |
| Forward proxy | `mode = "forward"`: egress rate shaping toward third-party APIs, see [Forward proxy](forward-proxy.html) | shipped |
| Embedded (Rust) | `tower::Layer` and a listener wrapper | shipped |
| Embedded (other) | C ABI with Go, Python and JavaScript packages, see [SDKs](sdk.html) | shipped |
| Cluster | Any proxy mode with `[store]`: replicas share limits, see [Clusters](clusters.html) | shipped |

## Failure policy

The protection path fails closed: when a limit cannot be decided, the
request does not pass. It fails open only where an RFC says so, and logs
it: a lost store falls back to local limits. Shutdown drains in-flight requests and open tunnels for up to 30 s.

## Stack

Rust for a small footprint without a GC and memory safety at the trust
boundary: `tokio`, `hyper`, `tower`, `rustls`, `quinn` and `h3` (feature
`http3`), `redis` and `tokio-postgres` (features `redis`, `postgres`),
`aya` (feature `xdp`), and `metrics` with the
Prometheus exporter. The idle binary has an RSS budget that CI checks on
every change.
