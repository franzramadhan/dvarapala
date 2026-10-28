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
  l4         connection caps, accept rate, timeouts -> close
    |
    v
  listener   TCP or TLS (ALPN h2, http/1.1), bounded handshakes;
    |        or QUIC (HTTP/3, Retry under load)
    v
  identity   peer address, or X-Forwarded-For from a trusted proxy
    |
    v
  rate limit token bucket per client          -> 429 + Retry-After
    |
    v
  detection  heavy hitters, baseline, entropy -> observe: log only
    |                                            enforce: 403, slower buckets
    v
  proxy      HTTP/1.1, HTTP/2 (h2c or ALPN) or a WebSocket tunnel
    |
    v
  upstream
```

Local errors on a gRPC request come back gRPC-shaped (HTTP 200 with
`grpc-status`), so clients see a status code instead of a broken stream.

## Crates

| Crate | Role |
|---|---|
| `engine` | Verdicts, token buckets, detection sketches. No I/O, no async runtime, so it can embed anywhere |
| `l4` | Listener wrapper: connection caps, accept rate, header, idle and body timeouts |
| `l7` | `tower` layers that run the engine on each request |
| `proxy` | Server loop, TLS, HTTP/2 limits, HTTP/3 over QUIC, reverse and forward proxy, WebSocket and `CONNECT` tunnels |
| `ffi` | C ABI (`dvarapala.h`) over the engine, for the SDKs |
| `node` | N-API addon over the C ABI for the JavaScript SDK |
| `dvarapala` | The binary: config, metrics endpoint, signals |

Dependencies point inward: the binary and `ffi` depend on the rest,
`engine` on no other workspace crate. More crates arrive with the RFC that
needs them: `store` with RFC 0010 (shared state across replicas) and
`xdp` with RFC 0011 (XDP fast path), both accepted.

## Modes

| Mode | Entry point | Status |
|---|---|---|
| Reverse proxy | `dvarapala serve --config <file>` | shipped |
| Forward proxy | `mode = "forward"`: egress rate shaping toward third-party APIs, see [Forward proxy](forward-proxy.html) | shipped |
| Embedded (Rust) | `tower::Layer` and a listener wrapper | shipped |
| Embedded (other) | C ABI with Go, Python and JavaScript packages, see [SDKs](sdk.html) | shipped |

## Failure policy

The protection path fails closed: when a limit cannot be decided, the
request does not pass. It fails open only where an RFC says so, and logs
it. Shutdown drains in-flight requests and open tunnels for up to 30 s.

## Stack

Rust for a small footprint without a GC and memory safety at the trust
boundary: `tokio`, `hyper`, `tower`, `rustls`, `quinn` and `h3` (feature
`http3`), and `metrics` with the
Prometheus exporter. The idle binary has an RSS budget that CI checks on
every change.
