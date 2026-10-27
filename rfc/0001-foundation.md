# 0001: Foundation

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-27 | #1 | v0.1.0 |

> Set the architecture (one I/O-free verdict engine, thin entry points) and
> ship the first usable slice: per-client L7 rate limiting in front of a
> reverse proxy, as one static binary.

## Problem

Small services need protection against floods and abusive clients without a
CDN or a heavy WAF. Existing options are either large (Envoy, NGINX plus
modules), tied to one vendor, or only a library for one language. Dvarapala
targets a single static binary that idles at a few MB of memory, and the same
engine embedded in-process.

## Proposal

### Architecture

- One `engine` crate decides a verdict for a request or connection:
  `Allow`, `Throttle { retry_after }`, `Challenge` or `Drop`. It has no I/O
  and no async runtime, and takes the current time as an input, so tests
  are deterministic.
- Entry points wrap the engine and never hold protection logic:
  the binary (reverse proxy now, forward proxy later), a `tower::Layer` for
  Rust services, and a C ABI for other languages.
- Layers run in order, cheapest first: XDP (later), L4 listener, L7
  middleware chain, proxy.

### This RFC ships (v0.1.0)

- `dvarapala serve --config <file>`: reverse proxy to one upstream.
- Per-client token bucket at L7. The client key is the peer IP, or the
  first untrusted hop of `X-Forwarded-For` when the peer is in
  `trusted_proxies`.
- Over the limit: `429 Too Many Requests` with `Retry-After`. The request
  never reaches the upstream.
- Bounded state: the limiter table has a fixed capacity and evicts the
  least recently seen client, so a spoofed-IP flood cannot exhaust memory.
- `/metrics` on a separate listen address (Prometheus text format).

Later milestones are separate RFCs: L4 connection limits and timeouts, the
SDK surface (`tower` layer and C ABI), forward proxy, challenges and TLS
fingerprints, Redis shared state, XDP.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/verdict.rs` | `Verdict` type |
| `crates/engine/src/bucket.rs` | token bucket math, time as input |
| `crates/engine/src/table.rs` | bounded per-key limiter table, LRU eviction |
| `crates/engine/src/key.rs` | client key from peer address and trusted proxies |
| `crates/l7/src/rate_limit.rs` | `tower::Layer` that calls the engine, maps a verdict to a response |
| `crates/proxy/src/reverse.rs` | `hyper` reverse proxy to one upstream |
| `crates/dvarapala/src/config.rs` | TOML file plus `DVARAPALA__*` environment overrides |
| `crates/dvarapala/src/metrics.rs` | Prometheus endpoint |
| `crates/dvarapala/src/main.rs` | CLI, wiring, graceful shutdown |

### Configuration

| Key | Default | |
|---|---|---|
| `listen` | `0.0.0.0:8080` | Proxy listen address |
| `upstream` | none, required | Upstream base URL |
| `metrics.listen` | `127.0.0.1:9090` | Metrics address; empty turns it off |
| `rate_limit.enabled` | `true` | Turn the limiter off |
| `rate_limit.rate` | `20` | Tokens refilled per second per client |
| `rate_limit.burst` | `40` | Bucket size |
| `rate_limit.max_clients` | `100000` | Table capacity before eviction |
| `trusted_proxies` | `[]` | CIDRs allowed to set `X-Forwarded-For` |

### Logs and metrics

| | |
|---|---|
| `dvarapala_requests_total{verdict}` | Requests by verdict |
| `dvarapala_limiter_clients` | Clients in the limiter table |
| `dvarapala_limiter_evictions_total` | Evictions; a steady rise means capacity is too small or a spoofed flood |
| `dvarapala_upstream_errors_total` | Upstream connect or response failures |
| `msg=throttled key=<ip>` | Debug level only, sampled, so a flood does not flood the logs |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | bucket rate 1/s, burst 2, full | 3 takes at t=0 | allow, allow, throttle with `retry_after` 1s | unit (`bucket`) |
| 2 | empty bucket, rate 10/s | take at t=+100ms | allow | unit (`bucket`) |
| 3 | bucket idle for 1 hour | take | tokens capped at burst, not rate times elapsed | unit (`bucket`) |
| 4 | clock moves backwards | take | no panic, no token gain | unit (`bucket`) |
| 5 | table capacity 2 with keys A, B | key C arrives | least recently seen key evicted, len stays 2 | unit (`table`) |
| 6 | 1M distinct keys | each takes once | memory bounded by capacity | unit (`table`) |
| 7 | peer 192.0.2.10 not trusted, XFF set | derive key | key is 192.0.2.10, XFF ignored | unit (`key`) |
| 8 | peer 192.0.2.1 trusted, XFF `198.51.100.7, 192.0.2.1` | derive key | key is 198.51.100.7 | unit (`key`) |
| 9 | malformed XFF | derive key | falls back to peer address | unit (`key`), fuzz |
| 10 | IPv6 client 2001:db8::1 | derive key | keyed per /64 | unit (`key`) |
| 11 | layer with burst 1 | 2 requests from one client | 200 then 429 with `Retry-After` | integration (`l7`) |
| 12 | throttled request | layer rejects | inner service not called | integration (`l7`) |
| 13 | proxy to a test upstream | GET with body and headers | upstream sees them, hop-by-hop headers removed | integration (`proxy`) |
| 14 | upstream down | request | 502, `dvarapala_upstream_errors_total` +1 | integration (`proxy`) |
| 15 | config file plus `DVARAPALA__RATE_LIMIT__RATE=5` | load | rate is 5 | unit (`config`) |
| 16 | config without `upstream` | load | error names the missing key | unit (`config`) |
| 17 | idle binary | RSS after start | under 10 MB | bench |

## Alternatives

| Option | Why not |
|---|---|
| Go | GC and a larger idle footprint; the goal is a few MB |
| Zig | pre-1.0, no mature async HTTP/2 and TLS stack |
| Pingora as the base | strong, but large; the C ABI and small binary goals favor a thin `hyper` core |
| Module for NGINX or Envoy | ties the project to one host and drops the standalone and embedded modes |
| Sliding window log | exact, but memory grows with request rate per client |

## Security and resource limits

- The attacker controls the source address, `X-Forwarded-For`, and the
  request rate. Spoofed addresses are bounded by `max_clients`;
  `X-Forwarded-For` is read only from trusted peers.
- IPv6 clients are keyed per /64 so one host cannot rotate addresses to
  dodge the limit.
- Engine memory is O(`max_clients`); per-request work is O(1).
- No request body is buffered by the limiter.

## Rollout

- **Rollout:** first release, v0.1.0, alpha.
- **Off switch:** `rate_limit.enabled = false` turns dvarapala into a plain
  reverse proxy.
