# 0009: L4 connection limits and timeouts

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-28 | #44 | v0.5.0 |

> Limit connections before any HTTP is parsed: a cap on open connections
> per client and in total, a token bucket on new connections per client,
> and timeouts for connections that send nothing useful.

## Problem

Every protection today runs per request. A client that opens connections
and sends no request (or sends one byte a minute) never reaches the rate
limit, yet each connection holds a socket, a task and, with TLS, a
handshake. The gaps:

- **Connection floods**: one address can open thousands of connections;
  only the process descriptor limit stops it, and then every client is
  refused (`accept failed`, EMFILE).
- **Connect rate**: reconnecting for every request (or a SYN flood that
  completes handshakes) costs an accept and, with TLS, a full handshake.
  `tls.max_handshakes` bounds the work in progress, not who causes it.
- **Slow clients**: hyper's header read timeout (30 s, not configurable
  today) covers the first request only. An idle keep-alive connection,
  or a body sent one byte at a time, is held for ever.

RFC 0001 names this as the L4 milestone; RFC 0003 deferred per-IP
connection limits to it.

## Proposal

- A new `crates/l4` wraps the listener. Every accepted connection is
  checked before TLS or HTTP: over a limit, the socket is closed at once
  (no response, nothing to parse), counted and sampled in the log.
- **Per client**: at most `max_per_client` open connections, and new
  connections through a token bucket (`accept_rate`, `accept_burst`). The
  client is the peer address grouped by `prefix_v4` / `prefix_v6`, in a
  bounded table (`max_clients`, least recently seen evicted) like the L7
  limiter. `X-Forwarded-For` does not apply here: behind a load balancer,
  list it in `exempt` (or keep these limits off).
- **In total**: at most `max_connections` open; over it, new connections
  are closed before accept work grows, so the process keeps descriptors
  for clients already in.
- **Timeouts**:
  - `header_timeout`: the whole request head must arrive within it (the
    current hard-coded 30 s, now a key, applying to every request on the
    connection, not only the first).
  - `idle_timeout`: a keep-alive connection with no request in flight for
    this long is closed.
  - `min_body_rate`: a request body slower than this many bytes per second,
    measured over 10 s, is cut with `408`.
- Order on each connection: total cap, per-client cap and bucket, then TLS
  handshake (RFC 0003 limits), then HTTP with the timeouts and the L7
  chain. Cheapest check first.
- Embedded use: the decision lives in the engine (`conns.rs`), so the
  SDK of RFC 0008 exposes the same limits (`dv_conn_open` /
  `dv_conn_close` and the `l4.*` keys). This RFC is implemented before
  RFC 0008.
- Applies in reverse and forward mode (RFC 0007), cleartext and TLS.
  WebSocket tunnels count as connections until they close.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/conns.rs` | per-client open count plus the existing `Bucket`, in the existing bounded `Table`; decision with time as input |
| `crates/l4/src/limits.rs` | `ConnLimits`: check on accept, a guard that decrements on drop |
| `crates/l4/src/listener.rs` | listener wrapper used by `proxy::serve`, total cap, metrics |
| `crates/l4/src/body.rs` | body wrapper enforcing `min_body_rate` |
| `crates/proxy/src/server.rs` | uses the wrapper; header and idle timeouts on the hyper builder |
| `crates/dvarapala/src/config.rs` | the `[l4]` section |

### Configuration

| Key | Default | |
|---|---|---|
| `l4.enabled` | `true` | `false` keeps only the timeouts |
| `l4.max_connections` | `0` (off) | Open connections in total |
| `l4.max_per_client` | `256` | Open connections per client; `0` off |
| `l4.accept_rate` | `0` (off) | New connections per second per client |
| `l4.accept_burst` | `64` | Bucket size for `accept_rate` |
| `l4.prefix_v4` / `l4.prefix_v6` | `32` / `64` | Group clients by prefix |
| `l4.max_clients` | `100000` | Table capacity, least recently seen evicted |
| `l4.exempt` | `[]` | CIDRs never limited (load balancers, health checks) |
| `l4.header_timeout` | `"30s"` | Time to receive each request head |
| `l4.idle_timeout` | `"60s"` | Keep-alive connection idle for this long is closed; `"0s"` off |
| `l4.min_body_rate` | `0` (off) | Bytes per second, over a 10 s window |

The defaults that are on (`max_per_client` 256, the timeouts) are generous
enough for browsers and NAT; the rate limits start off.

### Logs and metrics

| | |
|---|---|
| `dvarapala_l4_connections_open` | open connections; compare with `max_connections` |
| `dvarapala_l4_rejected_total{reason}` | closed on accept: `total`, `per_client`, `rate` |
| `dvarapala_l4_timeouts_total{kind}` | `header`, `idle`, `body` |
| `dvarapala_l4_clients` | entries in the per-client table |
| `msg="connection limit"` | at most once per second, with the reason and the client prefix |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `max_per_client` 2, fake clock | 3 opens from one client, then one close and one open | open, open, refused, open | unit (`engine`) |
| 2 | `accept_rate` 10, burst 2 | 5 opens at t=0, 1 at t=100 ms | 2 accepted, 3 refused, then 1 accepted | unit |
| 3 | `prefix_v4` 24 | opens from 192.0.2.1 and 192.0.2.2, `max_per_client` 1 | second refused | unit |
| 4 | `max_clients` 2 | opens from 3 clients | table stays at 2, oldest evicted | unit |
| 5 | `exempt` 192.0.2.0/24 | 10 opens from 192.0.2.1, `max_per_client` 1 | all accepted | unit |
| 6 | `max_per_client` 2 | 3 TCP connects through `serve` | third closed with no bytes sent, `rejected_total{reason=per_client}` 1 | integration (`l4/tests`) |
| 7 | `max_connections` 2 | 3 connects from different clients | third closed | integration |
| 8 | closed connection | after close | its place is free again | integration |
| 9 | `header_timeout` 1 s | a second request head sent slowly on a keep-alive connection | connection closed after 1 s | integration |
| 10 | `idle_timeout` 1 s | keep-alive connection with nothing sent | closed after about 1 s | integration |
| 11 | `min_body_rate` 1000 | body sent at 10 bytes per second | `408` | integration |
| 12 | TLS listener, `max_per_client` 1 | second TLS connect | closed before the handshake, `tls_handshakes_total` unchanged | integration |
| 13 | open WebSocket tunnel, `max_per_client` 1 | a second connect | refused until the tunnel closes | integration |
| 14 | 100000 clients | memory of the table | per-entry cost reported, within the budget below | bench |

## Implementation notes

Found while building, folded back from the PRs:

- `Table::entry` gives the bucket and the open count of a prefix in one
  lookup; `take` is built on it. The per-client cap is checked before the
  accept bucket, so a connection refused for the cap spends no token.
- `max_connections` is an atomic counter in `l4`, not in the engine: it
  has no key. Exempt connections count toward it but not per client.
- The listener's `accept` loops over refused streams, so `serve` only
  ever sees admitted ones. `serve` and `serve_tls` take
  `impl Into<Listener>`: a bare `TcpListener` gets no limits and the
  default timeouts.
- Idle means no bytes either way and no request in flight; a request is
  in flight until its response body ends, so a quiet streaming response
  (gRPC, server-sent events) is not cut. The watcher ends with the HTTP
  connection: an upgraded tunnel keeps only its RFC 0005 idle limit, but
  still holds its place.
- hyper restarts the header read timer for every head on a keep-alive
  HTTP/1.1 connection, so between requests the lower of `header_timeout`
  and `idle_timeout` closes it. A header timeout is counted from hyper's
  `is_timeout`, which on the server side is only that timer.
- `min_body_rate` windows start at the first poll of the body. The server
  puts a `BodyRate` extension on each request, and both proxies wrap the
  body they send upstream; the cut surfaces as an upstream error that
  maps to `408`. Other services behind `serve` see the extension and can
  wrap bodies themselves.
- Cases 9 to 13 live in `crates/proxy/tests` (`l4.rs`, `l4_tls.rs`): in
  `l4/tests` they would need the proxy as a dev-dependency of its own
  dependency.
- Case 14 (`cargo bench -p dvarapala-l4 --bench conns_table`) counts heap
  bytes with a counting allocator: about 106 bytes per client at 100000
  clients, budget 160.
- The `connection limit` log names the client address, not the prefix.

## Alternatives

| Option | Why not |
|---|---|
| Leave it to the kernel (`iptables connlimit`, `nftables` meters) | Linux-only and outside the config; the XDP RFC will cover packets, this covers the userspace listener everywhere |
| Respond `429` or `503` on refusal | needs TLS and HTTP first, the work the limit exists to avoid |
| Key by `X-Forwarded-For` | not available before HTTP parsing; behind a load balancer the peer is the balancer, so it is exempt |
| One table shared with the L7 limiter | different keys (prefix vs client), different lifetimes; two bounded tables are simpler |
| Unbounded per-client map | a spoofed-source flood grows it; the bounded `Table` is already there |

## Security and resource limits

- The attacker controls the source address (spoofable only with a
  completed TCP handshake, so real addresses or SYN cookies) and the
  connection timing.
- Memory: one table entry per client prefix (count, bucket, links, a few
  dozen bytes), capped by `max_clients`; 100000 entries is a few MB.
- CPU per refused connection: one table lookup and a close, no handshake.
- Fail closed: a refused connection is closed, never served past a limit.
  Eviction of a client resets its count; its open connections still
  decrement safely (the guard holds the key, a missing entry is a no-op).

## Rollout

- **Rollout:** v0.5.0. `max_per_client` 256 and the timeouts are on by default,
  generous for normal traffic; the release notes call out the new
  defaults. Deployments behind a load balancer set `exempt`.
- **Off switch:** `l4.enabled = false` (timeouts stay, at the old 30 s
  header value and no idle or body limit when set to `"0s"` / `0`).
