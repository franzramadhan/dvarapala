# 0036: Per-client QUIC connection limits

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-11-09 | #342 | |

> The QUIC listener gets the per-client open-connection cap and new-connection rate that the TCP listener has had since RFC 0009. Both are counted on the validated client address, so one client cannot take every HTTP/3 connection slot.

## Problem

RFC 0006 limits QUIC in total only: `quic.max_connections` (default `10000`) is checked in `crates/proxy/src/quic/endpoint.rs` against all open connections. The per-client limits of RFC 0009 (`l4.max_per_client`, `l4.accept_rate`) wrap the TCP listener only.

One host with a real address passes Retry, opens 10000 connections and keeps each one alive with PINGs under `quic.idle_timeout` (30 s). It costs the attacker 10000 handshakes from one source. After that, every new HTTP/3 client is refused before its handshake:

- Browsers fall back to TCP only after QUIC fails, so every visitor pays extra latency until `Alt-Svc` expires.
- Clients set up for HTTP/3 only lose the service.
- The L7 limiter never sees these connections, because they send no request.

An anti-DDoS gateway should not let one address take a shared resource that a per-client limit can protect.

## Proposal

- `quic.max_per_client` (default `256`, `0` off): open QUIC connections per client. A new connection over it is refused.
- `quic.accept_rate` (default `0`, off) and `quic.accept_burst` (default `64`): new QUIC connections per second per client, as a token bucket, like `l4.accept_rate`.
- Clients are grouped by `l4.prefix_v4` and `l4.prefix_v6`, in a table of at most `l4.max_clients` entries with the least recently seen client evicted. The table is separate from the TCP one, so the two budgets do not mix.
- A connection is counted only on a validated address. When the Initial carries a valid Retry token (`remote_address_validated`), it is counted at accept and refused with `CONNECTION_REFUSED` before any crypto. Otherwise it is counted when the handshake completes, and over the limit it is closed with `H3_EXCESSIVE_LOAD` before any request is read. A spoofed source never takes a place from the real address.
- `quic.max_connections` and Retry work as today and are checked first.
- The place is held until the connection closes. After a migration it stays with the address it was counted on; the request key still moves as RFC 0006 says.
- The keys are read at start; a reload does not change them.
- Out of scope: reporting clients over the accept rate to the XDP block list (RFC 0011), and per-client stream limits.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/proxy/src/quic/limits.rs` | the per-client table over the engine's `Conns`, a guard held by the connection task, refusal counting and logging |
| `crates/proxy/src/quic/endpoint.rs` | counting at accept (validated by Retry) or after the handshake, refusing or closing |
| `crates/proxy/src/quic/config.rs` | `max_per_client`, `accept_rate`, `accept_burst` and the grouping in `QuicConfig` |
| `crates/dvarapala/src/config/quic.rs` | the `[quic]` keys and their checks |

### Configuration

| Key | Default | |
|---|---|---|
| `quic.max_per_client` | `256` | Open QUIC connections per client; `0` off |
| `quic.accept_rate` | `0` (off) | New QUIC connections per second per client |
| `quic.accept_burst` | `64` | Bucket size for `quic.accept_rate`; at least 1 |

Grouping and table capacity come from `l4.prefix_v4`, `l4.prefix_v6` and `l4.max_clients`.

### Logs and metrics

| | |
|---|---|
| `dvarapala_quic_rejected_total{reason}` | `per_client` or `rate`: connections refused or closed by these limits |
| `dvarapala_quic_clients` | entries in the QUIC per-client table |
| `msg="quic connection limit"` | at most one line a second, with the reason and the client |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `max_per_client = 2`, `retry = "always"`, 2 connections open from 192.0.2.10 | a third connection from the same address | refused before the handshake, `dvarapala_quic_rejected_total{reason="per_client"}` is 1 | integration (`proxy/tests`) |
| 2 | same, 2 open from 192.0.2.10 | a connection from 192.0.2.11 | accepted, HTTP/3 GET answered | integration |
| 3 | `max_per_client = 2`, `retry = "never"` | a third connection from one address completes its handshake | closed with `H3_EXCESSIVE_LOAD`, the upstream not called | integration |
| 4 | `max_per_client = 2`, 2 open | one closes, then a new connection | accepted | integration |
| 5 | `accept_rate = 1`, `accept_burst = 2` | 3 new connections from one address within 1 s | the third refused with `reason="rate"` | integration |
| 6 | `retry = "under_load"` below the threshold | Initials with a spoofed source | no place counted for that address before a handshake completes | unit (`quic/limits`) |
| 7 | `max_per_client = 0`, `accept_rate = 0` | many connections from one address | only `max_connections` applies, as today | integration |
| 8 | `l4.prefix_v6 = 64` | connections from 2001:db8::1 and 2001:db8::2 | counted as one client | unit |
| 9 | table at `l4.max_clients` | a new client | least recently seen client evicted, gauge unchanged | unit |
| 10 | a counted connection migrates to a new address | it closes | the place of the original address is freed | integration |
| 11 | `accept_burst = 0` | start | config error naming `quic.accept_burst` | unit (`config`) |
| 12 | `[quic]` with the new keys | `CONFIG.md` and `examples/dvarapala.toml` | every key and metric listed | unit (docs check) |
| 13 | 10000 clients in the table | open and close in a loop | under the RFC 0009 cost per connection | bench (`quic_conns`) |

## Alternatives

| Option | Why not |
|---|---|
| Reuse `l4.max_per_client` and `l4.accept_rate` for QUIC | a browser opens one QUIC connection where it opens up to six TCP ones; an operator needs separate budgets, and may want one limit without the other |
| One table shared by TCP and QUIC | a client's HTTP/3 connections would use up its TCP budget and the reverse |
| Count at accept for every Initial | before validation the source can be spoofed, and a flood would use up a victim's places |
| Rely on XDP packet rates | XDP counts packets, while a client holding idle connections sends very few |

## Security and resource limits

- The attacker controls the source address of every Initial. Before validation it is not counted, so only `quic.max_connections` and Retry (RFC 0006) apply, as today.
- After validation the address is real. One table entry per client prefix, at most `l4.max_clients` entries, with the least recently seen evicted; the cost per entry is the RFC 0009 one (about 106 bytes).
- Each check is one table lookup under a lock, once per new connection, never per packet.
- An evicted client's count starts again, as in RFC 0009. A client can win back places only by outlasting `l4.max_clients` other clients.

## Rollout

- **Rollout:** v0.24.0. `quic.max_per_client = 256` changes behavior only for a client holding more than 256 HTTP/3 connections. `quic.accept_rate` stays off. `CONFIG.md` and `examples/dvarapala.toml` are updated in the implementation.
- **Off switch:** `quic.max_per_client = 0` and `quic.accept_rate = 0`.
