# 0014: Admin API and config reload

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-29 | #112 | |

> An authenticated admin listener to see the state, block a network by
> hand and reload the config file, and `SIGHUP` reloading the protection
> keys without a restart, so an operator can react to an attack in
> seconds without dropping connections.

## Problem

During an attack the operator's levers today are a config edit and a
restart:

- A restart drops every open connection and WebSocket tunnel, and empties
  the limiter table and the detector's baseline, so the gateway is blind
  for `warmup_windows` right when it matters.
- Moving detection from `observe` to `enforce`, lowering `rate_limit.rate`,
  turning the challenge on or adding a route all need that restart.
- There is no way to block a network by hand. The XDP block list (RFC
  0011) and the cluster drop list (RFC 0010) are fed by detection only.
- The state (detection state, heavy hitters, table size) is in metrics,
  which need a Prometheus to read; there is no direct answer to "who is
  attacking right now".

## Proposal

- `SIGHUP` re-reads the config file (and, as today, the TLS pair). The
  protection keys are applied in place; a key that needs a restart is
  logged and keeps its running value. A config that fails to load or
  validate is rejected whole and the running one stays.
- An admin listener, off by default (`admin.listen`), plain HTTP/1.1 with
  JSON answers, every request authenticated with
  `Authorization: Bearer <admin.token>`:
  - `GET /status`: version, mode, detection state, clients in the table,
    manual blocks, the last reload and its result.
  - `POST /reload`: the same as `SIGHUP`; answers what was applied and
    what needs a restart.
  - `GET /top`: the heavy hitters of the last closed window with their
    counts.
  - `GET /blocks`, `POST /blocks?cidr=<net>&ttl=<duration>`,
    `DELETE /blocks?cidr=<net>`: manual blocks. A blocked network gets
    `403` and the connection closed in the reverse proxy, before any
    bucket, and goes to the XDP block list when `[xdp]` is on.
- Reloaded in place: `rate_limit.rate`, `rate_limit.burst`,
  `trusted_proxies`, `detection.mode`, `detection.attack_rate_factor`,
  `[challenge]`, `[fingerprint]` (rules and header; turning JA4 on at the
  TLS listener needs a restart) and `[[routes]]`. Clients keep their
  buckets and the detector keeps its baseline. Route tables start empty
  after a reload that changes the routes.
- Everything else (listeners, `upstream`, `mode`, `[tls]` paths, `[l4]`,
  `[quic]`, `[store]`, `[xdp]`, `[metrics]`, `[admin]`) needs a restart.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/guard.rs` | `Guard::retune`: new limits, attack factor, enforce and challenge mode, table and detector kept |
| `crates/engine/src/blocks.rs` | `Blocks`: manual blocks with expiry, bounded |
| `crates/l7/src/rate_limit.rs` | the block check first, the policy read once per request |
| `crates/l7/src/control.rs` | `Policy`, `RateLimitLayer::reload(Reload)`, `block`, `unblock`, `blocks`, `status`, `top` |
| `crates/l7/src/admin.rs` | admin request parsing and the bearer check, apart from serving so the fuzz target reaches it |
| `crates/dvarapala/src/reload.rs` | read, validate, split the new config into applied keys and restart keys |
| `crates/dvarapala/src/admin.rs` | the admin listener: auth, endpoints, JSON |

### Configuration

| Key | Default | |
|---|---|---|
| `admin.listen` | `""` | `"127.0.0.1:9091"` turns the admin API on; empty is off |
| `admin.token` | `""` | bearer token, at least 32 bytes, required when `listen` is set; set it with `DVARAPALA__ADMIN__TOKEN` |
| `admin.max_blocks` | `4096` | manual blocks at most; a block over it is refused with `507` |
| `admin.max_block_ttl` | `"24h"` | longest `ttl` a block may ask for, also the default |

### Logs and metrics

| | |
|---|---|
| `msg="config reloaded"` / `msg="config reload failed"` | the outcome, with `restart` naming keys that kept their running value |
| `dvarapala_config_reloads_total{result}` | `ok`, `failed` |
| `dvarapala_admin_requests_total{endpoint,status}` | admin calls, `401` included |
| `dvarapala_blocks` | manual blocks in force |
| `dvarapala_requests_total{verdict="drop",scope="block"}` | requests refused by a manual block |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | a guard with clients in its table, `rate = 10` | `retune` to `rate = 1` | the same clients, the next refill at 1/s | unit (`engine::guard`) |
| 2 | a detector in `Attack`, observe | `retune` with enforce | heavy hitters dropped on the next request, baseline kept | unit (`engine::guard`) |
| 3 | blocks with `max = 2` | add three, add one past its expiry | the third refused, the expired one gone | unit (`engine::blocks`) |
| 4 | a block on `192.0.2.0/24` | requests from `.7` and `198.51.100.7` | `403` + close, then the inner service | integration (`l7/tests`) |
| 5 | a layer at `rate = 100` | `reload` with `rate = 1` | the second request `429`; no client lost | integration (`l7/tests`) |
| 6 | a layer without routes | `reload` adding a deny route | matching requests `403` | integration (`l7/tests`) |
| 7 | a running config | reload a file with `rate_limit.rate` and `listen` changed | rate applied, `listen` in the restart list | unit (`dvarapala::reload`) |
| 8 | a running config | reload a file with an invalid route | error, the running config unchanged | unit (`dvarapala::reload`) |
| 9 | the admin listener | requests without a token, with a wrong one, with the right one | `401`, `401`, `200`; the comparison is constant time | integration (`dvarapala/tests`) |
| 10 | the admin listener | `POST /blocks?cidr=192.0.2.0/24&ttl=10m`, then `GET /blocks` | listed with its expiry; the proxy refuses the network | integration (`dvarapala/tests`) |
| 11 | `admin.listen` set, `admin.token` empty or short | start | error naming `admin.token` | unit (`config`) |
| 12 | arbitrary admin request lines and query strings | parse | no panic | fuzz (`admin_query`) |
| 13 | the proxy under load | `SIGHUP` with a new rate | no connection dropped, the new rate applies | integration (`dvarapala/tests`) |
| 14 | a block list of 4096 networks | a request | the block check under 2 us | bench (`engine/benches/blocks.rs`) |

## Alternatives

| Option | Why not |
|---|---|
| Restart with `SO_REUSEPORT` handover | keeps connections but still empties the table and the baseline; much more code |
| Reload every key | listeners, TLS mode, the store and XDP hold sockets and kernel objects; rebuilding them in place is a restart in disguise |
| gRPC or a full REST framework | a new dependency for five endpoints |
| Admin on the metrics listener | metrics are often scraped from a wider network than the one allowed to block or reload |
| No token on loopback | any local process (or an SSRF in the upstream on the same host) could then reload or block |

## Security and resource limits

- The admin listener is off by default. Every call needs the bearer
  token, compared in constant time; there is no unauthenticated endpoint.
  Bind it to loopback or a management network.
- Request bodies are not read; parameters are in a query string of at
  most 1 KiB. Requests are answered over HTTP/1.1 with a 5 s header
  timeout and at most 16 connections.
- `max_blocks` bounds the manual block list; a block is at most
  `max_block_ttl` long. The block check is one hash lookup per prefix
  length in use, under 2 us at the default bound.
- A reload reads the file the process started with; the API cannot point
  it at another path.

## Implementation notes

Found while building:

- The swappable parts of the layer (trusted proxies, challenge,
  fingerprint rules, routes, enforce) sit in one `Policy` behind an
  `RwLock<Arc<_>>`, read once per request; `retune` changes the guard
  under its existing lock. Both live in `crates/l7/src/control.rs` to keep
  `rate_limit.rs` under 500 lines.
- `Blocks` keys a hash map by the network with host bits cleared and
  counts networks per prefix length, so a lookup tries only the lengths in
  use: about 75 ns at 4096 `/24` blocks (a linear scan measured 6 us).
- Admin parsing (`Call`, the query, percent decoding, the bearer check)
  lives in `crates/l7/src/admin.rs` so the `admin_query` fuzz target
  reaches it; the binary serves it and writes the JSON by hand (no new
  dependency). Connections are one request each, so an idle keep-alive
  cannot hold one of the 16 slots.
- Cases 9, 10 and 13 run the built binary (`crates/dvarapala/tests/admin.rs`).
- A reload validates the keys it applies; a changed restart-only key is
  reported, not validated, until the restart.
- Reported as needing a restart too: a new rate with a shared `[store]`
  (the cluster budget is set at start), JA4 turned on after a start
  without it (the TLS listener computes it only when asked at start). The
  detector's heavy hitter threshold also keeps the start rate.
- The challenge keeps its key when `secret` is unchanged, an empty one
  included, so a `SIGHUP` for a certificate renewal does not void passes.
- `DELETE /blocks` does not remove an XDP entry: it expires on its own.
- In forward mode, or with the rate limiter off, `/status` and `/reload`
  work and the other calls answer `503`.

## Rollout

- **Rollout:** v0.9.0. `SIGHUP` now also reloads the config file; the
  admin listener stays off until `admin.listen` is set.
- **Off switch:** unset `admin.listen`. A reload that misbehaves is undone
  by reverting the file and sending `SIGHUP` again.
