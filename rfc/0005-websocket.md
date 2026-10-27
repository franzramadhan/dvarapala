# 0005: WebSocket and HTTP upgrades

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-27 | #20 | v0.4.0 |

> Pass WebSocket upgrades through to the upstream, with the upgrade
> request rate limited like any other and the open tunnels bounded in
> number, idle time and lifetime.

## Problem

`hop.rs` strips `Connection` and `Upgrade` as hop-by-hop headers, and the
proxy never handles a `101 Switching Protocols`. A WebSocket client behind
dvarapala gets whatever the upstream does with a plain GET, usually a 400 or
426. Chat, live dashboards and most realtime APIs cannot use dvarapala today.

Upgraded connections are also a resource problem: each one holds a socket
and two buffers for as long as the client likes, and after the 101 the rate
limiter never sees the connection again.

## Proposal

- An HTTP/1.1 request with `Connection: upgrade` and `Upgrade: websocket`
  keeps both headers (and the `Sec-WebSocket-*` headers, which are end to
  end already). It goes through the L7 layers like any request, so the
  rate limit, detection and ML score all apply to the upgrade.
- When the upstream answers `101`, the proxy upgrades both sides and copies
  bytes in both directions until either side closes. Any other upstream
  answer goes back to the client as a normal response.
- Only protocols in `upgrade.protocols` (default `["websocket"]`) are
  passed. Other `Upgrade` values are stripped as today, so `h2c` or custom
  protocols cannot tunnel through by accident.
- Tunnel limits, on by default:
  - `upgrade.max_tunnels` (default `10000`): open tunnels at once. Over it,
    the upgrade request gets `503` before it reaches the upstream.
  - `upgrade.idle_timeout` (default `300s`): no bytes in either direction
    for this long closes the tunnel.
  - `upgrade.max_lifetime` (default `24h`, `0` off): closes even busy
    tunnels, so clients reconnect through the current limits.
- Graceful shutdown waits for tunnels up to the existing drain timeout, then
  closes them.
- The proxy does not parse WebSocket frames: no per-message rate limit, no
  compression handling, no `permessage-deflate` rewriting. Frame-level
  limits are a later RFC if needed.
- Out of scope: WebSocket over HTTP/2 (RFC 8441 extended CONNECT) and over
  HTTP/3 (RFC 9220). Browsers fall back to HTTP/1.1 when the server does
  not advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL`, which dvarapala does not.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/proxy/src/hop.rs` | keep `Connection: upgrade` and an allowed `Upgrade` |
| `crates/proxy/src/upgrade.rs` | on `101`: upgrade both sides, copy, enforce idle time and lifetime |
| `crates/proxy/src/tunnels.rs` | count tunnels against `max_tunnels` |
| `crates/proxy/src/reverse.rs` | route upgrade requests through `upgrade.rs` |
| `crates/dvarapala/src/config.rs` | `[upgrade]` section |

The listener already uses `serve_connection_with_upgrades`, and the engine
and l7 crates are untouched.

### Configuration

| Key | Default | |
|---|---|---|
| `upgrade.protocols` | `["websocket"]` | `Upgrade` tokens passed to the upstream; `[]` turns upgrades off |
| `upgrade.max_tunnels` | `10000` | Open tunnels at once; over it, `503` |
| `upgrade.idle_timeout` | `300s` | Close a tunnel with no traffic for this long |
| `upgrade.max_lifetime` | `24h` | Close any tunnel after this long; `0` off |

### Logs and metrics

| | |
|---|---|
| `dvarapala_tunnels_open{protocol}` | gauge, compare with `max_tunnels` |
| `dvarapala_tunnels_total{protocol,end}` | closed tunnels by `client`, `upstream`, `idle`, `lifetime`, `shutdown` |
| `dvarapala_tunnel_bytes_total{direction}` | bytes copied, `in` and `out` |
| `dvarapala_tunnels_rejected_total` | upgrades refused over `max_tunnels` |
| `msg="tunnel limit reached"` | sampled, at most once per second |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | WebSocket test upstream (`tokio-tungstenite` as a dev-dependency) | client connects through the proxy | `101`, text and binary messages echo both ways | integration (`proxy/tests`) |
| 2 | same | client sends close | upstream sees the close, tunnel counted with `end="client"` | integration |
| 3 | same | upstream closes | client sees the close, `end="upstream"` | integration |
| 4 | upstream answers the upgrade with `403` | connect | client gets `403`, no tunnel | integration |
| 5 | `Upgrade: h2c` request | proxy | `Upgrade` and `Connection: upgrade` stripped, plain request upstream | unit (`hop`) |
| 6 | `upgrade.protocols = []` | WebSocket request | headers stripped, no tunnel | integration |
| 7 | rate limit exhausted | upgrade request | `429`, upstream never sees it | integration |
| 8 | `max_tunnels = 2`, 2 open | third upgrade | `503`, upstream not called, rejected counter up | integration |
| 9 | `idle_timeout = 200ms` (fake clock or paused tokio time) | no traffic | tunnel closed, `end="idle"` | integration |
| 10 | `max_lifetime = 1s`, steady traffic | 1 s passes | closed, `end="lifetime"` | integration |
| 11 | open tunnel | shutdown | tunnel closed within the drain timeout, `end="shutdown"` | integration |
| 12 | 1 MB message each way | echo | bytes counted in both directions | integration |
| 13 | 10000 idle tunnels | memory | per-tunnel memory reported, within the budget below | bench |

## Alternatives

| Option | Why not |
|---|---|
| Pass any `Upgrade` token | `h2c` and custom protocols would tunnel past the HTTP/2 limits of RFC 0004 |
| Parse WebSocket frames for per-message limits | a frame parser on attacker input and a hot path cost, for a need nobody has stated yet |
| RFC 8441 (WebSocket over HTTP/2) now | one more translation path; HTTP/1.1 fallback is universal |
| No lifetime limit | a client admitted once keeps the tunnel through every later limit change or attack |

## Security and resource limits

- The attacker controls how many tunnels it opens and how long it keeps
  them. `max_tunnels` caps the count, the upgrade request goes through the
  rate limit, and `idle_timeout` and `max_lifetime` cap the time.
- Memory per tunnel: two copy buffers (8 KB each) plus the connection
  state, so about 200 MB at the default `max_tunnels` worst case. The
  budget is checked by test 13.
- The proxy copies bytes and never parses frames, so there is no new
  parser on attacker input.
- Only allowed `Upgrade` tokens pass; everything else is stripped as today.

## Rollout

- **Rollout:** v0.4.0. WebSocket upgrades start working by default; other
  traffic is unchanged.
- **Off switch:** `upgrade.protocols = []` restores the v0.3.0 behavior.
