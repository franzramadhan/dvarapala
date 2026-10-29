# 0013: Per-route policy

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-29 | | |

> Rules matched on host, path, method and client network that add a
> stricter limit, deny the request, or exempt it from the challenge, so
> `/login` and `/api` stop sharing one policy with static files.

## Problem

Every request to the reverse proxy gets the same treatment: one bucket per
client (`rate_limit`), one detector, one challenge mode (RFC 0012). Real
sites need different answers per path:

- Credential stuffing and search floods hit one or two expensive
  endpoints (`POST /login`, `/search`) well under the global per-client
  rate. A global rate low enough to stop them throttles every page load.
- Scanners probe paths the site never serves (`/wp-admin`, `/.env`).
  Every probe reaches the upstream today.
- API and gRPC clients cannot solve a JavaScript challenge. With
  `challenge.mode = "always"`, or during an attack with `"attack"`, they
  get `429` until the attack ends, and RFC 0012 tells operators to move
  them to another listener.
- Limits per API key or per tenant: many clients behind one NAT share a
  key today, and one client with many keys cannot be told apart.

## Proposal

- `[[routes]]`: an ordered list. The first route whose every condition
  matches applies; no match means the global policy only.
- Conditions, all optional (a route without any matches everything):
  - `host`: exact (`"api.example.com"`) or a suffix (`"*.example.com"`),
    case-insensitive, port ignored. From `:authority` or `Host`.
  - `path`: a prefix (`"/api/"`), or exact with a leading `=`
    (`"=/login"`). Compared on the raw path, before any decoding, so
    `%2F` tricks do not move a request between routes.
  - `methods`: `["POST", "PUT"]`.
  - `clients`: CIDRs of the client key (after `trusted_proxies`).
- Actions, all optional:
  - `deny = true`: `403` and the connection closed (gRPC: status 7). The
    request never reaches the upstream or the buckets.
  - `rate` and `burst`: a second token bucket for this route, on top of
    the global one: both must allow. Over it, `429` with `Retry-After`.
  - `key`: what the route's bucket counts per: `"client"` (default),
    `"header:<name>"` (an API key, a tenant id; a request without the
    header falls back to the client), or `"ja4"` (RFC 0012; falls back to
    the client without a fingerprint).
  - `challenge = false`: never challenged (API paths). During an attack
    these requests get the attack limit, like a request without a pass.
  - `max_keys`: the route's table size (default `10000`), least recently
    seen evicted first.
- The global bucket, detection, heavy-hitter drops and fingerprint
  `deny` apply to every request whatever the route: a route can tighten,
  never loosen, the DDoS limits. Raise `rate_limit.rate` for a site that
  needs a looser default.
- Metrics carry the route `name`, so the operator sees which rule fires.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/guard.rs` | `Pass::Exempt`: no challenge, attack limit |
| `crates/l7/src/routes/matcher.rs` | conditions: host, path, method, client CIDR |
| `crates/l7/src/routes/limits.rs` | the per-route bucket tables and their keys |
| `crates/l7/src/routes/mod.rs` | `Routes`: first match, the action for a request |
| `crates/dvarapala/src/config/routes.rs` | `[[routes]]` |

### Configuration

| Key | Default | |
|---|---|---|
| `routes[].name` | required | label in metrics and logs, unique |
| `routes[].host` | unset | exact host or `*.suffix` |
| `routes[].path` | unset | prefix, or exact with a leading `=` |
| `routes[].methods` | `[]` | any method when empty |
| `routes[].clients` | `[]` | any client when empty |
| `routes[].deny` | `false` | `403` for matching requests |
| `routes[].rate` / `burst` | `0` / `0` | route bucket; `rate = 0` turns it off; `burst` defaults to `rate` when 0 |
| `routes[].key` | `"client"` | `"client"`, `"header:<name>"` or `"ja4"` |
| `routes[].challenge` | `true` | `false` exempts the route from `[challenge]` |
| `routes[].max_keys` | `10000` | route table size |

### Logs and metrics

| | |
|---|---|
| `dvarapala_route_requests_total{route,verdict}` | per route: `allow`, `throttle` (the route's bucket), `deny` |
| `dvarapala_route_keys{route}` | keys in the route's table |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | routes `=/login` and `/` | `GET /login`, `GET /login/x`, `GET /a` | the first, the second, the second route | unit (`l7::routes::matcher`) |
| 2 | `host = "*.example.com"` | `a.example.com:8443`, `A.EXAMPLE.COM`, `example.com`, `badexample.com` | match, match, no, no | unit (`matcher`) |
| 3 | `path = "/admin"`, raw `/%61dmin` and `//admin` | match | no match (raw path) | unit (`matcher`) |
| 4 | `methods = ["POST"]`, `clients = ["192.0.2.0/24"]` | `GET` from inside, `POST` from outside, `POST` from inside | no, no, match | unit (`matcher`) |
| 5 | route `deny = true` | request through the layer | `403`, `connection: close`, inner not called, no global token taken | integration (`l7/tests`) |
| 6 | route `rate = 1, burst = 1`, global `rate = 100` | two requests | the second `429` with `Retry-After`, `verdict="throttle"` on the route | integration (`l7/tests`) |
| 7 | route `key = "header:x-api-key"` | two keys from one client, then one key from two clients | each key has its own bucket; the shared key is shared; no header falls back to the client | integration (`l7/tests`) |
| 8 | global `rate = 1`, route `rate = 100` | two requests | the second throttled by the global bucket | integration (`l7/tests`) |
| 9 | `challenge.mode = "always"`, route `/api/` with `challenge = false` | request to `/api/x` without a pass | inner called; `/x` gets the page | integration (`l7/tests`) |
| 10 | `Pass::Exempt` in `Attack`, enforce | check | the attack limit, never `Challenge` | unit (`engine::guard`) |
| 11 | duplicate names, bad CIDR, `key = "header:"`, `path` without `/` | start | error naming the route and key | unit (`config`) |
| 12 | 10 000 distinct header values on one route, `max_keys = 100` | requests | table stays at 100 | unit (`l7::routes::limits`) |
| 13 | arbitrary hosts, paths and methods | match | no panic | fuzz (`route_match`) |
| 14 | 32 routes, a request matching the last | match | under 1 us | bench (`l7/benches/routes.rs`) |

## Alternatives

| Option | Why not |
|---|---|
| Route limits that replace the global one | a route could then loosen the DDoS limit for any path an attacker picks; raising the global rate is explicit |
| Regular expressions for paths | a regex engine is a new dependency and a new way to write a slow rule; prefixes and exact paths cover the cases above |
| Decoded or normalized paths | the upstream sees the raw path; matching a different string than it serves lets `%2F` and `..` slip past a rule |
| Per-route upstreams | load balancing is RFC 0015's job; this RFC only decides what happens before the upstream |

## Security and resource limits

- The attacker controls the host, path, method and headers. Matching is
  byte comparison over a list fixed at start, no allocation per request
  except the header key's hash.
- Each route's table is bounded by `max_keys`; a flood of API keys evicts
  the least recently seen, as in the global table.
- A header key is hashed with a per-process random seed, so values
  cannot be chosen to collide.
- `deny` is checked before any bucket, so probes of denied paths cost one
  match.

## Rollout

- **Rollout:** v0.8.0. No routes by default: nothing changes.
- **Off switch:** remove the `[[routes]]` entries.
