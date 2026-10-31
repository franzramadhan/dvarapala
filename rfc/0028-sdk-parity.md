# 0028: SDK parity: routes, blocks, egress and reload

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-10-31 | #235 | |

> Bring four gateway features into the SDKs: per-route policy, manual
> blocks, egress shaping and live reload. Routes move from `l7` to
> `engine` so the C ABI can reach them without pulling in an async
> runtime. The ABI only gains functions; existing calls keep their
> behavior.

## Problem

The SDKs (RFC 0008) expose one global bucket per client, detection and
connection limits: `dv_check(ip, xff)`, `dv_conn_open`, `dv_stats`. A
service that embeds them instead of running the gateway loses:

- **Routes (RFC 0013):** a tighter limit on `POST /login`, a deny on
  probe paths, a bucket per API key or tenant (`key = "header:<name>"`).
  For an API service, the per-key bucket is often the limit it needs
  most.
- **Manual blocks (RFC 0014):** the gateway takes `POST /blocks`; an
  embedding app, which knows about failed logins or fraud first, cannot
  ban a client in its own guard.
- **Egress shaping (RFC 0007):** keeping outbound calls to a provider's
  rate needs the forward proxy, one more hop and one more process, for a
  budget the app could hold itself.
- **Reload:** a config change means a new guard, which drops every
  client's counts and the detection baseline.

Each of these lives in code the ABI can already reach, or close to it:

| Feature | Code today | Dependencies |
|---|---|---|
| Blocks | `engine/blocks.rs` | none |
| Egress | `engine/schedule.rs` (`Schedule::reserve`, `pause`); `proxy/forward/shaper.rs` wraps it | none |
| Reload | `Guard::retune` | none |
| Routes | `l7/routes/{matcher,limits,policy}.rs` | `http` types only, but `l7` brings `tokio`, `hyper` and `tower` |

## Proposal

- **Routes:** a new `dv_check_request` takes the method, host, path and
  the headers that route keys name, and applies `[[routes]]` as the
  gateway does. The first matching route can deny, or add its own bucket
  keyed by client or header, on top of the global one. `dv_check` stays
  as it is and ignores routes.
- **Blocks:** `dv_block(ip_or_cidr, ttl_ms)`, `dv_unblock` and
  `dv_blocks` (JSON). A blocked client gets `drop` from `dv_check` and
  `dv_check_request` before any bucket, and `DV_E_LIMIT` from
  `dv_conn_open`. Limits: `admin.max_blocks` and `admin.max_block_ttl`,
  with the gateway's defaults.
- **Egress:** `dv_egress(dest)` answers `now`, `wait <ms>` or
  `refuse <retry ms>` from the destination's schedule, and
  `dv_egress_pause(dest, retry_after_ms)` records a provider's
  `Retry-After`. The library never blocks or sleeps: each language waits
  in its own way (Go `time.Timer` with a `context`, Python `asyncio.sleep`
  or `time.sleep`, JavaScript `setTimeout`).
  - Go also gets `g.Transport(base http.RoundTripper)`: it shapes each
    request by origin, and pauses on `429` or `503` with `Retry-After`.
  - `max_concurrent` stays with the language's own semaphore (a Go
    channel, `asyncio.Semaphore`): a non-blocking ABI cannot hold a
    place. The key is refused in process, with that hint in the error.
- **Reload:** `dv_guard_reload(guard, config)` applies a new config to a
  running guard in one step, keeping client counts, the detection
  baseline, blocks and egress queue positions. A key that the gateway
  can only apply at restart (`rate_limit.max_clients`, `l4.max_clients`,
  `l4.max_connections`) fails the reload with an error naming it, and
  the guard stays as it was.
- **List-shaped keys:** `routes` and `forward.destinations` take a JSON
  array in `dv_config_set`, with the `CONFIG.md` field names. JSON
  because every SDK language has a JSON encoder in its standard library;
  TOML has none in Python's. Each SDK's config takes a list for these
  keys and encodes it.
- **In-process limits on route fields:**
  - `key = "ja4"` is refused: the SDK sees no TLS ClientHello;
  - `challenge` and `waf` are refused: neither runs in process;
  - every other field means what `CONFIG.md` says.
- **Middleware:** each SDK's HTTP middleware switches to
  `dv_check_request`, so routes apply with no code change in the app.
  The middleware passes only the headers that some route's `key` names
  (`dv_route_headers`), so a config without header keys reads no
  headers.
- **Gateway:** unchanged. `l7` keeps its `RouteConfig` and calls the
  matcher from `engine` through a thin adapter over `http` types.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/routes/` (moved from `l7/routes/`) | `Matcher` over `&str` method, host and path and a header lookup; `RouteKey`, route tables, `Routes::check`. No `http` |
| `crates/l7/src/routes/` | the adapter from `http::Request` to the engine matcher; the `challenge` and `waf` fields stay here |
| `crates/ffi/src/request.rs` | `dv_check_request`, `dv_route_headers` |
| `crates/ffi/src/blocks.rs` | `dv_block`, `dv_unblock`, `dv_blocks`, `dv_string_free` |
| `crates/ffi/src/egress.rs` | `dv_egress`, `dv_egress_pause`; the waiting count per destination |
| `crates/ffi/src/guard.rs` | `dv_guard_reload`; blocks checked in `dv_check` and `dv_conn_open` |
| `crates/ffi/src/config.rs` | `routes`, `forward.destinations` (JSON), `admin.max_blocks`, `admin.max_block_ttl` |
| `sdk/go`, `sdk/python`, `sdk/js` | the new calls, the middleware on `dv_check_request`, egress helpers, Go `Transport` |
| `crates/node` | the N-API side of the new calls |

### C ABI additions

```c
typedef struct DvRequest {
  const char *ip;        /* peer address */
  const char *xff;       /* X-Forwarded-For or NULL */
  const char *method;
  const char *host;      /* authority or Host, NULL when absent */
  const char *path;      /* raw path, no query */
  const char *headers;   /* "name: value\n" lines for dv_route_headers, or NULL */
} DvRequest;

typedef struct DvRequestVerdict {
  int32_t kind;            /* DV_ALLOW, DV_THROTTLE, DV_DROP */
  uint64_t retry_after_ms;
  const char *route;       /* matched route name, NULL when none; valid while the guard lives */
} DvRequestVerdict;

typedef struct DvSlot {
  int32_t kind;            /* DV_SLOT_NOW, DV_SLOT_WAIT, DV_SLOT_REFUSE */
  uint64_t ms;             /* wait for WAIT, retry after for REFUSE */
} DvSlot;

int32_t dv_check_request(const DvGuard *g, const DvRequest *r, DvRequestVerdict *out);
const char *dv_route_headers(const DvGuard *g);   /* comma separated, lower case; "" for none */
int32_t dv_block(const DvGuard *g, const char *cidr, uint64_t ttl_ms);  /* 0: admin.max_block_ttl */
int32_t dv_unblock(const DvGuard *g, const char *cidr);                 /* DV_E_NOT_FOUND */
char *dv_blocks(const DvGuard *g);                /* JSON [{"cidr","ttl_ms"}], free with dv_string_free */
void dv_string_free(char *s);
int32_t dv_egress(const DvGuard *g, const char *dest, DvSlot *out);     /* DV_E_NOT_FOUND */
int32_t dv_egress_pause(const DvGuard *g, const char *dest, uint64_t retry_after_ms);
int32_t dv_guard_reload(DvGuard *g, const DvConfig *cfg);
```

A new code, `DV_E_NOT_FOUND` (6), means an unknown destination or an
unlisted block. `dest` is a destination's `name` (default: its host). A `WAIT` slot is
taken: the library counts it as waiting until its time passes, so
`max_queue` holds without a callback.

### Configuration

No new keys: these are the gateway's keys, now accepted in process.

| Key | Default | In process |
|---|---|---|
| `routes` | `[]` | JSON array of `[[routes]]` tables; `key = "ja4"`, `challenge` and `waf` refused |
| `forward.destinations` | `[]` | JSON array of `[[forward.destinations]]` tables; `max_concurrent` refused. Other `forward.*` keys stay refused |
| `admin.max_blocks` | `4096` | blocks at most; `dv_block` over it returns `DV_E_LIMIT` |
| `admin.max_block_ttl` | `"24h"` | longest and default block TTL. Other `admin.*` keys stay refused |

### Logs and metrics

None new: the SDKs have no logger or metrics exporter.

- `DvStats` is unchanged: callers allocate it, so a new field would let
  the library write past an old caller's struct. `dv_blocks` gives the
  blocks in force.
- `DvRequestVerdict.route` lets the app label its own metrics per route.

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | route `login`, `path = "=/login"`, `methods = ["POST"]`, `rate = 1`, `burst = 2` | three `POST /login` from 192.0.2.1 | allow, allow, throttle with `route = "login"`; a `GET /login` is allowed | unit (ffi) |
| 2 | route `probes`, `path = "/wp-admin"`, `deny = true` | `GET /wp-admin/x` | drop, before any bucket (the client's global count is unchanged) | unit (ffi) |
| 3 | route `api`, `key = "header:x-api-key"`, `rate = 1`, `burst = 1` | two requests with key `a`, then one with `b`, same IP | allow, throttle, allow | unit (ffi) |
| 4 | the case 3 config | `dv_route_headers` | `"x-api-key"`; `""` with no header keys | unit (ffi) |
| 5 | routes with `key = "ja4"`, or with `challenge` or `waf` set | `dv_config_set` then `dv_guard_new` | error naming the route and the field | unit (ffi) |
| 6 | the gateway's `l7` route tests (RFC 0013) | run against the matcher in `engine` | pass unchanged | unit (l7) |
| 7 | `dv_block("192.0.2.0/24", 60000)` | `dv_check` and `dv_check_request` from 192.0.2.9, `dv_conn_open` from 192.0.2.9 | drop, drop, `DV_E_LIMIT`; 198.51.100.1 is allowed | unit (ffi) |
| 8 | a block with a 1 ms TTL | 5 ms later | 192.0.2.9 is allowed and `dv_blocks` is `[]` | unit (ffi) |
| 9 | `admin.max_blocks = 2` | a third `dv_block` | `DV_E_LIMIT`; `dv_unblock` of an unlisted CIDR is `DV_E_NOT_FOUND` | unit (ffi) |
| 10 | destination `stripe`, `rate = 10`, `burst = 1`, `max_queue = 1`, `max_wait = "1s"` | three `dv_egress("stripe")` at once | `now`, `wait` about 100 ms, `refuse` (queue full) | unit (ffi) |
| 11 | the case 10 destination | `dv_egress_pause("stripe", 2000)`, then `dv_egress` | `refuse` with about 2000 ms, never above `max_pause` | unit (ffi) |
| 12 | a destination with `max_concurrent` | `dv_guard_new` | error naming the key and pointing at a language semaphore | unit (ffi) |
| 13 | a guard at `rate_limit.rate = 1`, client 192.0.2.1 out of tokens | `dv_guard_reload` to `rate = 100` | the client keeps its count and refills at the new rate; blocks and the egress queue are kept | unit (ffi) |
| 14 | a running guard | `dv_guard_reload` that changes `rate_limit.max_clients` | error naming the key, the guard unchanged | unit (ffi) |
| 15 | the Go, Python and JavaScript middleware with the case 1 route | three `POST /login` | `200`, `200`, `429` with `Retry-After` | integration (per SDK) |
| 16 | Go `Transport` over a test server that answers `429` with `Retry-After: 1` once | two requests to it | the second waits about 1 s | integration (Go) |
| 17 | `dv_check_request` with arbitrary bytes in method, host, path and headers | fuzzing | no panic, no unwinding across the ABI | fuzz (`ffi_check_request`) |
| 18 | `dv_check_request` with no route matching | criterion bench | within 100 ns of `dv_check` (about 200 ns today, RFC 0008 case 14) | bench |

## Alternatives

| Option | Why not |
|---|---|
| `ffi` depends on `l7` for routes | `tokio`, `hyper` and `tower` in every SDK library, against the binary size goal; the route code itself needs none of them |
| TOML for list-shaped keys | Python's standard library reads TOML but cannot write it |
| Indexed keys (`routes.0.path`) | awkward to build in every language, and no clearer than JSON |
| Blocking `dv_egress` that sleeps in the library | a blocked thread per waiting call in Node and asyncio, and no cancellation |
| `max_concurrent` with a semaphore in the library | needs a release handle per call, so a leaked handle starves a destination; languages have semaphores that tie the release to scope |
| Change `DvVerdict` to add the route | breaks the ABI for existing callers; a new struct for the new call does not |
| Challenge middleware and the cluster store now | each is larger (the challenge page and HMAC pass; a runtime thread and network I/O for the store) and gets its own RFC |

## Security and resource limits

- Attacker input:
  - method, host, path and the named headers reach the route matcher
    through `dv_check_request`;
  - the matcher compares raw bytes as in the gateway (no decoding, so
    `/%61dmin` does not match `/admin`);
  - every string is length-checked before use: the ABI rejects a field
    over 8 KiB with `DV_E_INVALID`;
  - fuzz target `ffi_check_request` (case 17); `route_match` moves with
    the matcher to `engine`.
- Header keys are hashed with a per-process seed, as in the gateway, so
  a client cannot pick keys that collide in the route table.
- Memory:
  - route tables are bounded by `max_keys` per route (default 10000,
    least recently seen evicted);
  - blocks by `admin.max_blocks`;
  - an egress waiting entry is a deadline, 16 bytes, at most
    `max_queue` per destination.
- `dv_block` is an app call, not attacker input. A `/0` block is allowed,
  as on the gateway's admin API.

## Rollout

- **Rollout:** the next minor after acceptance. The ABI gains functions
  and one error code; no existing struct changes. `dv_check`, `dv_conn_open` and
  the existing config keys behave as before. The SDK middleware moves to
  `dv_check_request`; with no `routes`, its verdicts equal `dv_check`'s.
  `crates/ffi/dvarapala.h` is regenerated (`cbindgen` check in CI).
- **Off switch:** leave `routes` and `forward.destinations` empty, and
  call no block or egress functions.
