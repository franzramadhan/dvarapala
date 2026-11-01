# 0032: Adaptive concurrency limit for the upstream

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-11-01 | #269 | |

> Cap the requests in flight to the upstream at a limit learned from its
> latency, and shed the excess with `503` and `Retry-After` before it
> reaches the backend. Under the cap, requests from clients with a
> challenge pass or a low `[ml]` score are admitted before unknown
> clients, and clients flagged during an attack go last.

## Problem

Every limit today is per client or per route: the rate limiter, heavy
hitters, `[l4]` caps, challenges, `[ml]` scores. A wide, low-rate attack
stays under all of them: 50 000 sources at 1 request per second each is
50 000 requests per second, no single client looks abusive, entropy
stays high, and the backend saturates. Expensive endpoints (search,
login, report exports) fall over at a few hundred concurrent requests.

When the backend saturates, latency climbs, requests queue in the
backend and in dvarapala's upstream connections, timeouts fire, `[pool]`
ejects healthy endpoints (`eject_after` counts timeouts) and retries add
load. The site goes down for everyone, including clients that passed a
challenge.

What is missing is a limit on what the upstream can take, independent of
who is asking, and a choice of whom to turn away when it is reached.

## Proposal

- `[concurrency]` applies to the reverse proxy's upstream (the single
  `upstream` or the `[pool]` as a whole) and is off by default.
- `mode = "fixed"`: a hard cap of `limit` requests in flight.
- `mode = "gradient"`: the limit adapts between `min` and `max`. Every
  `window` (default `"1s"`) the limiter compares the window's p50
  latency against a long-run minimum (`rtt_noload`, a slowly decaying
  minimum of window p50s) and moves the limit:
  `new = old * clamp(rtt_noload / rtt_window, 0.5, 1.0) + sqrt(old)`,
  the gradient algorithm from Netflix's concurrency-limits. Flat latency
  grows the limit by about its square root per window; rising latency
  shrinks it, at most by half per window.
- A request is in flight from the moment it is sent upstream until its
  response head arrives or it fails. Streaming bodies, WebSocket and
  gRPC streams after the head do not count, so long-lived streams cannot
  pin the limit. `[upgrade]` tunnels keep their own limits (RFC 0005).
- Over the limit, a request is shed at once: `503` with `Retry-After:
  1` (gRPC: `RESOURCE_EXHAUSTED`, status 8), the connection kept open. No
  queue: queueing during overload adds latency to the requests that are
  admitted.
- Priority: the rate limiter (RFC 0001) puts a class on each allowed
  request. When in flight is at or above `limit * (1 - reserve)`, only
  `trusted` requests are admitted; at the limit, none.
  - `trusted`: a valid challenge pass (RFC 0012), or an `[ml]` score
    under `concurrency.trusted_score`.
  - `normal`: everything else.
  - `suspect`: a client detection names as a heavy hitter while an
    attack is on (RFC 0002); shed once in flight passes
    `limit * (1 - reserve * 2)`.
  `reserve` defaults to `0.2`: the last fifth of the capacity is kept
  for trusted clients.
- Timeouts and connect errors count as a latency sample at the
  upstream timeout, so a backend that stops answering shrinks the limit
  instead of hiding behind failures.
- Shed requests never count as failures for `[pool]` ejection or retries
  and never spend the retry budget.
- Routes (RFC 0013) can set `concurrency = false` to bypass the limit
  (health endpoints, static assets on a CDN origin) and
  `concurrency_weight` (default `1`) to count an expensive route as
  several requests.
- The algorithm is pure: an engine type fed with samples and a clock
  value, no I/O, no timer. The proxy owns the timing.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/concurrency.rs` | `Fixed` and `Gradient` limiters: admit by class and weight, release with a latency sample, recompute per window |
| `crates/l7/src/rate_limit.rs` | inserts the request's class as an extension on `Allow` |
| `crates/proxy/src/concurrency.rs` | a `tower` layer around the upstream call: admit or shed, time the response head, release |
| `crates/proxy/src/pool/` | ignores shed requests for ejection and retries |
| `crates/dvarapala/src/config.rs`, `reload.rs` | the keys; `fixed`/`gradient` bounds reload, `mode` needs a restart |
| `crates/engine/benches/concurrency.rs` | admit and release on 8 threads |
| `ui/` | the health page plots the limit, in flight and shed per class |
| `examples/concurrency.toml`, `CONFIG.md`, `site/docs/protection.md` | a gradient config in front of a slow backend |

### Configuration

| Key | Default | |
|---|---|---|
| `concurrency.mode` | `"off"` | `"fixed"` or `"gradient"` |
| `concurrency.limit` | `0` | The cap in `fixed` mode, and the start value in `gradient` (`0`: `min`) |
| `concurrency.min` / `max` | `20` / `1000` | Bounds of the gradient limit |
| `concurrency.window` | `"1s"` | Recompute interval; at least `"100ms"` |
| `concurrency.reserve` | `0.2` | Share of the limit kept for trusted requests, in `[0, 0.5]` |
| `concurrency.trusted_score` | `0.2` | `[ml]` scores under it count as trusted; unused without a model |
| `routes[].concurrency` | `true` | `false` bypasses the limit |
| `routes[].concurrency_weight` | `1` | Slots a request of the route takes, 1 to 100 |

### Logs and metrics

| | |
|---|---|
| `dvarapala_concurrency_limit` | the limit in force |
| `dvarapala_concurrency_in_flight` | weighted requests in flight |
| `dvarapala_concurrency_shed_total{class}` | requests shed, by `trusted`, `normal`, `suspect` |
| `dvarapala_concurrency_rtt_seconds{kind}` | `noload` and `window` latencies the gradient uses |
| `msg="concurrency shedding" limit=<n> class=<c>` | at most once a second while shedding, with counts since the last line |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `Gradient` at limit 20, samples at a constant 10 ms | 10 windows | the limit grows by about `sqrt(limit)` per window, never above `max` | unit (engine) |
| 2 | the same at limit 400 | window latency doubles to 20 ms | the limit halves at most once per window, never below `min` | unit (engine) |
| 3 | `Fixed` at 10, 10 in flight | an 11th admit of each class | refused; after one release, a trusted one is admitted | unit (engine) |
| 4 | limit 100, reserve 0.2, 80 in flight | a normal and a trusted admit | normal refused, trusted admitted | unit (engine) |
| 5 | an attack on, a heavy hitter's request | in flight at 60 of 100 | the suspect request is shed, a normal one admitted | integration |
| 6 | `mode = "fixed"`, `limit = 5`, an upstream that holds requests 500 ms | 10 concurrent requests | 5 reach the upstream, 5 get `503` with `Retry-After: 1`; gRPC gets status 8 | integration |
| 7 | the same | requests carrying a valid challenge pass among the 10 | every pass holder is admitted ahead of unknown clients | integration |
| 8 | `mode = "gradient"`, an upstream whose latency grows with concurrency above 50 | load ramps from 10 to 500 concurrent | the limit settles between 40 and 80, in flight never exceeds it, the upstream's p99 stays under twice its no-load latency | integration |
| 9 | a `[pool]` with `eject_after = 1` | requests shed by the limit | no endpoint ejected, no retry spent | integration |
| 10 | a route with `concurrency = false` | the limit is reached | its requests still reach the upstream | integration |
| 11 | a route with `concurrency_weight = 10` | limit 20 | two of its requests fill the limit | integration |
| 12 | a WebSocket upgrade | the 101 arrives | the slot is released; the tunnel does not count | integration |
| 13 | `mode = "off"` | any load | no `503` from the limiter, metrics absent | integration |
| 14 | admit and release on 8 threads | `criterion` | under 100 ns per pair, no lock on the hot path | bench |
| 15 | a recorded slow-flood log | `dvarapala replay` with a gradient config | the shed counts per class are reported | integration |
| 16 | `examples/concurrency.toml` | `example_configs_load` | loads | integration |

## Alternatives

| Option | Why not |
|---|---|
| Only lower `rate_limit.rate` | per client: does nothing against many low-rate clients |
| A global request rate | a rate does not see backend capacity: the right number changes with every deploy, cache state and request mix; latency does |
| A queue in front of the upstream | under sustained overload a queue only adds latency and memory; shedding at once keeps admitted requests fast |
| AIMD on errors only | reacts after the backend already fails; the gradient reacts to latency before errors |
| Per-endpoint limits in the pool | a later step; the pool shares one backend in most deployments, and one limit is easier to reason about first |
| Shed randomly instead of by class | throws away the signal challenges and `[ml]` already paid for |

## Security and resource limits

- An attacker controls load and, through slow requests, the latency the
  limiter sees. Slow requests shrink the limit for everyone, which is
  the point: the backend is the constrained resource. The `reserve` and
  the classes keep trusted clients served, and a client cannot make
  itself trusted without a pass or a model score.
- Making requests slow on purpose to shrink the limit needs the backend
  to be slow for them; the per-client rate limits and `[l4]` caps still
  bound how much one client can contribute.
- State is constant: a few atomics for in flight and the limit, one
  latency summary per window (a fixed 64-bucket histogram), no per-client
  memory.
- The admit path is an atomic add and compare; the window recompute runs
  on the first request after the window ends, or on a timer, never under
  a lock held by admits.
- Fail closed: an error inside the limiter sheds the request (`503`),
  logged; it never sends unbounded load upstream.

## Rollout

- **Rollout:** a minor release. Default `"off"`: nothing changes on
  upgrade. The docs recommend `fixed` at the backend's known capacity
  first, then `gradient` once the metrics show the no-load latency is
  stable.
- **Off switch:** `concurrency.mode = "off"` and a restart, or set
  `fixed` with a high `limit` and reload.
