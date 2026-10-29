# 0015: Upstream pools and health checks

| Status | Date | PR | Release |
|---|---|---|---|
| implemented | 2026-10-29 | #124 | v0.10.0 |

> The reverse proxy sends to a pool of upstreams instead of one: round
> robin or least requests, active health checks, passive ejection after
> repeated failures, and retries of idempotent requests under a budget, so
> one failing backend no longer turns into errors for a share of clients.

## Problem

`upstream` is one URL. Running more than one backend needs another load
balancer behind the gateway, which is one more hop and one more thing to
protect:

- When one backend dies, the gateway keeps sending to it until an outer
  balancer notices; with two backends that is half the requests failing.
- During an attack a backend that slows down or answers `503` gets the
  same share as the others, so the healthy ones carry no extra load and
  the sick one never recovers.
- A connect failure is final: a `GET` that never reached the backend
  could have gone to another one.

## Proposal

- `[pool]` replaces `upstream` when set: `upstreams` is a list of base
  URLs (`http://` or `https://`, each with its own path), sharing
  `upstream_protocol`, `[upgrade]` and `[upstream_tls]`. `upstream` and
  `[pool]` together are an error.
- `balance = "round_robin"` (default) or `"least_requests"` (the
  endpoint with the fewest requests in flight, ties in turn).
- Active checks, when `health_path` is set: every `health_interval`, a
  `GET <base><health_path>` per endpoint, `health_timeout` long; a
  `2xx` or `3xx` is a success. `unhealthy_after` failures in a row take an
  endpoint out, `healthy_after` successes bring it back. Endpoints start
  healthy.
- Passive ejection: `eject_after` failures in a row (connect error,
  timeout, or a `502`, `503` or `504` from the endpoint) eject it for
  `eject_time`, whether or not active checks run. The first request
  after that is a trial; a failure ejects it again.
- Retries: a request that failed to connect (it never reached the
  endpoint) goes to another endpoint when it is idempotent (`GET`,
  `HEAD`, `OPTIONS`), has no body and is not an upgrade, at most
  `retries` times. Every request adds `retry_budget` to a budget of at
  most 10 retries and a retry spends 1, so retries stay a share of the
  traffic during an outage instead of multiplying it.
- No endpoint healthy: the pool picks among all of them (fail open,
  logged and counted). Health checks can be wrong, and the protection
  layers already ran; a `503` from the gateway would turn a false
  negative into an outage.
- The TCP and the HTTP/3 listeners share one pool and its health state.
- Forward mode is unchanged.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/proxy/src/pool/balance.rs` | `Pool`: endpoints, pick by policy, in-flight counts, health and ejection state |
| `crates/proxy/src/pool/health.rs` | the active check task |
| `crates/proxy/src/pool/retry.rs` | `RetryBudget` |
| `crates/proxy/src/reverse.rs` | `ReverseProxy::with_pool`: pick, send, report the outcome, retry |
| `crates/dvarapala/src/config/pool.rs` | `[pool]`, validation |

### Configuration

| Key | Default | |
|---|---|---|
| `pool.upstreams` | `[]` | base URLs; empty uses `upstream`. At most 64 |
| `pool.balance` | `"round_robin"` | or `"least_requests"` |
| `pool.health_path` | `""` | path of the active check, for example `"/healthz"`; empty turns active checks off |
| `pool.health_interval` | `"5s"` | time between checks of one endpoint |
| `pool.health_timeout` | `"1s"` | one check at most |
| `pool.unhealthy_after` | `3` | failed checks in a row to take an endpoint out |
| `pool.healthy_after` | `2` | passed checks in a row to bring it back |
| `pool.eject_after` | `5` | failed requests in a row to eject an endpoint; `0` turns passive ejection off |
| `pool.eject_time` | `"30s"` | how long an ejection lasts |
| `pool.retries` | `1` | retries of a request that failed to connect; `0` turns retries off |
| `pool.retry_budget` | `0.2` | retries earned per request, in `[0, 1]` |

### Logs and metrics

| | |
|---|---|
| `msg="upstream unhealthy"` / `msg="upstream healthy"` | an active check changed an endpoint's state |
| `msg="upstream ejected"` | passive ejection, with the failure count |
| `msg="pool degraded"` | no endpoint healthy, picking among all; at most once a second |
| `dvarapala_upstream_requests_total{upstream,result}` | `ok`, `error` (connect error, timeout, `502` to `504`) |
| `dvarapala_upstream_healthy{upstream}` | 1 healthy, 0 out (checks or ejection) |
| `dvarapala_upstream_in_flight{upstream}` | requests in flight per endpoint |
| `dvarapala_upstream_ejections_total{upstream}` | passive ejections |
| `dvarapala_upstream_retries_total{result}` | `sent`, `budget` (refused by the budget) |
| `dvarapala_upstream_degraded_total` | picks made with no endpoint healthy |

`upstream` is the endpoint's `host:port` from the config, so the label set
is bounded by `pool.upstreams`.

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | three endpoints, round robin | 300 picks | 100 each | unit (`pool::balance`) |
| 2 | least requests, in flight 2, 0, 1 | a pick | the second; after its request ends, ties in turn | unit (`pool::balance`) |
| 3 | `eject_after = 5`, `eject_time = 30s` | 5 failures, then picks at 10 s and 31 s | not picked at 10 s, picked (trial) at 31 s; a failed trial ejects again | unit (`pool::balance`) |
| 4 | `unhealthy_after = 3`, `healthy_after = 2` | check results fail, fail, fail, pass, pass | out after the third, back after the fifth | unit (`pool::balance`) |
| 5 | every endpoint out | a pick | one of them; the degraded counter rises | unit (`pool::balance`) |
| 6 | `retry_budget = 0.2` | 100 requests, every one failing to connect | at most 30 retries (20 earned, 10 at start) | unit (`pool::retry`) |
| 7 | two endpoints, one with nothing listening | 20 `GET`s, then a `POST` sent to the dead one | every `GET` `200` from the live one; the `POST` `502`, not retried | integration (`proxy/tests`) |
| 8 | two endpoints, one with `/healthz` answering `500`, `health_interval = 50ms` | requests after 200 ms | all to the healthy one | integration (`proxy/tests`) |
| 9 | the same pool behind TCP and HTTP/3 | an endpoint ejected through TCP | HTTP/3 requests skip it too | integration (`proxy/tests`) |
| 10 | `upstream` and `pool.upstreams` both set; 65 upstreams; a bad URL; `retry_budget = 2` | load | an error naming the key | unit (`config`) |
| 11 | 16 endpoints, least requests | a pick | under 100 ns | bench (`proxy/benches/pool.rs`) |

No fuzz target: the pool reads no attacker input. Endpoint answers come
from configured backends and are parsed by `hyper`.

## Alternatives

| Option | Why not |
|---|---|
| Keep one upstream, put a balancer behind | one more hop, and the gateway still cannot react to a sick backend |
| DNS with several A records | resolved once per connection pool, no health, no ejection |
| Consistent hashing, sticky sessions | useful, but a separate feature with its own RFC; round robin and least requests cover stateless backends |
| `503` when every endpoint is out | turns a wrong health check into an outage |
| Retry every failed request | a retried `POST` can run twice; retries without a budget multiply load during an outage |

## Security and resource limits

- At most 64 endpoints. Each holds counters and a small state; the label
  set of every metric is bounded by the config.
- Active checks: one request per endpoint per `health_interval`, each at
  most `health_timeout`, the body not read beyond the status line and
  headers. They use the pool's own connections.
- Retries are bounded per request (`retries`) and in total (the budget,
  at most 10 banked), and only for requests that never reached a
  backend, so an attacker cannot make the gateway multiply its requests
  to the backends.
- Health and ejection state is per process; replicas each see their own.

## Rollout

- **Rollout:** v0.10.0. Without `[pool]` the proxy behaves as before with
  `upstream`.
- **Off switch:** remove `[pool]` and set `upstream`; `retries = 0` and
  `eject_after = 0` turn those parts off.

## Implementation notes

Found while building:

- `ReverseProxy` always holds an `Arc<Pool>`: `new` and `with_config`
  build a pool of one endpoint with no checks, ejection or retries, so a
  plain `upstream` behaves as before. `with_pool` takes a shared one; the
  HTTP/3 listener builds its own client (the body type differs) over the
  TCP listener's pool.
- With `upstream` alone, every other `[pool]` key must stay at its
  default, so tuning a pool that is not there is an error instead of
  silently ignored. A bad `[pool]` refuses a reload too, although pool
  changes need a restart.
- A retry pick does not move the round robin: with two endpoints, one of
  them dead, each request otherwise started on the dead one and the
  budget ran out after 14 requests.
- A request is retried only when its body is empty at the start
  (`is_end_stream`); the retry sends an empty body, so nothing is
  buffered. A `GET` with a body is not retried.
- In flight counts last until the response headers, not the end of the
  body.
- A pick over 16 endpoints with least requests measured about 71 ns
  (budget 100 ns), most of it reading the clock for ejection.
