# 0010: Shared state for clusters

| Status | Date | PR | Release |
|---|---|---|---|
| draft | 2026-10-28 | #71 | unplanned |

> A `store` crate and an optional Redis backend, so several dvarapala
> replicas behind one load balancer enforce one per-client limit, one
> egress budget per destination and one list of heavy hitters, without a
> network call on the request path.

## Problem

Every limit lives in the memory of one process. With `N` replicas behind a
load balancer:

- **Per-client rate limit:** a client spread round robin over `N`
  replicas gets `N x rate`. With 4 replicas and the default 20 rps, a
  client sends 80 rps before any `429`.
- **Forward proxy (RFC 0007):** each replica keeps its own schedule, so
  the provider sees `N x rate` and blocks us, the exact failure that mode
  exists to prevent. RFC 0007 lists this as out of scope until a store
  exists.
- **Detection (RFC 0002):** each replica sees `1/N` of a flood. A heavy
  hitter found on one replica is still served by the others.

A synchronous Redis call per request would fix the counts, but adds a
round trip (0.2 to 1 ms in one zone) to every request, makes Redis the
first thing an attacker saturates, and turns a Redis outage into a
gateway outage.

## Proposal

- `[store] backend = "memory"` (default) keeps today's behavior: no
  change, no new socket. `backend = "redis"` with `store.url` shares state
  between every replica that uses the same Redis and `store.cluster` name.
- Nothing on the request path waits for Redis. Each replica keeps its
  local state as today and syncs in the background every
  `store.sync_interval` (default 1 s). Limits are therefore approximate,
  with a bounded overshoot (below), never a hard dependency.
- **Replica count:** each replica writes a heartbeat key with a TTL of
  three intervals and reads how many are alive. `dvarapala_store_replicas`
  reports it.
- **Per-client limit:** the local token bucket stays at the full rate
  (exact when the load balancer pins a client to one replica). On top,
  every interval each replica adds the requests it allowed per active
  client to a cluster counter for the current window (`INCRBY` and
  `EXPIRE`, pipelined, at most `store.max_keys` clients per sync, busiest
  first). When a client's cluster count for the window is over
  `rate x window + burst`, every replica throttles it locally until the
  window ends. Overshoot is at most `N x rate x sync_interval` per window.
- **Forward proxy:** a destination's rate, burst and `max_concurrent` are
  divided by the live replica count on every sync, so the cluster never
  sends above the agreement (fail closed toward the provider). A provider
  pause (`Retry-After`) seen by one replica is published and applies on
  all.
- **Heavy hitters:** in `enforce` mode each replica publishes the
  prefixes its detector marks as heavy, with a TTL of
  `detection.cooldown_windows` windows; every replica drops them too.
  Detection state (`Normal` to `Attack`) stays per replica.
- **Lost Redis: fail open to local limits**, as `CLAUDE.md` allows for
  this case. Local buckets and detection keep working; the cluster
  counters and the shared drop list stop growing and expire. The last
  known replica count is kept for the forward split, so egress stays
  under the agreement. Logged once as `msg="store unavailable"`, and
  `msg="store recovered"` when it comes back; reconnects back off up to
  `store.sync_interval x 10`.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/cluster.rs` | pure merge rules: window counts to verdict overrides, budget split by replica count, overshoot bound. Time and counts as input |
| `crates/store/src/lib.rs` | the `Store` trait: heartbeat, add and read window counts, publish and read the drop list and pauses |
| `crates/store/src/memory.rs` | single-process backend, the default; also the test double |
| `crates/store/src/redis.rs` | Redis backend: pipelined commands, one connection, reconnect with backoff |
| `crates/store/src/sync.rs` | the background task that drains local deltas into the store and applies what comes back |
| `crates/l7/src/rate_limit.rs` | consult the cluster overrides and the shared drop list before the local bucket |
| `crates/proxy/src/forward/shaper.rs` | apply the replica split and shared pauses |
| `crates/dvarapala/src/config/store.rs` | `[store]` section |

`engine` keeps no I/O: it gets counts in and returns decisions, and the
sync task in `store` does the talking. The Redis client is the `redis`
crate (BSD-3-Clause) with `tokio-comp` and, for `rediss://`, rustls; it
must pass `cargo deny check` and lands behind a `redis` cargo feature so
the default binary does not grow.

### Configuration

| Key | Default | |
|---|---|---|
| `store.backend` | `"memory"` | `"memory"` or `"redis"`; `"memory"` turns sharing off |
| `store.url` | unset | `redis://<host>:6379/0` or `rediss://` for TLS; required with `"redis"`. The password goes in the URL or `DVARAPALA__STORE__URL`, and is never logged |
| `store.cluster` | `"dvarapala"` | Key prefix; replicas with the same Redis and name share state |
| `store.sync_interval` | `"1s"` | How often each replica syncs; shorter is tighter and costs more Redis commands |
| `store.max_keys` | `10000` | Clients synced per interval at most, busiest first |
| `store.timeout` | `"500ms"` | One sync round slower than this counts as a failure |

### Logs and metrics

| | |
|---|---|
| `dvarapala_store_replicas` | Live replicas seen in the last heartbeat round |
| `dvarapala_store_sync_seconds` | Histogram of one sync round |
| `dvarapala_store_sync_errors_total` | Failed rounds |
| `dvarapala_store_up` | 1 while the last round succeeded, 0 otherwise |
| `dvarapala_store_keys_dropped_total` | Clients left out of a sync by `max_keys` |
| `dvarapala_requests_total{verdict="throttle",scope="cluster"}` | Throttled by the cluster count, not the local bucket |
| `msg="store unavailable"` / `msg="store recovered"` | Fail open and back |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `backend = "memory"` | start | no store task, no socket, behavior and metrics as before | integration (`dvarapala`) |
| 2 | window counts from 3 replicas over the limit | merge | the client is throttled until the window ends | unit (`engine::cluster`) |
| 3 | rate 20, 4 replicas, interval 1 s | overshoot bound | at most 80 extra requests per window | unit (`engine::cluster`) |
| 4 | destination rate 50, 2 then 3 live replicas | split | 25, then 16.67 per replica; burst and `max_concurrent` rounded down, at least 1 | unit (`engine::cluster`) |
| 5 | two proxies on one Redis, one client round robin, rate 10 | 100 requests in 1 s | at most `10 + burst + overshoot` reach the upstream | integration (`store/tests`, Redis service) |
| 6 | two forward proxies on one Redis, destination rate 10 | callers on both send 100 rps | the test upstream sees at most 10 rps plus burst | integration (`store/tests`) |
| 7 | a provider `429` with `Retry-After: 2` on replica A | next request on replica B | B waits or refuses as paused | integration (`store/tests`) |
| 8 | heavy hitter found on A, `enforce` | it sends to B | B drops it after one sync | integration (`store/tests`) |
| 9 | Redis stops | traffic continues | local limits apply, `store_up` 0, one `store unavailable` log, no request waits | integration (`store/tests`) |
| 10 | Redis comes back | next round | counters resume, one `store recovered` log | integration (`store/tests`) |
| 11 | 50 000 active clients, `max_keys` 10 000 | one sync | 10 000 busiest synced, `keys_dropped_total` 40 000, round under `timeout` | integration (`store/tests`) |
| 12 | `store.url` with a password | any log or error | the password does not appear | unit (`config`) |
| 13 | `backend = "redis"`, no `url` | start | config error naming `store.url` | unit (`config`) |
| 14 | arbitrary bytes as a Redis reply | the backend parses it | no panic, an error | fuzz (`store_reply`) |
| 15 | sync task on a busy proxy | bench | request latency p99 unchanged within noise, sync under 5 ms for 10 000 keys on loopback | bench (`store/benches`) |

## Alternatives

| Option | Why not |
|---|---|
| Synchronous Redis per request (GCRA in Lua) | exact, but a round trip on every request, Redis becomes the attack target, and an outage stops traffic |
| Divide every per-client rate by `N` | wrong when the load balancer pins clients: a client on one replica would get `rate / N` |
| Gossip between replicas (no Redis) | membership, discovery and NAT handling are more work than one Redis most clusters already run |
| Sticky load balancing only | out of our control, and still leaves the forward proxy and heavy hitters per replica |
| Envoy-style external rate limit service | another service to run, and again synchronous on the request path |

## Security and resource limits

- Redis is trusted: anyone who can write the keys can throttle clients
  or pause destinations. Use a Redis that only the replicas reach, a
  password, and `rediss://` across untrusted networks.
- An attacker controls which clients are active, not what is synced:
  `max_keys` bounds the work and the keys per round, busiest first, so a
  spoofed-source flood of single requests costs at most `max_keys` keys
  per interval, each with a TTL of two windows.
- Memory per replica: the local delta map is bounded by the existing
  `rate_limit.max_clients` table, plus the shared drop list capped at the
  detector's `top_k` per replica.
- No request path code waits on the store, so a slow or hostile Redis
  costs sync rounds, never request latency.

## Rollout

- **Rollout:** unplanned. Default `memory`, so upgrading changes nothing.
  The `redis` cargo feature is off by default; release binaries may ship
  with it once the footprint job measures it.
- **Off switch:** `store.backend = "memory"`, or stop Redis: replicas fall
  back to local limits.
