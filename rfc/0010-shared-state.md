# 0010: Shared state for clusters

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-28 | #71 | unplanned |

> A `store` crate with optional Redis and PostgreSQL backends, so several
> dvarapala replicas behind one load balancer enforce one per-client
> limit, one egress budget per destination and one list of heavy hitters,
> without a network call on the request path.

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

A synchronous store call per request would fix the counts, but adds a
round trip (0.2 to 1 ms in one zone) to every request, makes the store
the first thing an attacker saturates, and turns a store outage into a
gateway outage.

## Proposal

- `[store] backend = "memory"` (default) keeps today's behavior: no
  change, no new socket. `backend = "redis"` or `backend = "postgres"`
  with `store.url` shares state between every replica that uses the same
  store and `store.cluster` name. Both backends implement the same
  `Store` trait and pass the same tests; the choice is whichever the
  deployment already runs.
- Nothing on the request path waits for the store. Each replica keeps its
  local state as today and syncs in the background every
  `store.sync_interval` (default 1 s). Limits are therefore approximate,
  with a bounded overshoot (below), never a hard dependency.
- **Replica count:** each replica writes a heartbeat that expires after
  three intervals and reads how many are alive.
  `dvarapala_store_replicas` reports it.
- **Per-client limit:** the local token bucket stays at the full rate
  (exact when the load balancer pins a client to one replica). On top,
  every interval each replica adds the requests it allowed per active
  client to a cluster counter for the current window (at most
  `store.max_keys` clients per sync, busiest first, in one round trip).
  When a client's cluster count for the window is over
  `rate x window + burst`, every replica throttles it locally until the
  window ends. Overshoot is at most `N x rate x sync_interval` per window.
- **Forward proxy:** a destination's rate, burst and `max_concurrent` are
  divided by the live replica count on every sync, so the cluster never
  sends above the agreement (fail closed toward the provider). A provider
  pause (`Retry-After`) seen by one replica is published and applies on
  all.
- **Heavy hitters:** in `enforce` mode each replica publishes the
  prefixes its detector marks as heavy, expiring after
  `detection.cooldown_windows` windows; every replica drops them too.
  Detection state (`Normal` to `Attack`) stays per replica.
- **Lost store: fail open to local limits**, as `CLAUDE.md` allows for
  this case. Local buckets and detection keep working; the cluster
  counters and the shared drop list stop growing and expire. The last
  known replica count is kept for the forward split, so egress stays
  under the agreement. Logged once as `msg="store unavailable"`, and
  `msg="store recovered"` when it comes back; reconnects back off up to
  `store.sync_interval x 10`.

### Redis backend

One sync round is one pipeline: `SET` the heartbeat with `PX`, `SCAN`
the heartbeat keys for the count, `INCRBY` and `PEXPIRE` per client
window key, `SET ... PX` for pauses and heavy hitters, `MGET` the window
keys this replica cares about. Keys are `<cluster>:<kind>:<id>`; Redis
TTLs do the expiry.

### PostgreSQL backend

For deployments that run PostgreSQL and no Redis, for example a
CloudNativePG cluster. Counters live in `UNLOGGED` tables in their own
schema:

```sql
CREATE UNLOGGED TABLE IF NOT EXISTS dvarapala.counters (
  cluster text, key text, window_start bigint, count bigint,
  expires_at timestamptz,
  PRIMARY KEY (cluster, key, window_start));
-- heartbeats(cluster, replica, expires_at)
-- marks(cluster, kind, key, expires_at)  -- pauses and heavy hitters
```

- One sync round is one transaction of a few statements, never one per
  client: window counts go up as arrays,
  `INSERT ... SELECT * FROM unnest($1, $2, $3) ON CONFLICT DO UPDATE SET
  count = counters.count + EXCLUDED.count RETURNING key, count`, so the
  same statement returns the cluster totals. Heartbeat and marks are
  upserts the same way; the live replica count is a `count(*)` over
  unexpired heartbeats.
- Expiry: reads filter on `expires_at > now()`, and one replica at a time
  (`pg_try_advisory_lock`) deletes expired rows every 10 intervals, in
  batches, so the tables stay small.
- `UNLOGGED` skips the WAL: cheaper writes, and the counters are not
  replicated to standbys and are emptied after a crash or failover. That
  is acceptable, since a counter reset is the same as a short store
  outage: replicas fall back to local limits for at most one window.
- Schema: numbered migrations in `crates/store/migrations/` (`0001.sql`,
  `0002.sql`, ...), embedded in the binary with `include_str!`. A
  `dvarapala.schema_version` table holds the last one applied. With
  `store.migrate = true` (the default) the backend takes
  `pg_advisory_lock`, applies the missing files in order, each in its own
  transaction with its version bump, and releases the lock, so replicas
  starting together migrate once. With `store.migrate = false` it only
  checks the version and runs with a role that has `SELECT`, `INSERT`,
  `UPDATE` and `DELETE` on the `dvarapala` schema.
- `dvarapala store schema` prints the SQL to apply by hand, from the
  version given with `--from <n>` (default 0) to the binary's, with the
  `schema_version` updates included. It needs no config and no database,
  so the output can go into a CloudNativePG
  `bootstrap.initdb.postInitApplicationSQLRefs` ConfigMap or any
  migration tool. Release assets include the same files.
- Version mismatch: a database older than the binary with `migrate =
  false`, or newer than the binary (a rollback), counts as a store
  failure: `store unavailable` names both versions and local limits
  apply. Since the tables only hold counters that expire within a
  window, a migration may drop and recreate a table instead of
  converting rows.
- Connection: `store.url` is a libpq URL; TLS follows `sslmode`
  (`require`, `verify-ca`, `verify-full`) with rustls. With CloudNativePG,
  point it at the `<cluster>-rw` service or a `Pooler` in transaction
  mode: the backend uses unnamed prepared statements only, so it works
  through PgBouncer.
- `LISTEN/NOTIFY` for instant pauses is left out: one sync interval of
  delay is within the forward proxy's budget, and NOTIFY does not pass
  through a transaction-mode pooler.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/cluster.rs` | pure merge rules: window counts to verdict overrides, budget split by replica count, overshoot bound. Time and counts as input |
| `crates/store/src/lib.rs` | the `Store` trait: heartbeat, add and read window counts, publish and read the drop list and pauses |
| `crates/store/src/memory.rs` | single-process backend, the default; also the test double |
| `crates/store/src/redis.rs` | Redis backend: one pipeline per round, one connection, reconnect with backoff |
| `crates/store/src/postgres.rs` | PostgreSQL backend: one transaction per round, schema creation, expiry sweep |
| `crates/store/src/migrate.rs` | PostgreSQL migrations: the embedded list, version check, apply under an advisory lock, render for `store schema` |
| `crates/store/migrations/NNNN.sql` | one file per schema version, never edited after release |
| `crates/dvarapala/src/main.rs` | the `store schema [--from <n>]` subcommand |
| `crates/store/src/sync.rs` | the background task that drains local deltas into the store and applies what comes back |
| `crates/l7/src/rate_limit.rs` | consult the cluster overrides and the shared drop list before the local bucket |
| `crates/proxy/src/forward/shaper.rs` | apply the replica split and shared pauses |
| `crates/dvarapala/src/config/store.rs` | `[store]` section |

`engine` keeps no I/O: it gets counts in and returns decisions, and the
sync task in `store` does the talking. Clients, each behind its own cargo
feature so the default binary does not grow, and each must pass
`cargo deny check`:

- `redis` feature: the `redis` crate (BSD-3-Clause) with `tokio-comp`
  and rustls for `rediss://`.
- `postgres` feature: `tokio-postgres` (MIT or Apache-2.0) with
  `tokio-postgres-rustls` for TLS. No `sqlx`: it brings macros, a
  migration runner and more dependencies than three tables need.

### Configuration

| Key | Default | |
|---|---|---|
| `store.backend` | `"memory"` | `"memory"`, `"redis"` or `"postgres"`; `"memory"` turns sharing off |
| `store.url` | unset | Required with a shared backend. `redis://<host>:6379/0`, `rediss://` for TLS; or `postgres://<user>@<host>:5432/<db>?sslmode=verify-full`. The password goes in the URL or `DVARAPALA__STORE__URL`, and is never logged |
| `store.cluster` | `"dvarapala"` | Key prefix (Redis) or `cluster` column (PostgreSQL); replicas with the same store and name share state |
| `store.sync_interval` | `"1s"` | How often each replica syncs; shorter is tighter and costs more store round trips |
| `store.max_keys` | `10000` | Clients synced per interval at most, busiest first |
| `store.timeout` | `"500ms"` | One sync round slower than this counts as a failure |
| `store.migrate` | `true` | PostgreSQL only: apply missing migrations at start; `false` only checks `schema_version` |

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

Cases 5 to 11 run once per shared backend, against a Redis service and a
PostgreSQL service in CI.

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `backend = "memory"` | start | no store task, no socket, behavior and metrics as before | integration (`dvarapala`) |
| 2 | window counts from 3 replicas over the limit | merge | the client is throttled until the window ends | unit (`engine::cluster`) |
| 3 | rate 20, 4 replicas, interval 1 s | overshoot bound | at most 80 extra requests per window | unit (`engine::cluster`) |
| 4 | destination rate 50, 2 then 3 live replicas | split | 25, then 16.67 per replica; burst and `max_concurrent` rounded down, at least 1 | unit (`engine::cluster`) |
| 5 | two proxies on one store, one client round robin, rate 10 | 100 requests in 1 s | at most `10 + burst + overshoot` reach the upstream | integration (`store/tests`) |
| 6 | two forward proxies on one store, destination rate 10 | callers on both send 100 rps | the test upstream sees at most 10 rps plus burst | integration (`store/tests`) |
| 7 | a provider `429` with `Retry-After: 2` on replica A | next request on replica B | B waits or refuses as paused | integration (`store/tests`) |
| 8 | heavy hitter found on A, `enforce` | it sends to B | B drops it after one sync | integration (`store/tests`) |
| 9 | the store stops | traffic continues | local limits apply, `store_up` 0, one `store unavailable` log, no request waits | integration (`store/tests`) |
| 10 | the store comes back | next round | counters resume, one `store recovered` log | integration (`store/tests`) |
| 11 | 50 000 active clients, `max_keys` 10 000 | one sync | 10 000 busiest synced, `keys_dropped_total` 40 000, round under `timeout` | integration (`store/tests`) |
| 12 | `store.url` with a password | any log or error | the password does not appear | unit (`config`) |
| 13 | `backend = "redis"` or `"postgres"`, no `url` | start | config error naming `store.url` | unit (`config`) |
| 14 | arbitrary bytes as a Redis reply | the backend parses it | no panic, an error | fuzz (`store_reply`) |
| 15 | sync task on a busy proxy | bench | request latency p99 unchanged within noise, sync under 5 ms for 10 000 keys on loopback | bench (`store/benches`) |
| 16 | PostgreSQL, empty database, `migrate = true` | two replicas start at once | every migration applied once, `schema_version` is the binary's | integration (`store/tests`) |
| 17 | PostgreSQL, `migrate = false`, schema missing or older | start | `store unavailable` naming both versions, local limits apply | integration (`store/tests`) |
| 18 | PostgreSQL at version 1, binary at version 2 | start with `migrate = true` | only `0002.sql` runs, version 2 | integration (`store/tests`) |
| 19 | database newer than the binary | start | `store unavailable` naming both versions, no migration runs | integration (`store/tests`) |
| 20 | `dvarapala store schema --from 1` | run without config | prints migrations after 1 with their version updates; applied by `psql` it gives the same schema as `migrate = true` | integration (`dvarapala`) |
| 21 | released migration files | CI | a changed released file fails the build (checksum list in `migrate.rs`) | unit (`store::migrate`) |
| 22 | PostgreSQL, rows past `expires_at` | sweep | deleted by one replica only, unexpired rows kept | integration (`store/tests`) |
| 23 | PostgreSQL through PgBouncer in transaction mode | cases 5 and 9 | same results | integration (`store/tests`) |

The PostgreSQL wire protocol is parsed by `tokio-postgres` and the reply
values are typed columns, so no separate fuzz target; case 14 covers the
Redis client, whose replies are untyped.

## Alternatives

| Option | Why not |
|---|---|
| Synchronous store call per request (GCRA in Lua) | exact, but a round trip on every request, the store becomes the attack target, and an outage stops traffic |
| Divide every per-client rate by `N` | wrong when the load balancer pins clients: a client on one replica would get `rate / N` |
| Gossip between replicas (no store) | membership, discovery and NAT handling are more work than one Redis or PostgreSQL most clusters already run |
| Sticky load balancing only | out of our control, and still leaves the forward proxy and heavy hitters per replica |
| Envoy-style external rate limit service | another service to run, and again synchronous on the request path |
| PostgreSQL with logged tables | WAL and replication for counters that are worthless after a minute |
| PostgreSQL `hstore` or `jsonb` as a key/value column | one hot row for every replica, lock contention; a row per key spreads it |

## Security and resource limits

- The store is trusted: anyone who can write the keys or rows can
  throttle clients or pause destinations. Use a store only the replicas
  reach, a password, and TLS (`rediss://`, `sslmode=verify-full`) across
  untrusted networks.
- PostgreSQL: give dvarapala its own role and schema, never a superuser
  or an application database's owner. With `migrate = false` the role
  needs no DDL rights. All values are bound parameters, never SQL text.
- An attacker controls which clients are active, not what is synced:
  `max_keys` bounds the work and the keys or rows per round, busiest
  first, so a spoofed-source flood of single requests costs at most
  `max_keys` entries per interval, each expiring after two windows.
- Memory per replica: the local delta map is bounded by the existing
  `rate_limit.max_clients` table, plus the shared drop list capped at the
  detector's `top_k` per replica.
- No request path code waits on the store, so a slow or hostile store
  costs sync rounds, never request latency. On PostgreSQL every round
  sets `statement_timeout` to `store.timeout`, so a stuck round does not
  hold locks.

## Rollout

- **Rollout:** unplanned. Default `memory`, so upgrading changes nothing.
  The `redis` and `postgres` cargo features are off by default; release
  binaries may ship with them once the footprint job measures them.
- **Off switch:** `store.backend = "memory"`, or stop the store: replicas
  fall back to local limits.
