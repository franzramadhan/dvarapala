# 0022: Traffic history for the console

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-30 | #178 | |

> The gateway keeps its own traffic history: a ring buffer in memory,
> always on with the console, and optionally a per-minute history in the
> PostgreSQL store. The overview graph then survives a page reload, a new
> tab and (with PostgreSQL) a restart.

## Problem

The overview graph (RFC 0018) is built in the browser: `ui/src/history.ts`
turns the `GET /status` polls (every 2 s) into rates per verdict and keeps
15 minutes in the tab's memory. So:

- A page reload, a new tab or a second operator starts with an empty graph.
  During an attack, the person who opens the console last sees nothing of
  how it started.
- A gateway restart loses even the counters, and with several replicas each
  tab sees only the replica its request landed on.

Operators who need weeks of history have Prometheus (`GET /metrics`). This
RFC is about the console: the last minutes always, the last days when a
store is already there.

## Proposal

- **Ring buffer (always on with the admin listener).** A background task
  samples the verdict counters every `history.interval` (default `5s`) and
  keeps `history.window` (default `15m`, so 180 samples) in a fixed-size
  ring. A sample is the rate per second of each verdict (`allow`,
  `throttle`, `challenge`, `drop`, `error`) over the interval, plus the
  detection state at the sample time. Memory is fixed at start: about
  `window / interval x 64` bytes (12 KiB at the defaults).
- **`GET /history?range=<range>`** on the admin listener, same auth as
  `GET /status`. `range` is one of `15m`, `1h`, `6h`, `24h`, `7d` (default
  `15m`). The answer:

  ```json
  {"interval_ms": 5000, "source": "memory", "samples": [
    {"t": 1767225600000, "allow": 41.2, "throttle": 0.4, "challenge": 0,
     "drop": 0, "error": 0, "detection": "normal"}]}
  ```

  Without the store, a range longer than `history.window` answers what the
  ring holds, with `"source": "memory"`, so the console can say "the last
  15 minutes only".
- **Persistent history (optional, PostgreSQL only).** With
  `history.persist = true` and `store.backend = "postgres"`, each replica
  writes one row per minute (the sums of its samples) to
  `dvarapala.traffic_history`, keyed by `(cluster, replica, minute)`. A
  range longer than the ring reads from the table, summed over the
  replicas of the cluster, with `"source": "store"` and `interval_ms`
  60000. The last `history.window` still comes from the ring, at full
  resolution. Rows older than `history.retention` (default `7d`) are
  deleted by the replica that runs the store's existing expiry sweep.
- **Fail open.** A failed write or read is logged once (`history store
  unavailable`, then `history store recovered`) and `GET /history` answers
  from the ring with `"source": "memory"`. The request path never waits on
  the history: writes run in the background task and drop a minute rather
  than queue it.
- **Console.** The overview loads `GET /history` once, then appends the
  `GET /status` polls as today. With the persistent history it shows a
  range picker (`15m`, `1h`, `6h`, `24h`, `7d`); without it, the graph
  says it shows this replica's last `history.window`.
- **Replay** (RFC 0016) and forward mode: the ring works the same in
  forward mode (its verdicts are the egress verdicts). Replay has no admin
  listener and does not record history.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/engine/src/history.rs` | `Ring`: fixed capacity, push a sample, read a range; minute roll-up. No I/O |
| `crates/store/src/history.rs` | PostgreSQL: write a minute row, read a range summed over replicas, delete expired rows |
| `crates/store/src/migrate.rs` | Migration 2: `dvarapala.traffic_history` (a logged table, unlike the `UNLOGGED` limit tables, so it survives a failover) |
| `crates/dvarapala/src/admin/history.rs` | The sampling task, `GET /history`, falling back to the ring |
| `ui/src/history.ts`, `ui/src/pages/Overview.tsx` | Load the history once, the range picker |

### Configuration

| Key | Default | |
|---|---|---|
| `history.interval` | `"5s"` | Sample period of the ring. At least `1s`. Restart |
| `history.window` | `"15m"` | How much the ring keeps; at most 10 000 samples (`window / interval`). Restart |
| `history.persist` | `false` | Write a row per minute to the PostgreSQL store. Needs `store.backend = "postgres"` (an error at start otherwise) and a build with the `postgres` feature (the container image has it). Restart |
| `history.retention` | `"7d"` | Rows older than this are deleted. At least `1h`. Reload |

The ring runs whenever `admin.listen` is set; there is no separate switch
(12 KiB). `history.persist = false` turns the PostgreSQL part off; the
table stays until dropped by hand.

### Logs and metrics

| | |
|---|---|
| `msg="history store unavailable" error=...` | Warn, once per outage; `GET /history` answers from memory |
| `msg="history store recovered"` | Info, once |
| `dvarapala_history_writes_total{result="ok"\|"error"\|"skipped"}` | Minute rows written, failed, or dropped because the previous write was still running |
| `dvarapala_history_rows_deleted_total` | Rows removed by retention |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | A ring of 3 | 5 samples pushed | It holds the last 3, oldest first | unit |
| 2 | Counters 100 then 150 over 5 s | a sample is taken | `allow` is 10.0 per second | unit |
| 3 | Counters that go down (a restart of the counters) | a sample is taken | The sample is skipped, not negative | unit |
| 4 | 12 samples of 5 s | rolled up to minutes | One minute row with the sums | unit |
| 5 | `history.window = "15m"`, `interval = "1ms"` | config load | Error naming `history.interval` (over 10 000 samples and under `1s`) | unit |
| 6 | `history.persist = true`, `store.backend = "memory"` | start | Error naming `history.persist` | integration |
| 7 | A running gateway with traffic | `GET /history` | 200, `source` `memory`, samples with rates | integration |
| 8 | No admin auth | `GET /history` | 401, as `GET /status` | integration |
| 9 | `range=2d` | `GET /history` | 400 naming the allowed ranges | integration |
| 10 | PostgreSQL, two replicas writing the same minute | `GET /history?range=1h` | One point per minute with the sum of both, `source` `store` | integration (PostgreSQL) |
| 11 | PostgreSQL stopped | a minute passes, then `GET /history?range=1h` | One warn log, `writes_total{result="error"}` 1, answer from memory | integration (PostgreSQL) |
| 12 | Rows older than `retention` | the sweep runs | They are deleted, newer ones stay | integration (PostgreSQL) |
| 13 | A database at schema version 1 | start with `migrate = true` | Migration 2 applied; `store schema --from 1` prints it | integration (PostgreSQL) |
| 14 | The console with history | the overview opens | The graph shows the samples from `GET /history` before the first poll | UI (Vitest) |
| 15 | The console with `source` `store` | the range picker is set to `24h` | `GET /history?range=24h` and a graph of 1 minute points | UI (Vitest) |
| 16 | Idle binary with the admin listener | footprint job | RSS still under the RFC 0001 budget | CI |

## Implementation notes

Deviations found while building:

- Retention runs in the history task, once every 60 minute rows, under its
  own advisory lock (`pg_try_advisory_xact_lock(hashtext('dvarapala.history'))`)
  and at most 10 000 rows per sweep, not in the store's sync sweep: the
  history has its own connection and does not depend on the shared limiter
  being on.
- The ring runs only when `admin.listen` is set, and `[history]` is
  validated only then (with a reload too).
- An answer that includes store points reports `interval_ms` 60000 for the
  whole answer, even though its tail comes from the ring at `interval`.
- Store points carry `"detection": null`; minute rows keep no state.
- Case 10 (two replicas, one point per minute) is tested at the store level
  (`history_read` sums the replicas); case 11 checks the answer from memory
  and the single log line, not the `writes_total{result="error"}` counter,
  which a minute boundary would make slow and flaky.
- The console shows the range picker only when the `15m` answer says
  `"source": "store"`; otherwise the graph says "This replica, last 15
  minutes". Longer ranges come from `GET /history` alone, without the
  polls.

## Alternatives

| Option | Why not |
|---|---|
| Keep it in the browser (`localStorage`) | Survives a reload in one browser only; a second operator or a new device still starts empty, and nothing survives a restart |
| SQLite for single instances | `rusqlite` bundles C SQLite: binary size and musl build work for what the ring covers until a restart. Can come later as another `history` backend if restart survival on one instance matters |
| Redis for the persistent history | Possible with a sorted set per replica, but the PostgreSQL store is where durable rows already fit (a logged table, SQL for the sums). Later if asked |
| Query Prometheus from the console | Needs a Prometheus URL and its auth in the gateway, and many deployments scrape without keeping a query API reachable. Prometheus stays the answer for weeks of history |
| Persist at the 5 s resolution | 12 times the rows for little gain in a console graph; the ring keeps full resolution for the recent part |

## Security and resource limits

- The attacker controls only the traffic, which moves counters, not the
  size of anything: the ring is allocated once, rows are one per replica
  per minute (10 080 per replica at `7d`).
- `range` is an enum; an unknown value is a 400. No user value reaches the
  SQL, which uses bound parameters.
- `GET /history` is behind the admin auth (token, cookie session or OIDC)
  like every other admin call, and reads at most 10 080 x replicas rows
  (summed in SQL, so the answer is at most 10 080 points).
- A slow PostgreSQL cannot pile up work: one write at a time, a minute
  whose write is still running is skipped and counted.

## Rollout

- **Rollout:** v0.15.0. The ring is on with the admin listener, no config
  needed. The persistent history is off until `history.persist = true`;
  migration 2 is applied at start with `store.migrate = true`, or printed
  by `dvarapala store schema --from 1` for a role without DDL rights.
- **Off switch:** `history.persist = false` and a restart. The ring has no
  switch: it is a fixed 12 KiB.
