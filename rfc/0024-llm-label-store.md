# 0024: LLM labels in the PostgreSQL store

| Status | Date | PR | Release |
|---|---|---|---|
| accepted | 2026-10-30 | #212 | |

> With `ml.llm.persist`, every replica writes its LLM labels (RFC 0023)
> as rows in the PostgreSQL store (RFC 0010) instead of a file of its
> own. Training data, the console's recent labels and the counts then
> cover all replicas and survive restarts, and `GET /llm/export` streams
> them as JSON lines.

## Problem

RFC 0023 keeps labels in two places, both local to one process:

- `ml.llm.export` appends JSON lines to a file. With 2 or more replicas
  each pod needs its own writable volume, and the training set is split
  over N files that someone has to collect and merge. A Deployment
  without a volume (read-only root, the operator's gateways, the
  `FROM scratch` image) cannot export at all.
- `GET /llm` (`counts` since start, the last 200 `recent`) is the memory
  of the one pod that answers. Behind a Service, two console loads can
  show two different lists, and a rollout empties both.

A lab with 2 replicas behind a load balancer and the `postgres` store
already on (RFC 0022 runs `history.persist` the same way) has the
database it needs. This RFC uses it.

## Proposal

- **Persist (optional, PostgreSQL only).** With `ml.llm.persist = true`
  and `store.backend = "postgres"`, each labeled sample becomes one row in
  `dvarapala.llm_labels`: the cluster, the replica, the time, the
  trigger, the route, the method, the redacted path (as sent to the
  model), the label, the confidence, the pattern, and the 10 `[ml]`
  feature columns as a `jsonb` object. The row holds what the export file
  line holds today, plus the request fields the console shows.
- **Writes off the request path.** Labels already arrive in the
  background worker, after the model answers. The worker queues rows in
  a bounded buffer (`ml.llm.persist_queue`, default 1024); a writer task
  inserts them in batches (up to 100 rows, at least every 5 s), one
  batch in flight. A full buffer drops the new row and counts it.
- **Fail open, as RFC 0022.** A failed write is logged once (`llm store
  unavailable`, then `llm store recovered`), the batch is dropped and
  counted, and labeling goes on: logs, metrics and the in-memory `recent`
  and `counts` still work. Labels never touched a verdict and still do
  not.
- **`GET /llm` from the store.** With `persist`, `counts` are the last
  24 h summed over the cluster's replicas, and `recent` is the cluster's
  last 200, newest first. The answer gains `"source": "store"` (or
  `"memory"`, with the per-pod values of today, when `persist` is off or
  the read fails). The console shows "all replicas, last 24 h" or "this
  replica since start" from that field.
- **`GET /llm/export`** on the admin listener: the rows as JSON lines,
  the same columns as the `ml.llm.export` file, streamed from a
  server-side cursor. Query parameters `since` and `until` (RFC 3339 or
  Unix ms), `label` and `trigger` (repeatable). `409` without `persist`.
  Same auth as the other admin calls. `psql -c "\copy (...) to ..."`
  stays possible for anyone with database access; the endpoint is for
  those without.
- **Retention.** Rows older than `ml.llm.retention` (default `30d`) are
  deleted by the writer once an hour, at most 10 000 rows per sweep,
  under its own advisory lock (as RFC 0022's history), so one replica
  sweeps at a time.
- **The file stays.** `ml.llm.export` works as today for one instance
  without PostgreSQL. Both can be on at once.
- **Migration 3** adds the table and its indexes; it applies at start
  with `store.migrate = true`, or is printed by
  `dvarapala store schema --from 2`.

### Domain

| Crate / module | Responsibility |
|---|---|
| `crates/store/src/labels.rs` | PostgreSQL: insert a batch, read counts and recent for a cluster, stream an export range, delete expired rows |
| `crates/store/src/migrate.rs` | Migration 3: `dvarapala.llm_labels` (logged), indexes on `(cluster, at)` and `(cluster, label, at)` |
| `crates/store/migrations/0003.sql` | The DDL |
| `crates/dvarapala/src/llm/persist.rs` | The bounded buffer, the writer task, batches, retention, the fail-open logging |
| `crates/dvarapala/src/llm/labels.rs` | `GET /llm` from the store with the memory fallback |
| `crates/dvarapala/src/admin/llm.rs` | `GET /llm/export`: the streamed body |
| `crates/l7/src/llm/export.rs` | Parsing the `GET /llm/export` parameters (client input, so fuzzed by the `admin_query` target) |
| `ui/src/pages/Llm.tsx` | The `source` line; an "Export" link with a date range |

### Configuration

| Key | Default | |
|---|---|---|
| `ml.llm.persist` | `false` | Write labels to the PostgreSQL store. Needs `store.backend = "postgres"` (an error at start otherwise) and a build with the `postgres` feature (the container image has it). Restart |
| `ml.llm.persist_queue` | `1024` | Rows waiting for the writer; a full buffer drops new rows (`dropped`). 1 to 65 536. Restart |
| `ml.llm.retention` | `"30d"` | Rows older than this are deleted. At least `1h`. Reload |

`ml.llm.persist = false` turns it off; the table stays until dropped by
hand. `ml.llm.export` and `ml.llm.export_max` are unchanged.

### Logs and metrics

| | |
|---|---|
| `msg="llm store unavailable" error=...` | Warn, once per outage; `GET /llm` answers from memory |
| `msg="llm store recovered"` | Info, once |
| `dvarapala_llm_store_rows_total{result="ok"\|"error"\|"dropped"}` | Rows written, lost with a failed batch, or dropped on a full buffer |
| `dvarapala_llm_store_rows_deleted_total` | Rows removed by retention |
| `dvarapala_llm_export_rows_total` | Rows streamed by `GET /llm/export` |

## Test cases

| # | Given | When | Then | Kind |
|---|---|---|---|---|
| 1 | `ml.llm.persist = true`, `store.backend = "memory"` | config load | Error naming `ml.llm.persist` | unit |
| 2 | `ml.llm.retention = "10m"` | config load | Error naming `ml.llm.retention` (at least `1h`) | unit |
| 3 | A buffer of 2, the writer blocked | 3 labels | 2 queued, `rows_total{result="dropped"}` 1 | unit |
| 4 | 250 labels queued | the writer runs | 3 batches (100, 100, 50), in order | unit |
| 5 | `since=yesterday&label=scanner&trigger=waf&trigger=attack` | parse | The range and the filters | unit |
| 6 | `since=abc`, `label=` over 32 values, a `since` after `until` | parse | `400` naming the parameter | unit |
| 7 | A labeled sample | written and read back | The row's export line equals the `ml.llm.export` file's line for the same sample | integration (PostgreSQL) |
| 8 | Two replicas of one cluster, each with labels | `GET /llm` on either | The same `recent` (merged, newest first) and summed `counts`, `source` `store` | integration (PostgreSQL) |
| 9 | Labels of another `store.cluster` in the table | `GET /llm` | Only this cluster's rows | integration (PostgreSQL) |
| 10 | PostgreSQL stopped | a label, then `GET /llm` | One warn log, the label in memory `recent`, `source` `memory` | integration (PostgreSQL) |
| 11 | Rows older than `retention` | the sweep runs | They are deleted, newer ones stay | integration (PostgreSQL) |
| 12 | 10 000 rows | `GET /llm/export` | 10 000 JSON lines, streamed (the body starts before the last row is read) | integration (PostgreSQL) |
| 13 | No admin auth | `GET /llm/export` | `401`, as `GET /llm` | integration |
| 14 | `persist = false` | `GET /llm/export` | `409` | integration |
| 15 | A database at schema version 2 | start with `migrate = true` | Migration 3 applied; `store schema --from 2` prints it | integration (PostgreSQL) |
| 16 | The `GET /llm/export` parser | fuzz | No panic | fuzz |
| 17 | The console with `source` `store` | the LLM page opens | "All replicas, last 24 h" and the export link | UI (Vitest) |

## Alternatives

| Option | Why not |
|---|---|
| A volume per pod for the file, collected later | N files to merge; no volume on read-only and operator-made gateways; the console stays per pod |
| A `ReadWriteMany` volume shared by the replicas | Needs a RWX storage class (NFS, CephFS), and concurrent appends to one file interleave lines without file locking that network file systems do not all honor |
| Ship labels to the logs only, train from VictoriaLogs or Loki | Works today (`msg="llm label"`), but the feature columns would have to be logged on every label, and training then depends on a log store's query API and retention |
| Redis | Fits counters, not a queryable training table; the PostgreSQL store is where durable rows already live (RFC 0022) |
| SQLite | One instance only, the case the file already covers; adds C SQLite to the binary (RFC 0022 ruled it out) |
| Raw `jsonb` line only, no columns | The console's filters and the retention sweep need `at`, `label` and `trigger` as columns with indexes; the features stay `jsonb` because training reads them whole |
| Share the console sampling switch (`POST /llm`) through the store too | Useful with replicas (today it reaches one pod), but it is control, not data. Later, with the other admin switches (`POST /mode`), in an RFC of its own |

## Security and resource limits

- The attacker controls the request, so a row's path, method and route
  are attacker data. They are the redacted values RFC 0023 already sends
  to the model (no cookies, no auth headers, query values masked, cut to
  512 bytes). They go to SQL as bound parameters only. A row is under
  1 KiB.
- Write volume is bounded by sampling, not traffic: `per_client`
  deduplication, the trigger rates and the model's `concurrency`. At most
  one row per model answer. The buffer is fixed at `persist_queue` rows
  (about 1 MiB at the default).
- Disk is bounded by `retention`. At 1 label per second, `30d` is about
  2.6 M rows, under 3 GiB with indexes; a smaller lab writes far less.
  The sweep deletes in batches of 10 000 so it never holds long locks.
- `GET /llm/export` is behind the admin auth. Its body streams from a
  cursor with a bounded fetch size, so memory does not grow with the
  range. It reads one cluster's rows only.
- Paths can carry personal data (an e-mail in a URL path segment). The
  rows keep it for `retention`, as the logs keep it for theirs; the
  operator sets both. `CONFIG.md` says so next to the key.

## Rollout

- **Rollout:** a minor release. Off until `ml.llm.persist = true`.
  Migration 3 applies at start with `store.migrate = true`, or
  `dvarapala store schema --from 2` prints it for a role without DDL
  rights.
- **Off switch:** `ml.llm.persist = false` and a restart. Labels go back
  to memory and the file; the table stays until dropped by hand.
