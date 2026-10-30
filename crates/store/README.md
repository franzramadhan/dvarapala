# dvarapala-store

Shared state for [dvarapala](https://github.com/franzramadhan/dvarapala) clusters: replicas behind one load
balancer share one per-client limit, one heavy hitter list and, in
forward mode, one budget per destination. A background task syncs each
replica's `dvarapala_engine::Cluster` with the store every
`sync_interval`; nothing on the request path waits for it, and a lost
store falls back to local limits.

| Feature | Adds |
|---|---|
| (none) | In-memory backend |
| `redis` | Redis backend |
| `postgres` | PostgreSQL backend (`UNLOGGED` tables, migrated at start) |

See [Clusters](https://dvarapala.franzramadhan.dev/docs/clusters.html).

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
