---
title: Clusters
---

One replica holds each client to `rate`. Several replicas behind a load
balancer each hold it to `rate` too, so a client spread across N replicas
gets N times its limit. A store gives the replicas one shared view: one
per-client limit, one list of heavy hitters, and in forward mode one
budget per destination.

## Run it

Build with the backend you need (`--features redis`, `--features
postgres`, or both), then point every replica at the same store and
cluster name:

```toml
[store]
backend = "redis"
url = "rediss://<host>:6379/0"   # or postgres://<user>@<host>:5432/<db>
cluster = "app"
sync_interval = "1s"
```

Put the password in `DVARAPALA__STORE__URL`, not the file; it is never
logged. Behind a load balancer, also list it in `trusted_proxies`.

## What is shared

- **Per-client limit:** each replica adds the requests it allowed to a
  cluster count per window (10 sync intervals). A client over `rate x
  window + burst` in the cluster is throttled on every replica until the
  window ends. A count reaches the other replicas within two sync
  periods, which bounds the overshoot.
- **Heavy hitters:** a prefix that detection drops in `enforce` mode on
  one replica is dropped on all of them for `cooldown_windows` windows.
- **Forward mode:** each destination's `rate`, `burst` and
  `max_concurrent` are divided by the live replica count, and a provider
  `Retry-After` seen by one replica pauses the destination on all.

## When the store goes away

Nothing on the request path waits for the store. Each replica decides
from local state and syncs in the background, so a lost store is a
fail-open to local limits, logged once as `store unavailable` and
`store recovered`. Forward mode keeps the last replica count, so egress
stays under the agreement.

## PostgreSQL

Tables are `UNLOGGED`, in the `dvarapala` schema, migrated at start
(`migrate = false` only checks the version). With CloudNativePG, use the
`<cluster>-rw` service or a `Pooler` in transaction mode.
`dvarapala store schema` prints the migration SQL to apply by hand.

## Watch it

`dvarapala_store_up` is 1 while syncing works;
`dvarapala_requests_total{scope="cluster"}` counts refusals from the
cluster count or drop list rather than the local bucket. Every key and
metric is in [Configuration](configuration.html#store).
