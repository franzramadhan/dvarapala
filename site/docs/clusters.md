---
title: Clusters
---

A replica is one dvarapala process in a group that serves the same app.
One replica holds each client to `rate`. Behind a load balancer, each of
several replicas also holds the client to `rate`. Thus a client spread
across N replicas gets N times its limit.

A store gives the replicas one shared view. This view has one limit per
client and one list of heavy hitters (the network prefixes with the most
traffic). In forward mode, it also has one budget per destination.

## Run it

The container image has both backends. The release tarballs (and thus
Homebrew and `install.sh`) have neither. With those binaries, a shared
backend fails at start with `store.backend = "redis" needs a binary built
with the redis feature`.

1. Use the image, or build with the backend that you need
   (`--features redis`, `--features postgres`, or both).
2. Point each replica at the same store and cluster name:

```toml
[store]
backend = "redis"
url = "rediss://<host>:6379/0"   # or postgres://<user>@<host>:5432/<db>
cluster = "app"
sync_interval = "1s"
```

Put the password in `DVARAPALA__STORE__URL`, not in the file. dvarapala
never logs this variable. If the replicas are behind a load balancer, also
put the load balancer in `trusted_proxies`.

## What is shared

- Per-client limit: each replica adds the requests that it allowed to a
  cluster count per window (10 sync intervals). If a client goes over
  `rate x window + burst` in the cluster, every replica throttles it until
  the window ends. A count reaches the other replicas within two sync
  periods. This sets the maximum overshoot.
- Heavy hitters: if detection drops a prefix in `enforce` mode on one
  replica, all replicas drop it for `cooldown_windows` windows.
- Forward mode: dvarapala divides the `rate`, `burst` and
  `max_concurrent` of each destination by the number of live replicas. If
  one replica gets a `Retry-After` from a provider, the destination pauses
  on all replicas.

## When the store goes away

Nothing on the request path waits for the store. Each replica decides
from local state and syncs in the background. If the store is lost, each
replica fails open to its local limits. dvarapala logs this once as
`store unavailable`, and later as `store recovered`. Forward mode keeps
the last replica count, so outbound traffic stays under the agreement.

## PostgreSQL

The tables are `UNLOGGED`, in the `dvarapala` schema. dvarapala migrates
them at start (with `migrate = false`, it only makes sure that the version
is correct). With CloudNativePG, use the
`<cluster>-rw` service or a `Pooler` in transaction mode.
`dvarapala store schema` prints the migration SQL to apply by hand.

## Watch it

`dvarapala_store_up` is 1 while the sync works.
`dvarapala_requests_total{scope="cluster"}` counts refusals that come from
the cluster count or the drop list, not from the local bucket. Every key and
metric is in [Configuration](configuration.html#store).
