---
title: Protection layers
---

Each layer is optional. This page says what each one stops, how it
answers, and which keys to look at first. The full list of keys is in
[Configuration](configuration.html).

## Rate limit

A token bucket per client: `rate` tokens per second, up to `burst`. An
empty bucket answers `429` with `Retry-After`, without contacting the
upstream. The client table holds `max_clients` entries and evicts the
least recently seen one, so a spoofed-source flood cannot grow memory.

Behind a load balancer, list it in `trusted_proxies`: only those peers may
set `X-Forwarded-For`. Everyone else is keyed by their own address.

Keys: [`[rate_limit]`](configuration.html#rate_limit), `trusted_proxies`.

## Adaptive detection

Per-window counts catch what a fixed rate misses: many clients that each
stay under the limit.

- **Heavy hitters**: a count-min sketch with a top-k list finds the
  prefixes sending more than the per-client limit.
- **Baseline**: an EWMA of the request rate; a window above it by
  `z_threshold` standard deviations is anomalous (after `warmup_windows`).
- **Entropy**: a sharp drop in how spread out the sources are
  (`entropy_drop`) is anomalous too.

`trigger_windows` anomalous windows in a row move the state to `Attack`;
`cooldown_windows` normal ones bring it back. Prefixes (`prefix_v4`,
`prefix_v6`) group a subnet into one key.

In `observe` mode none of this changes a verdict: it shows in logs
("would drop") and the `dvarapala_detection_*` metrics. In `enforce` mode
a heavy hitter gets `403` and the connection is closed, and during
`Attack` every client's bucket refills at `attack_rate_factor` of its rate.

An optional XGBoost model (builds with the `ml` feature) scores requests
that would pass; a score above `threshold` gets `429`.

Keys: [`[detection]`](configuration.html#detection),
[`[ml]`](configuration.html#ml).

## TLS

Terminates TLS with rustls, negotiates `h2` or `http/1.1` by ALPN, reloads
the certificate on `SIGHUP`, and bounds how many handshakes run at once and
how long each may take, so a handshake flood costs bounded CPU.

Keys: [`[tls]`](configuration.html#tls),
[`[upstream_tls]`](configuration.html#upstream_tls).

## HTTP/2

Limits that stop the cheap HTTP/2 attacks: rapid reset (streams opened and
cancelled), oversized header lists, and idle connections (keepalive).
Over a limit, the connection gets `GOAWAY`.

Keys: [`[http2]`](configuration.html#http2), `upstream_protocol`.

## WebSocket

The upgrade request goes through the rate limit and detection like any
request, so a reconnect storm is throttled. After the `101`, the tunnel
limits apply: `max_tunnels` in total (`503` above it), `idle_timeout`, and
`max_lifetime`, which makes long-lived clients reconnect through the
current limits once an attack starts.

Keys: [`[upgrade]`](configuration.html#upgrade).

## Metrics

Every layer reports on the metrics listener. The list is at the end of
[Configuration](configuration.html#metrics-1).
