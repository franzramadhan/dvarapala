---
title: Forward proxy
---

In forward mode dvarapala sits on the way out: your services call
third-party APIs through it, and it keeps each provider's agreed rate and
concurrency for all callers together. The provider never sees more than
the agreement allows, so it never has to block you.

## Run it

```toml
mode = "forward"
listen = "0.0.0.0:3128"

[forward]
clients = ["192.0.2.0/24"]   # your services

[[forward.destinations]]
name = "provider-a"
origin = "https://api.provider-a.example"
rate = 50              # requests per second, all callers together
max_concurrent = 20
max_wait = "3s"
```

Point the callers at it with `HTTP_PROXY` / `HTTPS_PROXY`
(`http://<host>:3128`) or their HTTP client's proxy setting.

## What a request gets

- **A free slot:** sent at once.
- **The next slot within `max_wait`, fewer than `max_queue` waiting:**
  held until its slot, then sent, first come first served.
- **Otherwise:** a local `429` with `Retry-After`, without contacting the
  provider. The proxy waits or refuses; it never sends above the rate.
- **A destination that is not listed, or a client outside `clients`:**
  `403`. The proxy is not an open relay.

When a provider answers `429` or `503` with `Retry-After`, that
destination pauses for the time it asks (capped by `max_pause`), so
callers stop piling retries on it.

## Absolute form or CONNECT

An `https://` URL through a proxy usually becomes a `CONNECT` tunnel: TLS
stays end to end and the proxy shapes tunnels, one slot each, not the
requests inside them. That suits providers that limit connections. To
shape every request, send absolute-form requests (`GET
https://host/path` as plain HTTP to the proxy): the proxy opens TLS to the
destination itself, verified by `[upstream_tls]`. Keep that hop on a
trusted network. `connect = false` accepts only absolute-form requests.

## Watch it

`dvarapala_egress_requests_total{destination,result}` counts `sent`,
`delayed`, `refused` and `denied`; `dvarapala_egress_wait_seconds`,
`dvarapala_egress_queue` and `dvarapala_egress_in_flight` show how close
each destination runs to its limits, and
`dvarapala_egress_provider_pauses_total` how often a provider pushed back.

The design is in [RFC 0007](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0007-forward-proxy.md),
every key in [Configuration](configuration.html#forward), and a full
config in [Examples](examples.html).
