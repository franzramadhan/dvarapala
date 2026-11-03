---
title: Forward proxy
---

In forward mode, dvarapala is a forward proxy: a proxy on the outbound path. Your services call
third-party APIs through it. dvarapala keeps the agreed rate and concurrency
of each provider for all callers together. The provider never sees more
traffic than the agreement allows, so it never has to block you.

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

Point the callers at the proxy with `HTTP_PROXY` or `HTTPS_PROXY`
(`http://<host>:3128`), or with the proxy configuration of their HTTP client.

## What a request gets

- If a slot is free, the proxy sends the request at once.
- If the next slot is within `max_wait` and fewer than `max_queue`
  requests wait, the proxy holds the request until its slot. Then it sends
  it, first come first served.
- In all other cases, the proxy sends a local `429` with `Retry-After`. It
  does not contact the provider. The proxy waits or refuses, but it never
  sends above the rate.
- If the destination is not listed, or the client is outside `clients`,
  the request gets `403`. The proxy is not an open relay.

If a provider answers `429` or `503` with `Retry-After`, that destination
pauses for the time that the provider asks for (up to `max_pause`). Thus
callers stop sending more retries to it.

## Absolute form or CONNECT

Through a proxy, an `https://` URL usually becomes a `CONNECT` tunnel. TLS
stays end to end. The proxy shapes the tunnels, one slot each, not the
requests inside them. This is good for providers that limit connections.

To shape each request, send absolute-form requests (`GET
https://host/path` as plain HTTP to the proxy). The proxy then opens TLS to
the destination itself and verifies it with `[upstream_tls]`. Keep the hop
from the caller to the proxy on a trusted network. With `connect = false`,
the proxy accepts only absolute-form requests.

## Watch it

`dvarapala_egress_requests_total{destination,result}` counts `sent`,
`delayed`, `refused` and `denied`. `dvarapala_egress_wait_seconds`,
`dvarapala_egress_queue` and `dvarapala_egress_in_flight` show how close
each destination is to its limits.
`dvarapala_egress_provider_pauses_total` shows how often a provider asked
for a pause.

The design is in [RFC 0007](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0007-forward-proxy.md),
every key in [Configuration](configuration.html#forward), and a full
configuration in [Examples](examples.html).
