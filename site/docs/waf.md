---
title: WAF
---

dvarapala can send each request that passed its limits to a WAF agent and
block or forward it on the agent's verdict
([RFC 0017](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0017-waf.md)). The agent is
[coraza-spoa](https://github.com/corazawaf/coraza-spoa): OWASP Coraza with
the OWASP Core Rule Set (CRS) built in. It runs as a sidecar and speaks
SPOP, the protocol HAProxy uses for the same job. The rules and their
exclusions live in the agent's config, so a rule change never needs a new
dvarapala build.

## Where it runs

The WAF stage sits after the rate limit, detection and challenge and
before the upstream pool, so floods are dropped before any rule runs. It
applies to the reverse proxy on HTTP/1.1, HTTP/2 and HTTP/3.

dvarapala sends the method, path, query, headers, client address and up to
`max_body` bytes of the body. The agent answers pass or deny with the
matched rule IDs. Requests on a route with `waf = false` skip it.

## Run it

`examples/waf/` runs both containers with a Unix socket they share, both
as UID 10001 (the socket's owner):

- [`compose.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/waf/compose.yaml): Docker Compose,
  the socket on a tmpfs volume.
- [`kubernetes.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/waf/kubernetes.yaml): one Pod with
  both containers, the socket on an in-memory `emptyDir`. The ConfigMap
  holds [`waf.toml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/waf.toml) and
  [`coraza.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/waf/coraza.yaml).

```toml
[waf]
enabled = true
mode = "observe"
endpoint = "unix:/run/coraza-spoa/coraza.sock"
timeout = "500ms"
max_body = "16KiB"
```

A TCP endpoint (`"127.0.0.1:9000"`) works too. SPOP is plain text, so
dvarapala warns when the endpoint is neither loopback nor a Unix socket.

## Observe, then enforce

1. Start with `mode = "observe"`: requests the agent would block pass and
   count as `dvarapala_waf_requests_total{verdict="would_block"}`, and a
   `waf match` log line names the rule IDs and the client.
2. Exclude false positives in `coraza.yaml`, after the CRS include, for
   example `SecRuleUpdateTargetById 942100 "!ARGS:comment"` or
   `SecRuleRemoveById 920350`. The agent reloads the file on change.
3. Set `mode = "enforce"` and reload dvarapala (`SIGHUP` or
   `POST /reload`): matches get `403`.

A higher CRS paranoia level catches more and needs more exclusions; set it
in `coraza.yaml` with `tx.blocking_paranoia_level`.

## Failures and limits

- In enforce, an agent that is down, slow or answers garbage gets the
  request `503`, unless `on_error = "pass"`; observe always forwards.
  Each failure counts in `dvarapala_waf_errors_total`.
- A body over `max_body` gets `413` in enforce mode
  (`body_limit_action = "reject"`) or goes to the agent without its body
  (`"pass"`). Give upload routes `waf = false`.
- `max_concurrent` caps requests waiting on the agent.

The CRS takes about 1 ms for a GET, and up to about 200 ms for a 16 KiB
form with hundreds of fields. A larger `max_body` needs a longer
`timeout`. `dvarapala_waf_inspect_seconds` shows the real numbers.

Keys and metrics: [`[waf]`](configuration.html#waf). Credits:
[CREDITS.md](https://github.com/franzramadhan/dvarapala/blob/main/CREDITS.md).
