---
title: WAF
---

dvarapala can send each request that passed its limits to a WAF agent.
A WAF (web application firewall) inspects requests for attacks. dvarapala
then blocks or forwards the request on the verdict of the agent
([RFC 0017](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0017-waf.md)). The agent is
[coraza-spoa](https://github.com/corazawaf/coraza-spoa): OWASP Coraza with
the OWASP Core Rule Set (CRS) built in. It runs as a sidecar (a second
container next to dvarapala). It speaks SPOP, the protocol that HAProxy uses
for the same job. The rules and their exclusions are in the configuration of
the agent. Thus a rule change never needs a new dvarapala build.

## Where it runs

The WAF stage comes after the rate limit, detection and challenge, and
before the upstream pool. Thus dvarapala drops floods before any rule runs.
The WAF stage applies to the reverse proxy on HTTP/1.1, HTTP/2 and HTTP/3.

dvarapala sends the method, path, query, headers, client address and up to
`max_body` bytes of the body. The agent answers pass or deny with the
matched rule IDs. Requests on a route with `waf = false` skip it.

## Run it

`examples/waf/` runs both containers with a Unix socket that they share.
Both containers run as UID 10001 (the owner of the socket):

- [`compose.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/waf/compose.yaml): Docker Compose,
  with the socket on a tmpfs volume.
- [`kubernetes.yaml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/waf/kubernetes.yaml): one Pod with
  both containers, with the socket on an in-memory `emptyDir`. The ConfigMap
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

A TCP endpoint (`"127.0.0.1:9000"`) also works. SPOP is plain text. Thus
dvarapala logs a warning if the endpoint is not loopback and not a Unix socket.

## Observe, then enforce

1. Start with `mode = "observe"`. In this mode, the requests that the
   agent blocks in enforce mode pass. They count as
   `dvarapala_waf_requests_total{verdict="would_block"}`. A `waf match` log
   line names the rule IDs and the client.
2. Exclude false positives (safe requests that a rule matches) in
   `coraza.yaml`, after the CRS include. For example, use
   `SecRuleUpdateTargetById 942100 "!ARGS:comment"` or
   `SecRuleRemoveById 920350`. The agent reloads the file when it changes.
3. Set `mode = "enforce"` and reload dvarapala (`SIGHUP` or
   `POST /reload`). Matched requests then get `403`.

A higher CRS paranoia level finds more attacks and needs more exclusions.
Set it in `coraza.yaml` with `tx.blocking_paranoia_level`.

## Failures and limits

- In enforce mode, the request gets `503` if the agent is down, slow or
  sends an answer that is not valid. To forward these requests, set
  `on_error = "pass"`. Observe mode always forwards. Each failure counts in
  `dvarapala_waf_errors_total`.
- If a body is larger than `max_body`, the request gets `413` in enforce
  mode (`body_limit_action = "reject"`). With `"pass"`, the request goes to
  the agent without its body. Set `waf = false` on upload routes.
- `max_concurrent` sets the maximum number of requests that wait for the agent.

The CRS takes about 1 ms for a GET. For a 16 KiB form with hundreds of
fields, it takes up to about 200 ms. A larger `max_body` needs a longer
`timeout`. `dvarapala_waf_inspect_seconds` shows the real numbers.

Keys and metrics: [`[waf]`](configuration.html#waf). Credits:
[CREDITS.md](https://github.com/franzramadhan/dvarapala/blob/main/CREDITS.md).
