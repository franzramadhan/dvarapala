---
title: Operations
---

The admin API changes a running gateway without a restart. With it, you
can block a network, see the top talkers and the detection state, and
reload the configuration. A top talker is a client that sends the most
traffic. The admin API is off by default. It listens on its own address,
next to the metrics endpoint ([RFC 0014](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0014-admin.md)).

## Turn it on

```toml
[admin]
listen = "127.0.0.1:9091"
# at least 32 bytes; prefer DVARAPALA__ADMIN__TOKEN
token = "<token>"
```

Bind the admin API to loopback or to a management network. Each call needs
`Authorization: Bearer <token>`. dvarapala compares the token in constant time.

## Calls

```sh
H="Authorization: Bearer $DVARAPALA__ADMIN__TOKEN"
curl -sH "$H" http://127.0.0.1:9091/status
curl -sH "$H" http://127.0.0.1:9091/top
curl -sH "$H" -X POST 'http://127.0.0.1:9091/blocks?cidr=192.0.2.0/24&ttl=1h'
curl -sH "$H" http://127.0.0.1:9091/blocks
curl -sH "$H" -X DELETE 'http://127.0.0.1:9091/blocks?cidr=192.0.2.0/24'
curl -sH "$H" -X POST http://127.0.0.1:9091/reload
```

| Call | Answer |
|---|---|
| `GET /status` | version, mode, detection state, tracked clients, blocks, last reload |
| `GET /top` | heavy hitters (the network prefixes with the most traffic) of the last closed detection window |
| `GET /blocks` | manual blocks in force with the seconds left |
| `POST /blocks` | blocks a CIDR or an address for `ttl` (default and maximum `max_block_ttl`) |
| `DELETE /blocks` | removes a block, `404` when it is not listed |
| `POST /reload` | the same as `SIGHUP` |
| `GET /config` | the running configuration, secrets redacted ([RFC 0021](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0021-admin-ui-config-waf.md)) |
| `GET /waf` | WAF configuration, mode in use, matched rules, the rule files of the agent |
| `GET /metrics` | the Prometheus text, behind the admin login |
| `GET /history` | `range=15m\|1h\|6h\|24h\|7d`: request rates by verdict for the console graph, from memory or, with `history.persist`, the PostgreSQL store ([RFC 0022](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0022-traffic-history.md)) |
| `GET /llm/export` | `since`, `until`, `label`, `trigger`: the stored LLM labels as JSON lines, oldest first. `409` without `ml.llm.persist` ([RFC 0024](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0024-llm-label-store.md)) |
| `POST /mode` | `layer=detection\|waf&mode=observe\|enforce`, until the next reload. `403` unless `admin.mode_switch` |

## Console

If `admin.ui_enabled = true`, the admin listener also serves a web
console at `/ui/` ([RFC 0018](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0018-admin-ui.md)). The console shows the detection
state, live request rates, top talkers and manual blocks, and it can start a reload. The
binary contains the console (the `ui` feature, in the default build).

The console also shows these pages ([RFC 0021](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0021-admin-ui-config-waf.md)):

- The running configuration (`GET /config`, secrets redacted). Each key
  shows if a reload applies it or if it needs a restart.
- The WAF (`GET /waf`): the matched rules grouped by CRS family, and the
  files of the agent from `waf.rules_files`.
- One page per layer, from `GET /metrics` on the admin listener (upstreams,
  store, routes, detection, challenges, XDP, TLS, tunnels, egress, limiter).
  The console shows a page only for the features that export series.

If `admin.mode_switch = true`, `POST /mode` switches detection or the WAF to
`observe` or `enforce` on this instance until the next reload. A banner
on each page names the user who switched the mode. The banner also offers
to go back to the mode in the file.

Log in with the admin token, or through an OIDC issuer with
`[admin.oidc]`. Some issuers verify emails but never send the
`email_verified` claim, for example Cloudflare Access. For these issuers, set
`require_email_verified = false` ([RFC 0020](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0020-oidc-email-trust.md)).
If users can edit their email at the provider, keep the default.

After the login, the console holds an `HttpOnly` session cookie. The API
calls above accept this cookie in place of the bearer token. Calls that
change state also need the CSRF header that the console sends. The listener
uses plain HTTP. If it listens on an address that is not loopback, put a TLS
terminator in front of it and set an `https` `admin.public_url`.

Keys: [`[admin]`](configuration.html#admin).

## Reload

`SIGHUP` or `POST /reload` reads the configuration file and the environment
again. If the file does not load or is not valid, dvarapala refuses all of it
and keeps the running configuration.

Some keys apply in place: clients keep their buckets and the detector keeps
its baseline. These keys are the limits (`rate_limit.rate` and `burst`), the
trusted proxies, the detection mode, `[challenge]`, `[fingerprint]`,
`[[routes]]` and `[waf]`. If a shared `[store]` is set, the limits do not
apply in place, because the cluster budget is fixed at start. The
`config reloaded` log line names each other changed key (`restart=`). These
keys wait for a restart. The full list is in [Configuration](configuration.html#reload).

Metrics: `dvarapala_config_reloads_total{result}`, and
`dvarapala_requests_total{scope="block"}` for requests refused by a
manual block.

## Replay

`dvarapala replay --config <file> [--out <file>] <log>` tests a configuration
on recorded traffic before the configuration reaches clients ([RFC 0016](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0016-replay.md)).
It runs the same protection layer as `serve` over a JSON Lines access
log (`-` for stdin). The clock is virtual and comes from the `ts` of each
line, so a day of traffic replays in seconds. Replay opens no listener and
sends no request.

```sh
jq -c '{ts: .time, client: .remote_addr, method, host, path: .uri}' access.json \
  | dvarapala replay --config candidate.toml --out candidate.jsonl -
```

The report lists the lines that replay read and skipped, the time span, and the
`dvarapala_requests_total`, `dvarapala_challenges_total`,
`dvarapala_fingerprint_matches_total`, `dvarapala_route_requests_total`
and `dvarapala_detection_*` series. `--out` writes one
`{"line":N,"status":S}` per line. To compare two configurations, replay
each one and diff the files.
[`examples/replay.toml`](https://github.com/franzramadhan/dvarapala/blob/main/examples/replay.toml)
and its synthetic log in
[`examples/replay/`](https://github.com/franzramadhan/dvarapala/tree/main/examples/replay)
show the loop.
The fields are in [Configuration](configuration.html#replay).
