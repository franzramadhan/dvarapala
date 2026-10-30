---
title: Operations
---

The admin API changes a running gateway without a restart: block a
network, look at the top talkers and the detection state, reload the
config. It is off by default and listens on its own address, next to the
metrics endpoint ([RFC 0014](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0014-admin.md)).

## Turn it on

```toml
[admin]
listen = "127.0.0.1:9091"
# at least 32 bytes; prefer DVARAPALA__ADMIN__TOKEN
token = "<token>"
```

Bind it to loopback or a management network. Every call needs
`Authorization: Bearer <token>`; the token is compared in constant time.

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
| `GET /top` | heavy hitters of the last closed detection window |
| `GET /blocks` | manual blocks in force with the seconds left |
| `POST /blocks` | blocks a CIDR or an address for `ttl` (default and maximum `max_block_ttl`) |
| `DELETE /blocks` | removes a block, `404` when it is not listed |
| `POST /reload` | the same as `SIGHUP` |
| `GET /config` | the running config, secrets redacted ([RFC 0021](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0021-admin-ui-config-waf.md)) |
| `GET /waf` | WAF settings, running mode, matched rules, the agent's rule files |
| `GET /metrics` | the Prometheus text, behind the admin login |
| `GET /history` | `range=15m\|1h\|6h\|24h\|7d`: request rates by verdict for the console graph, from memory or, with `history.persist`, the PostgreSQL store ([RFC 0022](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0022-traffic-history.md)) |
| `GET /llm/export` | `since`, `until`, `label`, `trigger`: the stored LLM labels as JSON lines, oldest first; `409` without `ml.llm.persist` ([RFC 0024](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0024-llm-label-store.md)) |
| `POST /mode` | `layer=detection\|waf&mode=observe\|enforce`, until the next reload; `403` unless `admin.mode_switch` |

## Console

With `admin.ui_enabled = true` the admin listener also serves a web
console at `/ui/` ([RFC 0018](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0018-admin-ui.md)): the detection
state and live request rates, top talkers, manual blocks and reload. It is
embedded in the binary (the `ui` feature, in the default build).

The console also shows ([RFC 0021](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0021-admin-ui-config-waf.md)):
the running config (`GET /config`, secrets redacted, each key marked as
applied by a reload or needing a restart), the WAF (`GET /waf`: matched
rules grouped by CRS family and the agent's files from `waf.rules_files`),
and a page per layer drawn from `GET /metrics` on the admin listener
(upstreams, store, routes, detection, challenges, XDP, TLS, tunnels,
egress, limiter), shown only for the features that export series. With
`admin.mode_switch = true`, `POST /mode` switches detection or the WAF to
`observe` or `enforce` on this instance until the next reload; a banner
on every page names who switched it and offers to revert to the file.

Log in with the admin token, or through an OIDC issuer with
`[admin.oidc]`. For an issuer that verifies emails but never sends the
`email_verified` claim, such as Cloudflare Access, set
`require_email_verified = false` ([RFC 0020](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0020-oidc-email-trust.md));
keep the default for any provider where users can edit their email. The console then holds an `HttpOnly` session cookie that
the API calls above accept in place of the bearer token; calls that
change state also need the CSRF header the console sends. The listener
stays plain HTTP: off loopback, put a TLS terminator in front and set an
`https` `admin.public_url`.

Keys: [`[admin]`](configuration.html#admin).

## Reload

`SIGHUP` or `POST /reload` reads the config file and the environment
again. A file that does not load or validate is refused whole and the
running config stays. Limits (`rate_limit.rate` and `burst`, unless a
shared `[store]` is set: the cluster budget is fixed at start), trusted
proxies, the detection mode,
`[challenge]`, `[fingerprint]`, `[[routes]]` and `[waf]` apply in place: clients
keep their buckets and the detector its baseline. Any other changed key
is named in the `config reloaded` log line (`restart=`) and waits for a
restart. The full list is in [Configuration](configuration.html#reload).

Metrics: `dvarapala_config_reloads_total{result}`, and
`dvarapala_requests_total{scope="block"}` for requests refused by a
manual block.

## Replay

`dvarapala replay --config <file> [--out <file>] <log>` tries a config
on recorded traffic before it reaches clients ([RFC 0016](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0016-replay.md)).
It runs the same protection layer as `serve` over a JSON Lines access
log (`-` for stdin) on a virtual clock taken from each line's `ts`, so a
day of traffic replays in seconds. Nothing listens and nothing is sent.

```sh
jq -c '{ts: .time, client: .remote_addr, method, host, path: .uri}' access.json \
  | dvarapala replay --config candidate.toml --out candidate.jsonl -
```

The report lists the lines read and skipped, the time span, and the
`dvarapala_requests_total`, `dvarapala_challenges_total`,
`dvarapala_fingerprint_matches_total`, `dvarapala_route_requests_total`
and `dvarapala_detection_*` series. `--out` writes one
`{"line":N,"status":S}` per line: replay two configs and diff the files.
The fields are in [Configuration](configuration.html#replay).
