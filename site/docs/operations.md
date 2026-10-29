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

## Reload

`SIGHUP` or `POST /reload` reads the config file and the environment
again. A file that does not load or validate is refused whole and the
running config stays. Limits, trusted proxies, the detection mode,
`[challenge]`, `[fingerprint]` and `[[routes]]` apply in place: clients
keep their buckets and the detector its baseline. Any other changed key
is named in the `config reloaded` log line (`restart=`) and waits for a
restart. The full list is in [Configuration](configuration.html#reload).

Metrics: `dvarapala_config_reloads_total{result}`, and
`dvarapala_requests_total{scope="block"}` for requests refused by a
manual block.
