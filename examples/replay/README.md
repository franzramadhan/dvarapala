# Sample access log for replay

> Disclaimer: `access.jsonl` is synthetic. A script wrote it for this
> example, with documentation addresses (`192.0.2.0/24`,
> `198.51.100.0/24`, `203.0.113.0/24`). It is not traffic from a real
> site.

`access.jsonl` is one minute of traffic in the line format of
[`dvarapala replay`](../../site/docs/operations.md#replay), 323 lines:

| Client | Traffic | What `../replay.toml` does with it |
|---|---|---|
| `198.51.100.10` to `.19` | 10 readers, one page every 4 to 8 s | allows every line |
| `203.0.113.7` | a scanner, 40 probes in 8 s, no `User-Agent` | denies 16 on `/wp-admin` and 12 on dotfiles (`/.env`, `/.git/config`, `/.aws/credentials`), allows the other 12 |
| `203.0.113.50` | a scraper, 10 requests per second for 15 s | throttles about 65 with the per-client bucket (`rate = 5`, `burst = 10`) |
| `192.0.2.66` | credential stuffing, 30 `POST /login` in 10 s | throttles about half with the login route (`rate = 1`, `burst = 5`) |

## Run it

```sh
dvarapala replay --config examples/replay.toml --out next.jsonl examples/replay/access.jsonl
```

The report gives the line counts, the time span and the protection
metrics, for example
`dvarapala_route_requests_total{route="probes",verdict="deny"} 16`.
`--out` writes one `{"line":N,"status":S}` per line. To see what a change
does, replay the config that you run now with `--out now.jsonl` and
compare the two files with `diff`.

## Use your own log

Convert your access log to these fields with `jq`. Each line needs `ts`
(Unix seconds) and `client` (the peer address). `method`, `host`, `path`,
`xff`, `ja4` and `headers` are optional. For an nginx JSON log:

```sh
jq -c '{ts: .time, client: .remote_addr, method, host, path: .uri}' access.json \
  | dvarapala replay --config candidate.toml -
```

If the log has the address of a load balancer in `client`, put the
original header in `xff` and the load balancer in `trusted_proxies`.
