# dvarapala

Rate limiting, flood detection and connection limits inside your Node.js
service, with the same engine and settings as the
[dvarapala](https://dvarapala.franzramadhan.dev) anti-DDoS gateway. Use it
where a service cannot sit behind the gateway, or as a second layer behind
it.

- Per-client token bucket: `429` with `Retry-After`.
- Flood detection: heavy hitters, a rate baseline and source entropy, with
  a stricter limit during an attack.
- Connection limits (`l4.*`) before any request is read.
- Per-route policy, manual blocks with a TTL, egress shaping for calls to
  rate-limited providers, and live reload that keeps client counts.

## Install

Node 20 or later, on Linux (glibc 2.28 or later) or macOS, x86_64 or arm64:

```sh
npm install dvarapala
```

npm installs the prebuilt addon of your platform from its `@dvarapala/*`
package; no Rust toolchain is needed. Keep optional dependencies on (no
`--omit=optional`), and install on the platform you deploy to.
`DVARAPALA_NODE` overrides the addon's path. Types ship in `index.d.ts`.

## Use

With Express (or `node:http`, the same way):

```js
const express = require('express');
const { Guard } = require('dvarapala');

const guard = new Guard({
  'rate_limit.rate': 20,
  'rate_limit.burst': 40,
  trusted_proxies: ['10.0.0.0/8'], // your load balancer
});
const app = express();
app.use(guard.middleware());
app.get('/', (req, res) => res.send('ok'));

// the l4 connection limits, before any request is read
guard.attach(app.listen(8080));
```

`middleware()` answers `429` with `Retry-After`, or `403` with
`Connection: close`, and calls `next()` otherwise. Anywhere else, ask for
a verdict yourself:

```js
const v = guard.check('192.0.2.10', req.headers['x-forwarded-for']);
// { kind: 'allow' | 'throttle' | 'drop', retryAfterMs }
```

`checkRequest()` applies `routes`, `block()` and `unblock()` manage manual
blocks, `egress(dest)` waits for a slot to a rate-limited destination,
`reload(config)` changes settings in place, and `stats()` returns the
counters and the detection state. One guard per process: behind several
workers, divide the rates by their number.

## Settings

Keys take their names and defaults from the gateway's
[configuration reference](https://dvarapala.franzramadhan.dev/docs/configuration.html):
`rate_limit.*`, `detection.*`, `trusted_proxies`, the connection keys of
`[l4]`, `routes` and `forward.destinations` (lists of objects),
`admin.max_blocks` and `admin.max_block_ttl`. A bad key throws with its
name. The exact list is on the
[SDK page](https://dvarapala.franzramadhan.dev/docs/sdk.html#keys).

## Links

- [SDK documentation](https://dvarapala.franzramadhan.dev/docs/sdk.html)
- [Source](https://github.com/franzramadhan/dvarapala/tree/main/sdk/js)
  and [design (RFC 0008)](https://github.com/franzramadhan/dvarapala/blob/main/rfc/0008-sdk.md)
- Go: `go get github.com/franzramadhan/dvarapala-go`; Python:
  `pip install dvarapala`

MIT licensed.
