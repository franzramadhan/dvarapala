# dvarapala-l4

Connection limits for [dvarapala](https://github.com/franzramadhan/dvarapala) listeners, checked before any TLS
or HTTP is read: a cap on open connections per client and in total, a
token bucket on new connections per client, and header, idle and
slow-body timeouts. `Listener` wraps a Tokio TCP listener with
`L4Config`; a refused connection is closed with nothing read.

Keys and defaults: [`[l4]`](https://dvarapala.franzramadhan.dev/docs/configuration.html#l4).

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
