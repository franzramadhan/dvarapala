---
title: Getting started
---

dvarapala is an anti-DDoS reverse proxy. It listens where your app used to,
forwards to the app as the upstream, and decides for each request whether
it may pass. This page takes you from a download to a running proxy.

## Install

With Homebrew, on macOS or Linux:

```sh
brew install franzramadhan/tap/dvarapala
```

Or with the install script, which downloads the latest release for your
platform, checks it against the release's `SHA256SUMS`, and installs it to
`/usr/local/bin` (when writable) or `~/.local/bin`:

```sh
curl -fsSL https://dvarapala.franzramadhan.dev/install.sh | sh
```

`DVARAPALA_VERSION=v<version>` pins a release, `DVARAPALA_INSTALL=<dir>`
picks the directory. Read [the script](https://dvarapala.franzramadhan.dev/install.sh)
first if you prefer.

Or by hand: each [release](https://github.com/franzramadhan/dvarapala/releases)
has a static binary per platform (`x86_64` and `aarch64`, Linux musl and
macOS) and a `SHA256SUMS` file. The binaries (also through Homebrew and
`install.sh`) have the default features only; the container image adds
the Redis and PostgreSQL stores. The table under
[Configuration](configuration.html#build-features-and-published-artifacts)
lists which sections need which build. Check the tarball before you unpack it:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf dvarapala-v<version>-<target>.tar.gz
./dvarapala --version
```

Or as a container image, for `linux/amd64` and `linux/arm64`. It is
`FROM scratch` with the static binary built with the Redis and PostgreSQL
stores (`[store]`, so replicas can share limits), runs as UID 10001 and
listens on port 8080. With no config file, every key comes from the environment:

```sh
docker run --rm -p 8080:8080 \
  -e DVARAPALA__UPSTREAM=http://app.example:8081 \
  ghcr.io/franzramadhan/dvarapala:<version>
```

To use a file, mount it and pass it to `serve`:

```sh
docker run --rm -p 8080:8080 -v ./dvarapala.toml:/etc/dvarapala.toml:ro \
  ghcr.io/franzramadhan/dvarapala:<version> serve --config /etc/dvarapala.toml
```

Inside a container, set `[metrics] listen = "0.0.0.0:9090"` to scrape
metrics from outside it (the default is loopback). The image carries
Alpine's root CAs, so `https://` upstreams, OIDC issuers and TLS stores
verify against public roots; for a private CA set `upstream_tls.ca_file`
or `store.ca_file`.

Or build from source with the toolchain pinned in `rust-toolchain.toml`:

```sh
git clone https://github.com/franzramadhan/dvarapala
cd dvarapala
cargo build --release
# optional: --features http3,ml,redis,postgres,xdp (only way to get ml, http3, xdp)
```

## First run

Start an app on port 8081 (any HTTP server will do), then put dvarapala in
front of it:

```toml
# dvarapala.toml
listen = "0.0.0.0:8080"
upstream = "http://127.0.0.1:8081"
```

```sh
./dvarapala serve --config dvarapala.toml
curl -i http://127.0.0.1:8080/
```

Everything else has a default: a rate limit of 20 requests per second per
client (burst 40), detection in `observe` mode, metrics on
`127.0.0.1:9090`. Send more than 40 requests at once and the extra ones get
`429 Too Many Requests` with `Retry-After`.

## Override with the environment

Every key can be set by an environment variable: `DVARAPALA__`, then the
key path with `__` between parts.

```sh
DVARAPALA__RATE_LIMIT__RATE=5 ./dvarapala serve --config dvarapala.toml
```

The log level comes from `RUST_LOG` (default `info`).

## Watch, then enforce

Detection starts in `observe` mode: it logs and counts what it would do,
but changes no verdict. Scrape the metrics endpoint, let the baseline warm
up (300 windows of 1 s by default), and check the `dvarapala_detection_*`
series against real traffic. When they stay quiet in normal hours, set:

```toml
[detection]
mode = "enforce"
```

## Next

- [Protection layers](protection.html): what each layer does and when to
  tune it.
- [Configuration](configuration.html): every key, default and metric.
- [Examples](examples.html): TLS, gRPC, WebSocket, HTTP/3, connection
  limits, forward proxy, cluster and XDP deployments.
- [Forward proxy](forward-proxy.html): hold outbound calls to each
  provider's rate.
- [SDKs](sdk.html): the same protection inside a Go, Python or JavaScript
  service.
- [Clusters](clusters.html): replicas behind one load balancer sharing
  their limits.
