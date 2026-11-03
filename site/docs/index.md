---
title: Getting started
---

dvarapala is an anti-DDoS reverse proxy. A reverse proxy receives the
requests for an app and sends them on to it. dvarapala listens on the address
that your app used before. It forwards requests to the app (the upstream) and
decides for each request if it can pass.

## Install

With Homebrew, on macOS or Linux:

```sh
brew install franzramadhan/tap/dvarapala
```

Or use the install script. The script downloads the latest release for
your platform and compares it with the `SHA256SUMS` of the release. Then it
installs it to `/usr/local/bin` (if you can write there) or `~/.local/bin`:

```sh
curl -fsSL https://dvarapala.franzramadhan.dev/install.sh | sh
```

`DVARAPALA_VERSION=v<version>` pins a release. `DVARAPALA_INSTALL=<dir>`
sets the directory. You can read [the script](https://dvarapala.franzramadhan.dev/install.sh)
before you run it.

Or install by hand. Each [release](https://github.com/franzramadhan/dvarapala/releases)
has a static binary per platform (`x86_64` and `aarch64`, Linux musl and
macOS) and a `SHA256SUMS` file. The binaries (also through Homebrew and
`install.sh`) have only the default features. The container image has
every feature. The table under
[Configuration](configuration.html#build-features-and-published-artifacts)
shows which build each section needs. Make sure that the tarball is correct
before you unpack it:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf dvarapala-v<version>-<target>.tar.gz
./dvarapala --version
```

Or use the container image, for `linux/amd64` and `linux/arm64`. The image
is `FROM scratch` with the static binary. The binary has the Redis and
PostgreSQL stores (`[store]`), so replicas (copies of the gateway) can share
limits. The image runs as UID 10001 and listens on port 8080. Without a
configuration file, every key comes from the environment:

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

If you scrape metrics from outside the container, set
`[metrics] listen = "0.0.0.0:9090"` (the default is loopback). The image
contains the Alpine root CAs. Thus dvarapala verifies `https://` upstreams,
OIDC issuers and TLS stores against public roots. For a private CA, set
`upstream_tls.ca_file` or `store.ca_file`.

Or from crates.io, which builds the default features:

```sh
cargo install dvarapala
# optional: --features http3,ml,redis,postgres,xdp,geoip
```

Or build from source with the toolchain pinned in `rust-toolchain.toml`:

```sh
git clone https://github.com/franzramadhan/dvarapala
cd dvarapala
cargo build --release
# optional: --features http3,ml,redis,postgres,xdp,geoip (or use the container image)
```

## First run

Start an app on port 8081 (any HTTP server is good). Then put dvarapala in
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

All other keys have a default: a rate limit of 20 requests per second per
client (burst 40), detection in `observe` mode, and metrics on
`127.0.0.1:9090`. If you send more than 40 requests at once, the extra
requests get `429 Too Many Requests` with `Retry-After`.

## Override with the environment

An environment variable can set each key. The name is `DVARAPALA__`, then
the key path with `__` between the parts.

```sh
DVARAPALA__RATE_LIMIT__RATE=5 ./dvarapala serve --config dvarapala.toml
```

The log level comes from `RUST_LOG` (default `info`).

## Watch, then enforce

Detection starts in `observe` mode. In this mode, detection logs and
counts the requests that it will block in `enforce` mode, but it changes no
verdict.

1. Scrape the metrics endpoint.
2. Let the baseline (the normal traffic level) warm up (300 windows of 1 s by default).
3. Compare the `dvarapala_detection_*` series with real traffic.
4. If the series stay quiet in normal hours, set:

```toml
[detection]
mode = "enforce"
```

## Next

- [Architecture](architecture.html): the request path, the crates and the
  failure policy.
- [Protection layers](protection.html): what each layer does and when to
  tune it.
- [WAF](waf.html): the Coraza sidecar with the OWASP CRS.
- [Forward proxy](forward-proxy.html): hold outbound calls to the rate
  of each provider.
- [SDKs](sdk.html): the same protection, routes, blocks and egress shaping inside a Go, Python or JavaScript
  service.
- [Clusters](clusters.html): replicas behind one load balancer sharing
  their limits.
- [Kubernetes](kubernetes.html): the operator, a gateway per labeled
  backend.
- [Operations](operations.html): the admin API, the console, reloads and
  replay.
- [Configuration](configuration.html): every key, default and metric.
- [Examples](examples.html): TLS, gRPC, WebSocket, HTTP/3, connection
  limits, forward proxy, cluster and XDP deployments.
- [Roadmap](roadmap.html): every RFC and its status.
