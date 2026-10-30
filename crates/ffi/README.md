# dvarapala-ffi

C ABI over the [dvarapala](https://github.com/franzramadhan/dvarapala) engine: a guard per process or service
with the per-client rate limit, flood detection and connection limits.
The Go, Python and JavaScript SDKs call it, so their verdicts match the
gateway's. [`dvarapala.h`](https://github.com/franzramadhan/dvarapala/blob/main/crates/ffi/dvarapala.h) is the contract.

Each [release](https://github.com/franzramadhan/dvarapala/releases) attaches the static and shared library and
the header per platform. See [SDKs](https://dvarapala.franzramadhan.dev/docs/sdk.html).

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
