# dvarapala-xdp

Loader for the [dvarapala](https://github.com/franzramadhan/dvarapala) XDP fast path (Linux): attaches the
checked-in eBPF program to a network interface and keeps its maps (the
allow and block lists, per-source packet, SYN and UDP rates, the
counters). L4 and L7 feed it dynamic blocks for sources that completed a
handshake.

Feature `load` adds the loader (`aya`); without it the crate has only
the config types and the block list bookkeeping, so a build without XDP
links no `aya`. Needs `CAP_BPF` and `CAP_NET_ADMIN`.

Part of [dvarapala](https://github.com/franzramadhan/dvarapala), an anti-DDoS gateway in Rust. Docs: <https://dvarapala.franzramadhan.dev/docs/>. License: MIT.
