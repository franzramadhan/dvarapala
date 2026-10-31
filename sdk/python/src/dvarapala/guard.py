import asyncio
import ctypes
import json
import time
from collections.abc import Mapping
from dataclasses import dataclass

from ._lib import (
    DV_E_LIMIT,
    DV_E_NOT_FOUND,
    DV_OK,
    DvRequest,
    DvRequestVerdict,
    DvSlot,
    DvStats,
    DvVerdict,
    last_error,
    lib,
)

ALLOW, THROTTLE, DROP = 0, 1, 2


@dataclass(frozen=True)
class Verdict:
    kind: int
    """ALLOW, THROTTLE or DROP."""
    retry_after: float = 0.0
    """Seconds, with THROTTLE."""
    route: str | None = None
    """The matched route's name, from check_request (RFC 0028)."""


class Refused(Exception):
    """A connection over an l4.* limit; the reason is `total`, `per_client` or `rate`."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class EgressRefused(Exception):
    """The destination refused a call; retry after `retry_after` seconds."""

    def __init__(self, dest: str, retry_after: float):
        super().__init__(f"egress to {dest} refused, retry after {retry_after}s")
        self.retry_after = retry_after


# RFC 0028: list-shaped keys take JSON
_JSON_KEYS = {"routes", "forward.destinations"}


def _text(k: str, v: object) -> bytes:
    if k in _JSON_KEYS and not isinstance(v, str):
        return json.dumps(v).encode()
    if isinstance(v, bool):
        v = "true" if v else "false"
    elif isinstance(v, (list, tuple)):
        v = ",".join(map(str, v))
    return str(v).encode()


def _b(s: str | None) -> bytes | None:
    return s.encode() if s is not None else None


class Guard:
    """Thread-safe. Settings use the CONFIG.md names, for example
    ``Guard({"rate_limit.rate": 20, "trusted_proxies": ["192.0.2.0/24"]})``;
    unset keys keep the gateway defaults. A bad key raises ValueError
    naming it. ``routes`` and ``forward.destinations`` take a list of
    dicts. One guard per process: behind several workers, divide the rates
    by their number."""

    def __init__(self, config: Mapping[str, object] | None = None):
        self._g = None
        self._g = self._with_config(config, lib.dv_guard_new)
        if not self._g:
            raise ValueError(last_error())
        self._headers()

    @staticmethod
    def _with_config(config, f):
        cfg = lib.dv_config_new()
        try:
            for k, v in (config or {}).items():
                if lib.dv_config_set(cfg, k.encode(), _text(k, v)) != DV_OK:
                    raise ValueError(last_error())
            return f(cfg)
        finally:
            lib.dv_config_free(cfg)

    def _headers(self) -> None:
        # the header names route keys read, lower case
        self.route_headers = [h for h in lib.dv_route_headers(self._g).decode().split(",") if h]

    def reload(self, config: Mapping[str, object] | None = None) -> None:
        """Applies `config` in place, keeping counts, blocks and egress
        queues. Raises ValueError naming a key that only applies at
        creation; the guard stays as it was."""
        if self._with_config(config, lambda cfg: lib.dv_guard_reload(self._g, cfg)) != DV_OK:
            raise ValueError(last_error())
        self._headers()

    def check_request(
        self,
        ip: str,
        method: str,
        path: str,
        host: str | None = None,
        xff: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Verdict:
        """The verdict with the routes applied. `path` is the raw path
        without the query; `headers` maps lower-case names to values, only
        the route_headers are read. Raises ValueError on bad input."""
        h = headers or {}
        lines = "".join(f"{n}: {h[n]}\n" for n in self.route_headers if n in h)
        r = DvRequest(_b(ip), _b(xff), _b(method), _b(host), _b(path), _b(lines or None))
        v = DvRequestVerdict()
        if lib.dv_check_request(self._g, ctypes.byref(r), ctypes.byref(v)) != DV_OK:
            raise ValueError(last_error())
        return Verdict(v.kind, v.retry_after_ms / 1000, v.route.decode() if v.route else None)

    def block(self, cidr: str, ttl: float = 0) -> None:
        """Blocks `cidr` for `ttl` seconds, 0 for admin.max_block_ttl."""
        if lib.dv_block(self._g, cidr.encode(), int(ttl * 1000)) != DV_OK:
            raise ValueError(last_error())

    def unblock(self, cidr: str) -> None:
        """Raises KeyError when `cidr` is not blocked."""
        rc = lib.dv_unblock(self._g, cidr.encode())
        if rc == DV_E_NOT_FOUND:
            raise KeyError(cidr)
        if rc != DV_OK:
            raise ValueError(last_error())

    def blocks(self) -> list[dict]:
        """The blocks in force: ``[{"cidr": ..., "ttl_ms": ...}]``."""
        p = lib.dv_blocks(self._g)
        try:
            return json.loads(ctypes.string_at(p))
        finally:
            lib.dv_string_free(p)

    def _slot(self, dest: str) -> float:
        """Seconds to wait before a call to `dest`; raises EgressRefused."""
        s = DvSlot()
        if lib.dv_egress(self._g, dest.encode(), ctypes.byref(s)) != DV_OK:
            raise KeyError(last_error())
        if s.kind == 2:
            raise EgressRefused(dest, s.ms / 1000)
        return s.ms / 1000

    async def egress(self, dest: str) -> None:
        """Returns when a call to `dest` may go. A wait is spent even when
        the task is cancelled. Raises EgressRefused or KeyError."""
        if wait := self._slot(dest):
            await asyncio.sleep(wait)

    def egress_wait(self, dest: str) -> None:
        """egress for sync code (WSGI): sleeps the thread."""
        if wait := self._slot(dest):
            time.sleep(wait)

    def egress_pause(self, dest: str, retry_after: float) -> None:
        """A provider's Retry-After in seconds, capped by max_pause."""
        if lib.dv_egress_pause(self._g, dest.encode(), int(retry_after * 1000)) != DV_OK:
            raise KeyError(last_error())

    def check(self, ip: str, xff: str | None = None) -> Verdict:
        """The verdict for one request from peer `ip`, with the raw
        X-Forwarded-For value. Raises ValueError on a bad address."""
        v = DvVerdict()
        x = xff.encode() if xff is not None else None
        if lib.dv_check(self._g, ip.encode(), x, ctypes.byref(v)) != DV_OK:
            raise ValueError(last_error())
        return Verdict(v.kind, v.retry_after_ms / 1000)

    def stats(self) -> dict[str, float]:
        s = DvStats()
        lib.dv_stats(self._g, ctypes.byref(s))
        return {name: getattr(s, name) for name, _ in DvStats._fields_}

    def conn_open(self, ip: str) -> int:
        """Counts a connection from `ip` and returns its handle for
        conn_close. Raises Refused over a limit."""
        h = ctypes.c_void_p()
        rc = lib.dv_conn_open(self._g, ip.encode(), ctypes.byref(h))
        if rc == DV_E_LIMIT:
            raise Refused(last_error())
        if rc != DV_OK:
            raise ValueError(last_error())
        return h.value

    def conn_close(self, handle: int) -> None:
        """Frees the place; call once per handle."""
        lib.dv_conn_close(handle)

    def close(self) -> None:
        if getattr(self, "_g", None):
            lib.dv_guard_free(self._g)
            self._g = None

    def __del__(self):
        self.close()
