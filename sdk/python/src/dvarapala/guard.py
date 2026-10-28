import ctypes
from collections.abc import Mapping
from dataclasses import dataclass

from ._lib import DV_E_LIMIT, DV_OK, DvStats, DvVerdict, last_error, lib

ALLOW, THROTTLE, DROP = 0, 1, 2


@dataclass(frozen=True)
class Verdict:
    kind: int
    """ALLOW, THROTTLE or DROP."""
    retry_after: float = 0.0
    """Seconds, with THROTTLE."""


class Refused(Exception):
    """A connection over an l4.* limit; the reason is `total`, `per_client` or `rate`."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _text(v: object) -> bytes:
    if isinstance(v, bool):
        v = "true" if v else "false"
    elif isinstance(v, (list, tuple)):
        v = ",".join(map(str, v))
    return str(v).encode()


class Guard:
    """Thread-safe. Settings use the CONFIG.md names, for example
    ``Guard({"rate_limit.rate": 20, "trusted_proxies": ["192.0.2.0/24"]})``;
    unset keys keep the gateway defaults. A bad key raises ValueError
    naming it."""

    def __init__(self, config: Mapping[str, object] | None = None):
        cfg = lib.dv_config_new()
        try:
            for k, v in (config or {}).items():
                if lib.dv_config_set(cfg, k.encode(), _text(v)) != DV_OK:
                    raise ValueError(last_error())
            self._g = lib.dv_guard_new(cfg)
            if not self._g:
                raise ValueError(last_error())
        finally:
            lib.dv_config_free(cfg)

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
        if self._g:
            lib.dv_guard_free(self._g)
            self._g = None

    def __del__(self):
        self.close()
