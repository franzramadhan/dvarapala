"""ctypes declarations for crates/ffi/dvarapala.h."""

import ctypes
import os
import sys
from ctypes import POINTER, c_char_p, c_double, c_int32, c_uint8, c_uint64, c_void_p
from pathlib import Path


class DvVerdict(ctypes.Structure):
    _fields_ = [("kind", c_int32), ("retry_after_ms", c_uint64)]


class DvStats(ctypes.Structure):
    _fields_ = [
        ("allowed", c_uint64),
        ("throttled", c_uint64),
        ("dropped", c_uint64),
        ("clients", c_uint64),
        ("evictions", c_uint64),
        ("detection_state", c_uint8),
        ("rate_zscore", c_double),
        ("source_entropy", c_double),
    ]


class DvRequest(ctypes.Structure):
    _fields_ = [
        ("ip", c_char_p),
        ("xff", c_char_p),
        ("method", c_char_p),
        ("host", c_char_p),
        ("path", c_char_p),
        ("headers", c_char_p),
    ]


class DvRequestVerdict(ctypes.Structure):
    _fields_ = [("kind", c_int32), ("retry_after_ms", c_uint64), ("route", c_char_p)]


class DvSlot(ctypes.Structure):
    _fields_ = [("kind", c_int32), ("ms", c_uint64)]


def _path() -> str:
    """DVARAPALA_LIB, else the library next to this file (the wheel)."""
    if env := os.environ.get("DVARAPALA_LIB"):
        return env
    name = {"darwin": "libdvarapala.dylib", "win32": "dvarapala.dll"}.get(
        sys.platform, "libdvarapala.so"
    )
    return str(Path(__file__).with_name(name))


lib = ctypes.CDLL(_path())
_sigs = {
    "dv_config_new": ([], c_void_p),
    "dv_config_set": ([c_void_p, c_char_p, c_char_p], c_int32),
    "dv_config_free": ([c_void_p], None),
    "dv_guard_new": ([c_void_p], c_void_p),
    "dv_guard_free": ([c_void_p], None),
    "dv_check": ([c_void_p, c_char_p, c_char_p, POINTER(DvVerdict)], c_int32),
    "dv_stats": ([c_void_p, POINTER(DvStats)], c_int32),
    "dv_conn_open": ([c_void_p, c_char_p, POINTER(c_void_p)], c_int32),
    "dv_conn_close": ([c_void_p], None),
    "dv_last_error": ([], c_char_p),
    "dv_guard_reload": ([c_void_p, c_void_p], c_int32),
    "dv_check_request": ([c_void_p, POINTER(DvRequest), POINTER(DvRequestVerdict)], c_int32),
    "dv_route_headers": ([c_void_p], c_char_p),
    "dv_block": ([c_void_p, c_char_p, c_uint64], c_int32),
    "dv_unblock": ([c_void_p, c_char_p], c_int32),
    # a c_void_p, not c_char_p, so the pointer survives for dv_string_free
    "dv_blocks": ([c_void_p], c_void_p),
    "dv_string_free": ([c_void_p], None),
    "dv_egress": ([c_void_p, c_char_p, POINTER(DvSlot)], c_int32),
    "dv_egress_pause": ([c_void_p, c_char_p, c_uint64], c_int32),
}
for _name, (_args, _res) in _sigs.items():
    _f = getattr(lib, _name)
    _f.argtypes, _f.restype = _args, _res

DV_OK, DV_E_LIMIT, DV_E_NOT_FOUND = 0, 4, 6


def last_error() -> str:
    m = lib.dv_last_error()
    return m.decode() if m else "unknown error"
