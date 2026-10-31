"""ASGI and WSGI middleware with the routes applied (RFC 0028): 429 with
Retry-After (seconds, rounded up, at least 1) or 403 with Connection:
close, as the gateway does, and 400 with Connection: close for input the
guard refuses, so a bad request never reaches the app. Neither protocol
exposes accepted connections, so the l4 limits need the server's own hook
and Guard.conn_open.

One guard per process: behind gunicorn or uvicorn workers, a client's
limit multiplies by the worker count; divide the rates by it."""

import math

from .guard import DROP, THROTTLE, Guard, Verdict


def _retry(v: Verdict) -> str:
    return str(max(math.ceil(v.retry_after), 1))


def _answer(v: Verdict | None) -> tuple[int, str, list[tuple[str, str]]] | None:
    """The status, reason and headers that refuse the request, or None."""
    if v is None:
        return 400, "Bad Request", [("Connection", "close")]
    if v.kind == THROTTLE:
        return 429, "Too Many Requests", [("Retry-After", _retry(v))]
    if v.kind == DROP:
        return 403, "Forbidden", [("Connection", "close")]
    return None


class ASGIMiddleware:
    def __init__(self, app, guard: Guard):
        self.app, self.guard = app, guard

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        peer = (scope.get("client") or ("",))[0]
        wanted = {"host", *self.guard.route_headers}
        h: dict[str, str] = {}
        xff = []
        for k, v in scope["headers"]:
            name = k.decode("latin-1")
            if name == "x-forwarded-for":
                xff.append(v.decode("latin-1"))
            elif name in wanted and name not in h:
                h[name] = v.decode("latin-1")
        raw = scope.get("raw_path") or scope["path"].encode()
        try:
            path = raw.split(b"?", 1)[0].decode()
            x = ", ".join(xff) if xff else None
            v = self.guard.check_request(peer, scope["method"], path, h.get("host"), x, h)
        except ValueError:
            # fail closed: bad input or no peer address (a unix socket)
            v = None
        if (refuse := _answer(v)) is None:
            return await self.app(scope, receive, send)
        status, _, headers = refuse
        raw_headers = [(k.lower().encode(), v.encode()) for k, v in headers]
        await send({"type": "http.response.start", "status": status, "headers": raw_headers})
        await send({"type": "http.response.body", "body": b""})


class WSGIMiddleware:
    def __init__(self, app, guard: Guard):
        self.app, self.guard = app, guard

    def __call__(self, environ, start_response):
        g = self.guard
        keys = {n: "HTTP_" + n.upper().replace("-", "_") for n in g.route_headers}
        h = {n: environ[k] for n, k in keys.items() if k in environ}
        try:
            # PEP 3333 strings carry the raw bytes as latin-1
            raw = environ.get("RAW_URI") or (
                environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")
            )
            path = raw.split("?", 1)[0].encode("latin-1").decode()
            v = g.check_request(
                environ.get("REMOTE_ADDR", ""),
                environ.get("REQUEST_METHOD", ""),
                path,
                environ.get("HTTP_HOST"),
                environ.get("HTTP_X_FORWARDED_FOR"),
                h,
            )
        except ValueError:
            v = None
        if (refuse := _answer(v)) is None:
            return self.app(environ, start_response)
        status, reason, headers = refuse
        start_response(f"{status} {reason}", headers)
        return [b""]
