"""ASGI and WSGI middleware: 429 with Retry-After (seconds, rounded up, at
least 1) or 403 with Connection: close, as the gateway does. Neither
protocol exposes accepted connections, so the l4 limits need the server's
own hook and Guard.conn_open."""

import math

from .guard import DROP, THROTTLE, Guard, Verdict


def _retry(v: Verdict) -> str:
    return str(max(math.ceil(v.retry_after), 1))


class ASGIMiddleware:
    def __init__(self, app, guard: Guard):
        self.app, self.guard = app, guard

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        peer = (scope.get("client") or ("",))[0]
        xff = [v.decode("latin-1") for k, v in scope["headers"] if k == b"x-forwarded-for"]
        try:
            v = self.guard.check(peer, ", ".join(xff) if xff else None)
        except ValueError:
            # fail closed: no peer address (a unix socket) or a bad one
            v = Verdict(DROP)
        if v.kind == THROTTLE:
            headers = [(b"retry-after", _retry(v).encode())]
            status = 429
        elif v.kind == DROP:
            headers, status = [(b"connection", b"close")], 403
        else:
            return await self.app(scope, receive, send)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b""})


class WSGIMiddleware:
    def __init__(self, app, guard: Guard):
        self.app, self.guard = app, guard

    def __call__(self, environ, start_response):
        try:
            v = self.guard.check(environ.get("REMOTE_ADDR", ""), environ.get("HTTP_X_FORWARDED_FOR"))
        except ValueError:
            v = Verdict(DROP)
        if v.kind == THROTTLE:
            start_response("429 Too Many Requests", [("Retry-After", _retry(v))])
            return [b""]
        if v.kind == DROP:
            start_response("403 Forbidden", [("Connection", "close")])
            return [b""]
        return self.app(environ, start_response)
