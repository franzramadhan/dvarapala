import asyncio
import tempfile
import time
import unittest
from pathlib import Path

from dvarapala import _lib
from dvarapala import (
    ALLOW,
    DROP,
    THROTTLE,
    ASGIMiddleware,
    EgressRefused,
    Guard,
    Refused,
    WSGIMiddleware,
)

LOGIN = [{"name": "login", "path": "=/login", "methods": ["POST"], "rate": 1, "burst": 2}]


def limited():
    return Guard({"rate_limit.rate": 1, "rate_limit.burst": 1})


class GuardTest(unittest.TestCase):
    def test_bad_config_names_the_key(self):
        with self.assertRaisesRegex(ValueError, "rate_limit.rate"):
            Guard({"rate_limit.rate": "fast"})

    def test_throttles_over_the_burst(self):
        g = limited()
        self.assertEqual(g.check("192.0.2.1").kind, ALLOW)
        v = g.check("192.0.2.1")
        self.assertEqual(v.kind, THROTTLE)
        self.assertTrue(0 < v.retry_after <= 1)
        self.assertEqual(g.stats()["clients"], 1)

    def test_bad_ip_raises(self):
        with self.assertRaisesRegex(ValueError, "ip"):
            Guard().check("not an ip")

    # RFC 0008 case 19
    def test_conn_bound(self):
        g = Guard({"l4.max_per_client": 2})
        a, _ = g.conn_open("192.0.2.1"), g.conn_open("192.0.2.1")
        with self.assertRaises(Refused) as e:
            g.conn_open("192.0.2.1")
        self.assertEqual(e.exception.reason, "per_client")
        g.conn_close(a)
        g.conn_open("192.0.2.1")


# RFC 0008 case 11
class MiddlewareTest(unittest.TestCase):
    def test_wsgi(self):
        def app(environ, start_response):
            start_response("200 OK", [])
            return [b"ok"]

        mw = WSGIMiddleware(app, limited())
        got = []
        for _ in range(2):
            env = {"REMOTE_ADDR": "192.0.2.1", "REQUEST_METHOD": "GET", "PATH_INFO": "/"}
            mw(env, lambda s, h: got.append((s, dict(h))))
        self.assertEqual(got[0][0], "200 OK")
        self.assertEqual(got[1], ("429 Too Many Requests", {"Retry-After": "1"}))

    def test_asgi(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = ASGIMiddleware(app, limited())
        scope = {"type": "http", "client": ("192.0.2.1", 1234), "headers": []}
        scope |= {"method": "GET", "path": "/"}
        first, second = asyncio.run(asgi(mw, scope)), asyncio.run(asgi(mw, scope))
        self.assertEqual(first["status"], 200)
        self.assertEqual(second["status"], 429)
        self.assertIn((b"retry-after", b"1"), second["headers"])

    # RFC 0028 cases 15 and 19
    def test_routes_and_bad_input(self):
        ran = []

        async def app(scope, receive, send):
            ran.append(scope["path"])
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = ASGIMiddleware(app, Guard({"routes": LOGIN}))
        post = {"type": "http", "client": ("192.0.2.1", 1), "headers": [], "method": "POST"}
        post |= {"path": "/login", "raw_path": b"/login?x=1"}
        codes = [asyncio.run(asgi(mw, post))["status"] for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])
        bad = post | {"path": "/x", "raw_path": b"/" + b"a" * 9000}
        self.assertEqual(asyncio.run(asgi(mw, bad))["status"], 400)
        self.assertEqual(asyncio.run(asgi(mw, post | {"raw_path": b"/\xff"}))["status"], 400)
        self.assertEqual(len(ran), 2)

        def wapp(environ, start_response):
            ran.append(environ["PATH_INFO"])
            start_response("200 OK", [])
            return [b"ok"]

        api = [{"name": "api", "path": "/", "key": "header:x-api-key", "rate": 1, "burst": 1}]
        w = WSGIMiddleware(wapp, Guard({"routes": api}))
        got = []
        env = {"REMOTE_ADDR": "192.0.2.1", "REQUEST_METHOD": "GET", "PATH_INFO": "/v1"}
        for key in ["a", "a", "b", "a\nb"]:
            w(env | {"HTTP_X_API_KEY": key}, lambda s, h: got.append(s))
        self.assertEqual(got, ["200 OK", "429 Too Many Requests", "200 OK", "400 Bad Request"])


async def asgi(mw, scope):
    sent = []

    async def send(m):
        sent.append(m)

    await mw(scope, None, send)
    return sent[0]


# RFC 0028: blocks, egress and reload
class ControlTest(unittest.TestCase):
    def test_blocks(self):
        g = Guard()
        g.block("192.0.2.0/24", 60)
        self.assertEqual(g.check("192.0.2.9").kind, DROP)
        self.assertEqual(g.blocks()[0]["cidr"], "192.0.2.0/24")
        g.unblock("192.0.2.0/24")
        with self.assertRaises(KeyError):
            g.unblock("192.0.2.0/24")

    # RFC 0028 case 22
    def test_egress_wait(self):
        d = {"origin": "https://api.example.com", "name": "stripe", "rate": 1, "burst": 1}
        g = Guard({"forward.destinations": [d | {"max_queue": 1}]})
        start = time.monotonic()
        g.egress_wait("stripe")
        g.egress_wait("stripe")
        self.assertGreater(time.monotonic() - start, 0.9)
        g.egress_pause("stripe", 5)
        with self.assertRaises(EgressRefused) as e:
            asyncio.run(g.egress("stripe"))
        self.assertGreater(e.exception.retry_after, 2)

    def test_reload(self):
        g = Guard({"rate_limit.rate": 1, "rate_limit.burst": 1})
        self.assertEqual(g.check("192.0.2.1").kind, ALLOW)
        with self.assertRaisesRegex(ValueError, "rate_limit.max_clients"):
            g.reload({"rate_limit.max_clients": 10})
        g.reload({"routes": [{"name": "api", "path": "/", "key": "header:X-Api-Key", "rate": 5}]})
        self.assertEqual(g.route_headers, ["x-api-key"])
        v = g.check_request("192.0.2.2", "GET", "/", headers={"x-api-key": "a"})
        self.assertEqual(v.route, "api")


if __name__ == "__main__":
    unittest.main()


class LibTest(unittest.TestCase):
    # RFC 0026 case 7
    def test_no_library_is_an_import_error(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ImportError, "supported: linux-x86_64, linux-aarch64"):
                _lib._path({}, Path(d))
            self.assertEqual(_lib._path({"DVARAPALA_LIB": "/x.so"}, Path(d)), "/x.so")
