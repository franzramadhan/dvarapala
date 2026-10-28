import asyncio
import unittest

from dvarapala import ALLOW, THROTTLE, ASGIMiddleware, Guard, Refused, WSGIMiddleware


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
            mw({"REMOTE_ADDR": "192.0.2.1"}, lambda s, h: got.append((s, dict(h))))
        self.assertEqual(got[0][0], "200 OK")
        self.assertEqual(got[1], ("429 Too Many Requests", {"Retry-After": "1"}))

    def test_asgi(self):
        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        mw = ASGIMiddleware(app, limited())
        scope = {"type": "http", "client": ("192.0.2.1", 1234), "headers": []}

        async def one():
            sent = []

            async def send(m):
                sent.append(m)

            await mw(scope, None, send)
            return sent[0]

        first, second = asyncio.run(one()), asyncio.run(one())
        self.assertEqual(first["status"], 200)
        self.assertEqual(second["status"], 429)
        self.assertIn((b"retry-after", b"1"), second["headers"])


if __name__ == "__main__":
    unittest.main()
