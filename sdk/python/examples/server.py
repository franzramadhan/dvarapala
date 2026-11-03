"""A WSGI app behind a dvarapala guard, with the standard library only.

    python examples/server.py           # serve on 127.0.0.1:8080
    python examples/server.py --demo    # serve on a free port, send five requests, exit

The guard has a per-client limit, a deny route for scanners and a manual
block. The demo prints the status of each request:

    / 200
    / 200
    / 429 Retry-After: 1
    /wp-admin/ 403
    192.0.2.1 dropped: True
"""

import sys
import threading
import urllib.error
import urllib.request
from wsgiref.simple_server import WSGIRequestHandler, make_server

from dvarapala import DROP, Guard, WSGIMiddleware

guard = Guard({
    "rate_limit.rate": 1,
    "rate_limit.burst": 2,
    # Python takes routes as a list of dicts
    "routes": [{"name": "probes", "path": "/wp-admin", "deny": True}],
})


def app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


class Quiet(WSGIRequestHandler):
    def log_message(self, *args):
        pass


def demo(port):
    for path in ["/", "/", "/", "/wp-admin/"]:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}") as r:
                print(path, r.status)
        except urllib.error.HTTPError as e:
            ra = e.headers.get("Retry-After")
            print(path, e.code, *(["Retry-After:", ra] if ra else []))
    # every check drops a blocked client until the block expires
    guard.block("192.0.2.0/24", ttl=3600)
    print("192.0.2.1 dropped:", guard.check("192.0.2.1").kind == DROP)


if __name__ == "__main__":
    run_demo = "--demo" in sys.argv
    port = 0 if run_demo else 8080
    with make_server("127.0.0.1", port, WSGIMiddleware(app, guard), handler_class=Quiet) as srv:
        if not run_demo:
            srv.serve_forever()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        demo(srv.server_port)
        srv.shutdown()
