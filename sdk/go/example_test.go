//go:build cgo && (linux || darwin) && (amd64 || arm64)

package dvarapala

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"time"
)

// A net/http server with a per-client limit, a deny route for scanners
// and a manual block. In a real server, wrap your mux the same way and
// serve it with http.Serve(g.Listener(l), handler) for the l4 limits.
func ExampleGuard_Middleware() {
	g, err := New(Config{
		"rate_limit.rate":  "1",
		"rate_limit.burst": "2",
		// Go takes routes as JSON text
		"routes": `[{"name": "probes", "path": "/wp-admin", "deny": true}]`,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer g.Close()

	app := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})
	srv := httptest.NewServer(g.Middleware(app))
	defer srv.Close()

	// the burst is 2, the third request is throttled; the deny route
	// refuses before any bucket
	for _, path := range []string{"/", "/", "/", "/wp-admin/"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			log.Fatal(err)
		}
		res.Body.Close()
		if ra := res.Header.Get("Retry-After"); ra != "" {
			fmt.Println(path, res.StatusCode, "Retry-After:", ra)
		} else {
			fmt.Println(path, res.StatusCode)
		}
	}

	// every check drops a blocked client until the block expires
	if err := g.Block(netip.MustParsePrefix("192.0.2.0/24"), time.Hour); err != nil {
		log.Fatal(err)
	}
	v := g.Check(netip.MustParseAddr("192.0.2.1"), "")
	fmt.Println("192.0.2.1 dropped:", v.Kind == Drop)
	// Output:
	// / 200
	// / 200
	// / 429 Retry-After: 1
	// /wp-admin/ 403
	// 192.0.2.1 dropped: true
}
