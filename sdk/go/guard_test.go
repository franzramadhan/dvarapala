//go:build cgo && (linux || darwin) && (amd64 || arm64)

package dvarapala

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func guard(t *testing.T, cfg Config) *Guard {
	t.Helper()
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	return g
}

func TestBadConfigNamesTheKey(t *testing.T) {
	_, err := New(Config{"rate_limit.rate": "fast"})
	if err == nil || !strings.Contains(err.Error(), "rate_limit.rate") {
		t.Fatalf("got %v", err)
	}
}

// RFC 0008 case 9
func TestMiddlewareThrottles(t *testing.T) {
	g := guard(t, Config{"rate_limit.rate": "1", "rate_limit.burst": "1"})
	srv := httptest.NewServer(g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})))
	defer srv.Close()
	for i, want := range []int{200, 429} {
		res, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("request %d: %d, want %d", i, res.StatusCode, want)
		}
		if want == 429 && res.Header.Get("Retry-After") != "1" {
			t.Fatalf("Retry-After %q", res.Header.Get("Retry-After"))
		}
	}
}

// RFC 0008 case 10, run with -race
func TestSharedAcrossGoroutines(t *testing.T) {
	g := guard(t, Config{"rate_limit.rate": "50", "rate_limit.burst": "10"})
	peer := netip.MustParseAddr("192.0.2.10")
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			for range 100 {
				if g.Check(peer, "").Kind == Drop {
					t.Error("dropped without detection")
				}
			}
		})
	}
	wg.Wait()
	s := g.Stats()
	if s.Allowed+s.Throttled != 10000 || s.Clients != 1 {
		t.Fatalf("%+v", s)
	}
	// one bucket: at most the burst plus what refilled while the test ran
	if s.Allowed > 10+50*uint64(time.Since(start).Seconds()+1) {
		t.Fatalf("allowed %d over the bound", s.Allowed)
	}
}

var start = time.Now()

// RFC 0008 case 17
func TestListenerCapsPerClient(t *testing.T) {
	g := guard(t, Config{"l4.max_per_client": "1"})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	})}
	go srv.Serve(g.Listener(l))
	defer srv.Close()

	first, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// the server holds the first connection open (keep-alive)
	io.WriteString(first, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	buf := make([]byte, 12)
	if _, err := io.ReadFull(first, buf); err != nil || string(buf) != "HTTP/1.1 200" {
		t.Fatalf("first: %q %v", buf, err)
	}

	second, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := second.Read(buf); n != 0 || err == nil {
		t.Fatalf("second: %d bytes, %v", n, err)
	}
}
