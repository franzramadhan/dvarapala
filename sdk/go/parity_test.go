package dvarapala

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const login = `[{"name": "login", "path": "=/login", "methods": ["POST"], "rate": 1, "burst": 2}]`

// RFC 0028 cases 15 and 19
func TestMiddlewareRoutesAndBadInput(t *testing.T) {
	var ran atomic.Int32
	h := guard(t, Config{"routes": login}).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran.Add(1)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	var codes []int
	for range 3 {
		res, err := http.Post(srv.URL+"/login", "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		codes = append(codes, res.StatusCode)
		if res.StatusCode == http.StatusTooManyRequests && res.Header.Get("Retry-After") != "1" {
			t.Fatalf("Retry-After %q", res.Header.Get("Retry-After"))
		}
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Fatalf("codes %v", codes)
	}
	res, err := http.Get(srv.URL + "/" + strings.Repeat("a", 9000))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest || ran.Load() != 2 {
		t.Fatalf("long path: %d, handler ran %d times", res.StatusCode, ran.Load())
	}
}

// RFC 0028 case 16
func TestTransportPausesOnRetryAfter(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	t.Cleanup(srv.Close)
	dest := `[{"origin": "` + srv.URL + `", "rate": 100, "burst": 10}]`
	c := &http.Client{Transport: guard(t, Config{"forward.destinations": dest}).Transport(nil)}
	for range 2 {
		start := time.Now()
		res, err := c.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if n.Load() == 2 && time.Since(start) < 900*time.Millisecond {
			t.Fatalf("second request after %s", time.Since(start))
		}
	}
}

// RFC 0028 case 20, under -race
func TestReloadWithChecksInFlight(t *testing.T) {
	g := guard(t, Config{"routes": login, "rate_limit.rate": "1"})
	var wg sync.WaitGroup
	for i := 1; i <= 8; i++ {
		wg.Go(func() {
			r := Request{Peer: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), Method: "POST", Path: "/login"}
			for range 500 {
				v, err := g.CheckRequest(r)
				if err != nil || v.Kind == Drop {
					t.Errorf("%v %v", v, err)
					return
				}
			}
		})
	}
	for i := range 100 {
		rate := map[bool]string{true: "100", false: "1"}[i%2 == 0]
		if err := g.Reload(Config{"routes": login, "rate_limit.rate": rate}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestBlocksEgressAndReload(t *testing.T) {
	dest := `[{"origin": "https://api.example.com", "name": "stripe", "rate": 10, "max_queue": 1, "max_wait": "1s"}]`
	g := guard(t, Config{"forward.destinations": dest})
	p := netip.MustParsePrefix("192.0.2.0/24")
	if err := g.Block(p, time.Minute); err != nil {
		t.Fatal(err)
	}
	if g.Check(netip.MustParseAddr("192.0.2.9"), "").Kind != Drop {
		t.Fatal("blocked client allowed")
	}
	if b, _ := g.Blocks(); len(b) != 1 || b[0].Prefix != p {
		t.Fatalf("blocks %v", b)
	}
	if g.Unblock(p) != nil || g.Unblock(p) != ErrNotFound {
		t.Fatal("unblock")
	}
	ctx := context.Background()
	if g.Egress(ctx, "stripe") != nil || g.Egress(ctx, "nope") != ErrNotFound {
		t.Fatal("egress")
	}
	_ = g.EgressPause("stripe", 2*time.Second)
	var refused *EgressRefused
	if !errors.As(g.Egress(ctx, "stripe"), &refused) || refused.RetryAfter < time.Second {
		t.Fatalf("pause: %v", refused)
	}
	err := g.Reload(Config{"rate_limit.max_clients": "10"})
	if err == nil || !strings.Contains(err.Error(), "rate_limit.max_clients") {
		t.Fatalf("reload: %v", err)
	}
	if err := g.Reload(Config{"routes": `[{"name": "api", "key": "header:X-Api-Key", "rate": 1}]`}); err != nil {
		t.Fatal(err)
	}
	if h := g.RouteHeaders(); len(h) != 1 || h[0] != "x-api-key" {
		t.Fatalf("headers %v", h)
	}
}
