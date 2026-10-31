package dvarapala

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Middleware applies the routes (RFC 0028) and answers 429 with
// Retry-After (seconds, rounded up, at least 1) or 403 with Connection:
// close, as the gateway does, and passes the rest to next. Input the guard
// refuses is a 400 with Connection: close; next never sees it. The peer is
// r.RemoteAddr.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, _ := netip.ParseAddrPort(r.RemoteAddr)
		v, err := g.CheckRequest(Request{
			Peer:    peer.Addr().Unmap(),
			XFF:     strings.Join(r.Header.Values("X-Forwarded-For"), ", "),
			Method:  r.Method,
			Host:    r.Host,
			Path:    r.URL.EscapedPath(),
			Headers: r.Header,
		})
		switch {
		case err != nil:
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusBadRequest)
		case v.Kind == Throttle:
			ms := v.RetryAfter.Milliseconds()
			w.Header().Set("Retry-After", strconv.FormatInt(max((ms+999)/1000, 1), 10))
			w.WriteHeader(http.StatusTooManyRequests)
		case v.Kind == Drop:
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusForbidden)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// Transport shapes each request through base (http.DefaultTransport when
// nil) by its URL's host, a destination's name: it waits for the slot
// with the request's context, and pauses the destination on a 429 or 503
// with Retry-After. Hosts without a destination pass through.
func (g *Guard) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripper{g, base}
}

type roundTripper struct {
	g    *Guard
	base http.RoundTripper
}

func (t roundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	dest := r.URL.Hostname()
	err := t.g.Egress(r.Context(), dest)
	if err == ErrNotFound {
		return t.base.RoundTrip(r)
	}
	if err != nil {
		return nil, err
	}
	res, err := t.base.RoundTrip(r)
	if err == nil && (res.StatusCode == http.StatusTooManyRequests || res.StatusCode == http.StatusServiceUnavailable) {
		if d, ok := retryAfter(res.Header.Get("Retry-After")); ok {
			_ = t.g.EgressPause(dest, d)
		}
	}
	return res, err
}

// retryAfter reads delay-seconds or an HTTP date.
func retryAfter(v string) (time.Duration, bool) {
	if s, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(s) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(time.Until(t), 0), true
	}
	return 0, false
}
