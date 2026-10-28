package dvarapala

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Middleware answers 429 with Retry-After (seconds, rounded up, at least
// 1) or 403 with Connection: close, as the gateway does, and passes the
// rest to next. The peer is r.RemoteAddr.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, _ := netip.ParseAddrPort(r.RemoteAddr)
		xff := strings.Join(r.Header.Values("X-Forwarded-For"), ", ")
		v := g.Check(peer.Addr().Unmap(), xff)
		switch v.Kind {
		case Throttle:
			ms := v.RetryAfter.Milliseconds()
			w.Header().Set("Retry-After", strconv.FormatInt(max((ms+999)/1000, 1), 10))
			w.WriteHeader(http.StatusTooManyRequests)
		case Drop:
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusForbidden)
		default:
			next.ServeHTTP(w, r)
		}
	})
}
