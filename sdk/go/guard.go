// Package dvarapala embeds the dvarapala engine (RFC 0008): the gateway's
// per-client rate limit, flood detection and connection limits, in process,
// with routes, blocks, egress shaping and reload (RFC 0028).
//
// One guard per process: behind several replicas, a client's limit and a
// provider's budget multiply by their number; divide the rates by it.
//
// It links the static C library from crates/ffi. Build it first:
//
//	cargo build --release -p dvarapala-ffi
package dvarapala

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/ffi
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libdvarapala.a -lm
#cgo linux LDFLAGS: -ldl -lpthread
#include <stdlib.h>
#include "dvarapala.h"
*/
import "C"

import (
	"errors"
	"net/netip"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"
)

// Config holds settings by their CONFIG.md names, for example
// "rate_limit.rate": "20" or "trusted_proxies": "192.0.2.0/24,2001:db8::/32".
// "routes" and "forward.destinations" take a JSON array with the
// CONFIG.md field names. Unset keys keep the gateway defaults.
type Config map[string]string

// Kind is what to do with a request.
type Kind int

const (
	Allow    Kind = C.DV_ALLOW
	Throttle Kind = C.DV_THROTTLE
	Drop     Kind = C.DV_DROP
)

// Verdict is the decision for one request. RetryAfter is set with Throttle.
type Verdict struct {
	Kind       Kind
	RetryAfter time.Duration
}

// Stats are the guard's counters, for the host's metrics.
type Stats struct {
	Allowed, Throttled, Dropped uint64
	Clients, Evictions          uint64
	// 0 normal, 1 suspect, 2 attack, 3 cooldown; 0 without detection
	DetectionState uint8
	RateZscore     float64
	SourceEntropy  float64
}

// Guard is safe for concurrent use. Close frees it.
type Guard struct {
	g *C.DvGuard
	// RouteHeaders, refreshed by Reload
	headers atomic.Pointer[[]string]
}

// New builds a guard; the error names the bad key.
func New(cfg Config) (*Guard, error) {
	// dv_last_error is per thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c, err := config(cfg)
	if err != nil {
		return nil, err
	}
	defer C.dv_config_free(c)
	g := C.dv_guard_new(c)
	if g == nil {
		return nil, lastError()
	}
	out := &Guard{g: g}
	out.loadHeaders()
	return out, nil
}

// config is a C config holding cfg; the caller holds its OS thread and
// frees it.
func config(cfg Config) (*C.DvConfig, error) {
	c := C.dv_config_new()
	for k, v := range cfg {
		ck, cv := C.CString(k), C.CString(v)
		rc := C.dv_config_set(c, ck, cv)
		C.free(unsafe.Pointer(ck))
		C.free(unsafe.Pointer(cv))
		if rc != C.DV_OK {
			err := lastError()
			C.dv_config_free(c)
			return nil, err
		}
	}
	return c, nil
}

// Check is the verdict for one request from peer, with the raw
// X-Forwarded-For value ("" when absent). An invalid peer is dropped.
func (g *Guard) Check(peer netip.Addr, xff string) Verdict {
	ip := C.CString(peer.String())
	defer C.free(unsafe.Pointer(ip))
	var x *C.char
	if xff != "" {
		x = C.CString(xff)
		defer C.free(unsafe.Pointer(x))
	}
	var v C.DvVerdict
	if C.dv_check(g.g, ip, x, &v) != C.DV_OK {
		// fail closed: only a zero netip.Addr gets here
		return Verdict{Kind: Drop}
	}
	return verdict(v.kind, v.retry_after_ms)
}

func verdict(kind C.int32_t, ms C.uint64_t) Verdict {
	return Verdict{Kind(kind), time.Duration(ms) * time.Millisecond}
}

func (g *Guard) Stats() Stats {
	var s C.DvStats
	C.dv_stats(g.g, &s)
	return Stats{
		uint64(s.allowed), uint64(s.throttled), uint64(s.dropped),
		uint64(s.clients), uint64(s.evictions),
		uint8(s.detection_state), float64(s.rate_zscore), float64(s.source_entropy),
	}
}

// Close frees the guard. Connections from Listener keep its state until
// they close; no other call may follow.
func (g *Guard) Close() {
	C.dv_guard_free(g.g)
	g.g = nil
}

// lastError reads dv_last_error; the caller holds its OS thread.
func lastError() error {
	if m := C.dv_last_error(); m != nil {
		return errors.New("dvarapala: " + C.GoString(m))
	}
	return errors.New("dvarapala: unknown error")
}
