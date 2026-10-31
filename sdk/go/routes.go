package dvarapala

/*
#include <stdlib.h>
#include "dvarapala.h"
*/
import "C"

import (
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"unsafe"
)

// Request is what CheckRequest reads (RFC 0028). Path is the raw path
// without the query; Host is the authority or Host header, "" when absent.
// Only the headers RouteHeaders names are read.
type Request struct {
	Peer    netip.Addr
	XFF     string
	Method  string
	Host    string
	Path    string
	Headers http.Header
}

// RequestVerdict is a Verdict with the matched route's name, "" for none.
type RequestVerdict struct {
	Verdict
	Route string
}

// CheckRequest is the verdict for r with the config's routes applied, as
// the gateway applies them. Bad input (a field over 8 KiB, a newline in a
// header value, no method or path) is an error: refuse the request.
func (g *Guard) CheckRequest(r Request) (RequestVerdict, error) {
	var lines strings.Builder
	for _, n := range *g.headers.Load() {
		if vs := r.Headers.Values(n); len(vs) > 0 {
			lines.WriteString(n + ": " + vs[0] + "\n")
		}
	}
	str := func(s string, null bool) *C.char {
		if null && s == "" {
			return nil
		}
		return C.CString(s)
	}
	req := C.DvRequest{
		ip:      str(r.Peer.String(), false),
		xff:     str(r.XFF, true),
		method:  str(r.Method, false),
		host:    str(r.Host, true),
		path:    str(r.Path, false),
		headers: str(lines.String(), true),
	}
	for _, p := range []*C.char{req.ip, req.xff, req.method, req.host, req.path, req.headers} {
		if p != nil {
			defer C.free(unsafe.Pointer(p))
		}
	}
	// dv_last_error is per thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var v C.DvRequestVerdict
	if C.dv_check_request(g.g, &req, &v) != C.DV_OK {
		return RequestVerdict{}, lastError()
	}
	out := RequestVerdict{Verdict: verdict(v.kind, v.retry_after_ms)}
	if v.route != nil {
		out.Route = C.GoString(v.route)
	}
	return out, nil
}

// RouteHeaders are the header names the routes' keys read, lower case.
func (g *Guard) RouteHeaders() []string {
	return *g.headers.Load()
}

func (g *Guard) loadHeaders() {
	h := strings.FieldsFunc(C.GoString(C.dv_route_headers(g.g)), func(r rune) bool { return r == ',' })
	g.headers.Store(&h)
}
