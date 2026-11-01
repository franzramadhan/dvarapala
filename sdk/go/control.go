//go:build cgo && (linux || darwin) && (amd64 || arm64)

package dvarapala

/*
#include <stdlib.h>
#include "dvarapala.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"time"
	"unsafe"
)

// ErrNotFound is an unknown egress destination or an unlisted block.
var ErrNotFound = errors.New("dvarapala: not found")

// Reload applies cfg to the running guard (RFC 0028), keeping client
// counts, the detection baseline, blocks and egress queues. A key that
// only applies at New fails and leaves the guard as it was. Safe with
// checks in flight.
func (g *Guard) Reload(cfg Config) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c, err := config(cfg)
	if err != nil {
		return err
	}
	defer C.dv_config_free(c)
	if C.dv_guard_reload(g.g, c) != C.DV_OK {
		return lastError()
	}
	g.loadHeaders()
	return nil
}

// Block drops requests and connections from prefix for ttl, 0 for
// admin.max_block_ttl.
func (g *Guard) Block(prefix netip.Prefix, ttl time.Duration) error {
	p := C.CString(prefix.String())
	defer C.free(unsafe.Pointer(p))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.dv_block(g.g, p, C.uint64_t(ttl.Milliseconds())) != C.DV_OK {
		return lastError()
	}
	return nil
}

// Unblock lifts the block on prefix; ErrNotFound when it is not listed.
func (g *Guard) Unblock(prefix netip.Prefix) error {
	p := C.CString(prefix.String())
	defer C.free(unsafe.Pointer(p))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	switch C.dv_unblock(g.g, p) {
	case C.DV_OK:
		return nil
	case C.DV_E_NOT_FOUND:
		return ErrNotFound
	default:
		return lastError()
	}
}

// A Block in force and the time it has left.
type Block struct {
	Prefix netip.Prefix
	TTL    time.Duration
}

func (g *Guard) Blocks() ([]Block, error) {
	s := C.dv_blocks(g.g)
	if s == nil {
		return nil, errors.New("dvarapala: no block list")
	}
	defer C.dv_string_free(s)
	var raw []struct {
		CIDR  string `json:"cidr"`
		TTLMs int64  `json:"ttl_ms"`
	}
	if err := json.Unmarshal([]byte(C.GoString(s)), &raw); err != nil {
		return nil, err
	}
	out := make([]Block, len(raw))
	for i, b := range raw {
		p, err := netip.ParsePrefix(b.CIDR)
		if err != nil {
			return nil, err
		}
		out[i] = Block{p, time.Duration(b.TTLMs) * time.Millisecond}
	}
	return out, nil
}

// EgressRefused is a destination over its queue or its max_wait.
type EgressRefused struct {
	Dest       string
	RetryAfter time.Duration
}

func (e *EgressRefused) Error() string {
	return fmt.Sprintf("dvarapala: egress to %s refused, retry after %s", e.Dest, e.RetryAfter)
}

// Egress returns when a call to dest (a destination's name) may go, or
// *EgressRefused, ErrNotFound or ctx's error. A wait is spent once given
// out, even when ctx ends first.
func (g *Guard) Egress(ctx context.Context, dest string) error {
	d := C.CString(dest)
	defer C.free(unsafe.Pointer(d))
	var s C.DvSlot
	if C.dv_egress(g.g, d, &s) != C.DV_OK {
		return ErrNotFound
	}
	wait := time.Duration(s.ms) * time.Millisecond
	switch s.kind {
	case C.DV_SLOT_NOW:
		return nil
	case C.DV_SLOT_REFUSE:
		return &EgressRefused{dest, wait}
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// EgressPause holds every call to dest for d (a provider's Retry-After),
// at most the destination's max_pause.
func (g *Guard) EgressPause(dest string, d time.Duration) error {
	c := C.CString(dest)
	defer C.free(unsafe.Pointer(c))
	if C.dv_egress_pause(g.g, c, C.uint64_t(d.Milliseconds())) != C.DV_OK {
		return ErrNotFound
	}
	return nil
}
