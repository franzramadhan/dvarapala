package dvarapala

/*
#include <stdlib.h>
#include "dvarapala.h"
*/
import "C"

import (
	"net"
	"sync"
	"unsafe"
)

// Listener applies the l4.* connection limits (RFC 0009): Accept closes a
// refused connection and waits for the next, Close on a connection frees
// its place. Connections without a TCP peer address pass through.
func (g *Guard) Listener(l net.Listener) net.Listener {
	return &listener{l, g}
}

type listener struct {
	net.Listener
	g *Guard
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		a, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			return c, nil
		}
		ip := C.CString(a.AddrPort().Addr().Unmap().String())
		var h *C.DvConn
		rc := C.dv_conn_open(l.g.g, ip, &h)
		C.free(unsafe.Pointer(ip))
		if rc != C.DV_OK {
			c.Close()
			continue
		}
		return &conn{Conn: c, h: h}, nil
	}
}

type conn struct {
	net.Conn
	h    *C.DvConn
	once sync.Once
}

func (c *conn) Close() error {
	c.once.Do(func() { C.dv_conn_close(c.h) })
	return c.Conn.Close()
}
