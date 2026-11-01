//go:build cgo && (linux || darwin) && (amd64 || arm64)

package dvarapala

// The static library from a checkout. The release writes its own link.go
// for the dvarapala-go module, with a prebuilt library per platform
// (RFC 0027).

/*
#cgo CFLAGS: -I${SRCDIR}/../../crates/ffi
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libdvarapala.a -lm
#cgo linux LDFLAGS: -ldl -lpthread
*/
import "C"
