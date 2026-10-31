//go:build !cgo || !(linux || darwin) || !(amd64 || arm64)

package dvarapala

// RFC 0027: without cgo, or on a platform with no prebuilt library, the
// build stops here instead of at a list of undefined C symbols.
var _ = dvarapala_needs_cgo_on_linux_or_darwin_with_amd64_or_arm64
