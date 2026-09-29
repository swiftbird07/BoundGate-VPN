//go:build cgo

package sandbox

// with cgo (the race detector's builds) Go cannot reach every thread, and
// the C library's threads ask the kernel for more than Go's
const withCgo = true
