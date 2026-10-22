//go:build !unix

package db

// freeBytes: the control plane is built for Linux and macOS; elsewhere the
// free space is simply unknown, and nothing warns about it.
func freeBytes(string) uint64 { return 0 }
