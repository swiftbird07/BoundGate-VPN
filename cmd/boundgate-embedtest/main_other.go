//go:build !linux

// Command boundgate-embedtest is Linux only (see main_linux.go).
package main

import "log"

func main() { log.Fatal("boundgate-embedtest runs on Linux only") }
