//go:build !windows

// boundgate-tray is the Windows tray app; the Mac has BoundGate.app, Linux
// the command line (boundgatectl).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "boundgate-tray is for Windows; use boundgatectl here")
	os.Exit(2)
}
