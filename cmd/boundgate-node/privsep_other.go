//go:build !linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
)

const workerArg = "privsep-worker"

func runPrivileged(context.Context, []byte, config) error {
	return errors.New("privsep: privilege separation runs on Linux only for now; remove privsep from the configuration (docs/PRIVSEP.md)")
}

func runWorker() int {
	fmt.Fprintln(os.Stderr, "boundgate-node: privilege separation runs on Linux only")
	return 1
}
