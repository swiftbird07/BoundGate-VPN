package safefile

import "os"

// Windows: the service's directories are protected by their DACL
// (boundgate-node protect), and there is no unprivileged worker.
func openOf(path string, _ int) (*os.File, error) { return os.Open(path) }
