//go:build !unix

package embed

import (
	"errors"
	"os"
)

func lockDir(string) (*os.File, error) {
	return nil, errors.New("embed: not supported on this platform (Windows runs the daemon)")
}
