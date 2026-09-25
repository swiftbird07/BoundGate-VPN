// Package logging provides the JSON Lines log streams that feed the SIEM.
// Every component writes one file per stream under a log directory and,
// optionally, the same records to stdout (for container logs).
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Stream names. They are also the file names (<name>.jsonl).
const (
	StreamSystem     = "system"     // process lifecycle, config, errors
	StreamAudit      = "audit"      // admin actions (who changed what)
	StreamAdminAuth  = "admin-auth" // admin logins, passkey events
	StreamUserAuth   = "user-auth"  // OIDC logins, sessions
	StreamEnrollment = "enrollment" // device requests, approvals, revocations
	StreamFlow       = "flow"       // per-flow decisions on the gateway
)

// Streams holds one logger per stream.
type Streams struct {
	System     *slog.Logger
	Audit      *slog.Logger
	AdminAuth  *slog.Logger
	UserAuth   *slog.Logger
	Enrollment *slog.Logger
	Flow       *slog.Logger

	files []*rotating
}

// Options controls where records go.
type Options struct {
	// Dir receives <stream>.jsonl files. Empty disables files.
	Dir string
	// Stdout mirrors every record to stdout.
	Stdout bool
	// Level is the minimum level (default Info).
	Level slog.Leveler
	// Component is added to every record, e.g. "gateway".
	Component string
	// MaxBytes is the size at which a stream file is rotated
	// (<stream>.jsonl.1 … .3 are kept). Default 256 MiB.
	MaxBytes int64
}

// Open creates the streams. Files are opened append-only with mode 0640.
func Open(o Options) (*Streams, error) {
	if o.Level == nil {
		o.Level = slog.LevelInfo
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = 256 << 20
	}
	if o.Dir == "" && !o.Stdout {
		o.Stdout = true
	}
	if o.Dir != "" {
		if err := os.MkdirAll(o.Dir, 0o750); err != nil {
			return nil, fmt.Errorf("logging: mkdir %s: %w", o.Dir, err)
		}
	}
	s := &Streams{}
	mk := func(name string) (*slog.Logger, error) {
		var ws []io.Writer
		if o.Dir != "" {
			f, err := openRotating(filepath.Join(o.Dir, name+".jsonl"), o.MaxBytes)
			if err != nil {
				return nil, fmt.Errorf("logging: open %s: %w", name, err)
			}
			s.files = append(s.files, f)
			ws = append(ws, f)
		}
		if o.Stdout {
			ws = append(ws, os.Stdout)
		}
		h := slog.NewJSONHandler(io.MultiWriter(ws...), &slog.HandlerOptions{Level: o.Level})
		l := slog.New(h).With("stream", name)
		if o.Component != "" {
			l = l.With("component", o.Component)
		}
		return l, nil
	}
	var err error
	for _, p := range []struct {
		name string
		dst  **slog.Logger
	}{
		{StreamSystem, &s.System},
		{StreamAudit, &s.Audit},
		{StreamAdminAuth, &s.AdminAuth},
		{StreamUserAuth, &s.UserAuth},
		{StreamEnrollment, &s.Enrollment},
		{StreamFlow, &s.Flow},
	} {
		if *p.dst, err = mk(p.name); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close closes the underlying files.
func (s *Streams) Close() {
	for _, f := range s.files {
		_ = f.Close()
	}
	s.files = nil
}

// keepRotated is how many rotated files of a stream stay next to it.
const keepRotated = 3

// rotating is an append-only stream file that moves itself aside at a size
// limit, so that whoever makes a component log (a peer whose packets are
// refused, a client that fails to sign in over and over) cannot fill the
// disk with it.
type rotating struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openRotating(path string, max int64) (*rotating, error) {
	r := &rotating{path: path, max: max}
	return r, r.open()
}

func (r *rotating) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotating) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, os.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		r.rotate()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// rotate shifts <path>.1 … to .2 …, the current file to .1, and starts an
// empty one. If it cannot, it keeps writing where it was.
func (r *rotating) rotate() {
	for i := keepRotated - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil {
		return
	}
	old := r.f
	if err := r.open(); err != nil {
		_ = os.Rename(r.path+".1", r.path)
		r.f = old
		return
	}
	_ = old.Close()
}

func (r *rotating) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
