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

	files []*os.File
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
}

// Open creates the streams. Files are opened append-only with mode 0640.
func Open(o Options) (*Streams, error) {
	if o.Level == nil {
		o.Level = slog.LevelInfo
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
			f, err := os.OpenFile(filepath.Join(o.Dir, name+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
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
