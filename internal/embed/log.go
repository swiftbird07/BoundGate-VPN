package embed

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// newPlatformHandler writes records as text lines (without time: the
// platform's log has its own) to Platform.Log.
func newPlatformHandler(p Platform, level slog.Level) slog.Handler {
	w := &lineWriter{p: p}
	return slog.NewTextHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}})
}

// lineWriter gets one Write per record from the text handler.
type lineWriter struct {
	mu sync.Mutex
	p  Platform
}

func (w *lineWriter) Write(b []byte) (int, error) {
	line := string(bytes.TrimRight(b, "\n"))
	level := slog.LevelInfo
	if rest, ok := strings.CutPrefix(line, "level="); ok {
		name, _, _ := strings.Cut(rest, " ")
		_ = level.UnmarshalText([]byte(name))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.p.Log(int(level), line)
	return len(b), nil
}

func parseLevel(s string) slog.Level {
	var l slog.Level
	if s == "" || l.UnmarshalText([]byte(s)) != nil {
		return slog.LevelInfo
	}
	return l
}

type discard struct{}

func (discard) Enabled(context.Context, slog.Level) bool  { return false }
func (discard) Handle(context.Context, slog.Record) error { return nil }
func (d discard) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discard) WithGroup(string) slog.Handler           { return d }
