package embed

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// newPlatformHandler writes records as text lines (without time: the
// platform's log has its own) to Platform.Log. The level can change while
// the engine runs (Engine.SetLogLevel): a phone's debug log is switched on
// when something is wrong, not when the app was started.
func newPlatformHandler(p Platform, level *slog.LevelVar) slog.Handler {
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

// flowHandler carries the flow log (one line per connection) to the
// platform's log when Config.FlowLog asks for it, and otherwise whenever
// the log level is debug: a connection that does not get through is what a
// debug log of a phone is read for.
type flowHandler struct {
	inner  slog.Handler
	always bool
	level  *slog.LevelVar
}

func (h flowHandler) on() bool { return h.always || h.level.Level() <= slog.LevelDebug }

func (h flowHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.on() && h.inner.Enabled(ctx, l)
}

func (h flowHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.on() {
		return nil
	}
	return h.inner.Handle(ctx, r)
}

func (h flowHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return flowHandler{inner: h.inner.WithAttrs(as), always: h.always, level: h.level}
}

func (h flowHandler) WithGroup(name string) slog.Handler {
	return flowHandler{inner: h.inner.WithGroup(name), always: h.always, level: h.level}
}
