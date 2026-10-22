package logging

import (
	"log"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ThrottleStdLog routes what libraries write with the standard log package
// to l, at most stdBurst lines per stdPer; the rest is counted and reported
// in one line when the next may pass. connect-ip-go writes one line for
// every packet it refuses, and how many that are is up to the peer.
func ThrottleStdLog(l *slog.Logger) {
	log.SetFlags(0)
	log.SetOutput(&throttle{l: l, per: stdPer, burst: stdBurst})
}

// StdLogNote is what BoundGate adds to a library line: the library writes
// plain text and knows nothing of nodes, tunnels or who owns an address.
type StdLogNote struct {
	// Attrs are appended to the line's attributes.
	Attrs []any
	// Warn makes it a warning instead of an informational line.
	Warn bool
}

var explainStdLog atomic.Pointer[func(string) StdLogNote]

// ExplainStdLog sets who may annotate library log lines. connect-ip-go
// reports a refused packet as "connect-ip: datagram source address not
// allowed: 10.25.0.8" and that is all of it — no peer, no tunnel, no
// destination — because it takes no logger and offers no callback (it is
// pinned at v0.2.0, R1). The node fills in what it knows. f must not block
// and must survive any text; nil switches it off.
func ExplainStdLog(f func(line string) StdLogNote) {
	if f == nil {
		explainStdLog.Store(nil)
		return
	}
	explainStdLog.Store(&f)
}

const (
	stdPer   = 10 * time.Second
	stdBurst = 20
)

type throttle struct {
	mu         sync.Mutex
	l          *slog.Logger
	per        time.Duration
	burst      int
	start      time.Time
	n, dropped int
}

func (t *throttle) Write(p []byte) (int, error) {
	now := time.Now()
	t.mu.Lock()
	if now.Sub(t.start) >= t.per {
		if t.dropped > 0 {
			t.l.Warn("library log lines suppressed", "count", t.dropped, "within", t.per.String())
		}
		t.start, t.n, t.dropped = now, 0, 0
	}
	if t.n >= t.burst {
		t.dropped++
		t.mu.Unlock()
		return len(p), nil
	}
	t.n++
	t.mu.Unlock()
	line := strings.TrimRight(string(p), "\n")
	attrs := []any{"source", "library"}
	note := StdLogNote{}
	if f := explainStdLog.Load(); f != nil {
		note = (*f)(line)
		attrs = append(attrs, note.Attrs...)
	}
	if note.Warn {
		t.l.Warn(line, attrs...)
	} else {
		t.l.Info(line, attrs...)
	}
	return len(p), nil
}
