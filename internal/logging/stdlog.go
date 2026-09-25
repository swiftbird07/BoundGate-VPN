package logging

import (
	"log"
	"log/slog"
	"strings"
	"sync"
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
	t.l.Info(strings.TrimRight(string(p), "\n"), "source", "library")
	return len(p), nil
}
