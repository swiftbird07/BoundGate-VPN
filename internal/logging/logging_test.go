package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStreamFilesRotateAtTheLimit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Options{Dir: dir, MaxBytes: 4 << 10, Component: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	line := strings.Repeat("x", 200)
	for range 200 {
		s.Flow.Info(line)
	}
	for _, name := range []string{"flow.jsonl", "flow.jsonl.1", "flow.jsonl.2", "flow.jsonl.3"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Size() > 4<<10 {
			t.Fatalf("%s is %d bytes", name, st.Size())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "flow.jsonl.4")); err == nil {
		t.Fatal("more rotated files kept than keepRotated")
	}
}

func TestThrottleStdLog(t *testing.T) {
	var buf bytes.Buffer
	th := &throttle{l: slog.New(slog.NewTextHandler(&buf, nil)), per: stdPer, burst: 3}
	for range 10 {
		th.Write([]byte("dropping proxied packet\n"))
	}
	if n := strings.Count(buf.String(), "dropping proxied packet"); n != 3 {
		t.Fatalf("%d lines passed", n)
	}
	th.start = th.start.Add(-stdPer)
	th.Write([]byte("next\n"))
	if !strings.Contains(buf.String(), "suppressed") || !strings.Contains(buf.String(), "count=7") {
		t.Fatalf("no summary: %s", buf.String())
	}
}

// A library line can be annotated by whoever knows more: the library writes
// plain text and knows nothing of nodes or tunnels.
func TestExplainStdLog(t *testing.T) {
	var buf bytes.Buffer
	th := &throttle{l: slog.New(slog.NewTextHandler(&buf, nil)), per: time.Minute, burst: 10}
	ExplainStdLog(func(line string) StdLogNote {
		if !strings.Contains(line, "not allowed") {
			return StdLogNote{}
		}
		return StdLogNote{Attrs: []any{"src_node", "orkus_node"}, Warn: true}
	})
	defer ExplainStdLog(nil)

	th.Write([]byte("connect-ip: datagram source address not allowed: 10.25.0.1\n"))
	th.Write([]byte("handling stream failed: eof\n"))
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "src_node=orkus_node") {
		t.Errorf("the annotated line: %q", out)
	}
	if n := strings.Count(out, "src_node"); n != 1 {
		t.Errorf("a line nobody explained got attributes: %q", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("the other line is not an info line: %q", out)
	}
}
