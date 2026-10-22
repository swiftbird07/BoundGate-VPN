package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// The control plane has to see how much room its own database takes and how
// much is left, because nothing else does: on 2026-10-22 a 90-day retention
// had grown it to 7.5 GB on a 16 GB disk and the first sign was every node
// getting 503 (R139).
func TestTheDatabaseKnowsItsSizeAndWhatIsLeft(t *testing.T) {
	dir := t.TempDir()
	d, err := Open(context.Background(), filepath.Join(dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	size, free := d.Size()
	if size == 0 {
		t.Error("the database has no size")
	}
	if free == 0 {
		t.Error("the free space on the disk is unknown")
	}

	// it grows with what is written, write-ahead log included
	ctx := context.Background()
	for i := 0; i < 2000; i++ {
		d.InsertLog(ctx, LogEvent{Stream: "flow", Message: "a log event with some text in it", Attrs: map[string]any{"event": "allow"}})
	}
	if grown, _ := d.Size(); grown <= size {
		t.Errorf("size did not grow with 2000 events: %d -> %d", size, grown)
	}
}

func TestTheWarningNamesTheCornerThatCannotBeRepaired(t *testing.T) {
	const gb = 1 << 30
	cases := []struct {
		name       string
		size, free uint64
		want       string
	}{
		{"room to work", 2 * gb, 40 * gb, ""},
		{"unknown free space", 2 * gb, 0, ""},
		{"nothing written yet", 0, 0, ""},
		// 2026-10-22 on pVPN, shortly before the disk was full
		{"bigger than what is left", 7*gb + gb/2, 3 * gb, "rebuilt or vacuumed"},
		{"twice as big as what is left", gb, gb / 2, "rebuilt or vacuumed"},
		{"small database, full disk", 100 << 20, 700 << 20, "less than a gigabyte"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SpaceWarning(c.size, c.free)
			if c.want == "" {
				if got != "" {
					t.Fatalf("warned without reason: %q", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("warning %q does not mention %q", got, c.want)
			}
		})
	}
}
