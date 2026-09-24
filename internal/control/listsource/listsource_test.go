package listsource_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/listsource"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type notifier struct{ last atomic.Uint64 }

func (n *notifier) Notify(v uint64) { n.last.Store(v) }

func open(t *testing.T) *db.DB {
	t.Helper()
	store, err := db.Open(context.Background(), filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func newList(t *testing.T, store *db.DB, l db.List) db.List {
	t.Helper()
	out, _, err := store.CreateList(context.Background(), l, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFetchReplacesEntriesAndFollowsETag(t *testing.T) {
	ctx := context.Background()
	var calls, conditional atomic.Int64
	body := "# a comment\n10.0.0.0/8\n192.168.5.7\n\n10.0.0.0/8\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	store := open(t)
	l := newList(t, store, db.List{Name: "from-git", Kind: "ip", Entries: []string{"172.16.0.1/32"},
		SourceURL: srv.URL, SourceInterval: time.Minute})
	n := &notifier{}
	f := listsource.New(quiet())

	l, version, err := f.Fetch(ctx, store, n, l)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "192.168.5.7/32"}; strings.Join(l.Entries, ",") != strings.Join(want, ",") {
		t.Fatalf("entries %v", l.Entries)
	}
	if version == 0 || n.last.Load() != version {
		t.Fatalf("the nodes were not told: version %d, notified %d", version, n.last.Load())
	}
	if l.SourceStatus != "" || l.SourceFetchedAt.IsZero() || l.SourceETag != `"v1"` {
		t.Fatalf("source state %+v", l)
	}

	// the same file again: a conditional request, no new snapshot
	l, version, err = f.Fetch(ctx, store, n, l)
	if err != nil || version != 0 {
		t.Fatalf("second fetch: %v, version %d", err, version)
	}
	if conditional.Load() != 1 || len(l.Entries) != 2 {
		t.Fatalf("conditional %d, entries %v", conditional.Load(), l.Entries)
	}

	// due only after the interval
	due, err := store.ListsDue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Fatalf("fetched just now, still due: %v", due)
	}
}

func TestFetchKeepsTheListWhenTheSourceIsBad(t *testing.T) {
	ctx := context.Background()
	mode := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch <-mode {
		case "500":
			w.WriteHeader(http.StatusInternalServerError)
		case "junk":
			_, _ = w.Write([]byte("10.0.0.0/8\nnot an address\n"))
		case "secret":
			if r.Header.Get("Private-Token") != "s3cret" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte("10.1.0.0/16\n"))
		}
	}))
	defer srv.Close()

	store := open(t)
	l := newList(t, store, db.List{Name: "keeps", Kind: "ip", Entries: []string{"172.16.0.1/32"},
		SourceURL: srv.URL, SourceInterval: time.Minute, SourceHeader: "Private-Token", SourceSecret: "s3cret"})
	f := listsource.New(quiet())

	for _, what := range []string{"500", "junk"} {
		mode <- what
		got, version, err := f.Fetch(ctx, store, nil, l)
		if err == nil {
			t.Fatalf("%s: no error", what)
		}
		if version != 0 || len(got.Entries) != 1 || got.Entries[0] != "172.16.0.1/32" {
			t.Fatalf("%s: the list lost its entries: %v", what, got.Entries)
		}
		if got.SourceStatus == "" {
			t.Fatalf("%s: no status for the admin", what)
		}
		l = got
	}

	mode <- "secret"
	l, version, err := f.Fetch(ctx, store, nil, l)
	if err != nil {
		t.Fatalf("with the header: %v", err)
	}
	if version == 0 || len(l.Entries) != 1 || l.Entries[0] != "10.1.0.0/16" {
		t.Fatalf("entries %v (version %d)", l.Entries, version)
	}
	if l.SourceStatus != "" {
		t.Fatalf("status after a fetch that worked: %q", l.SourceStatus)
	}
}

func TestSourceIsCheckedAndRedirectsStayOnTheHost(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.9.0.0/16\n"))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()

	store := open(t)
	l := newList(t, store, db.List{Name: "redirect", Kind: "ip", Entries: []string{"172.16.0.1/32"},
		SourceURL: srv.URL, SourceInterval: time.Minute})
	if _, _, err := listsource.New(quiet()).Fetch(context.Background(), store, nil, l); err == nil ||
		!strings.Contains(err.Error(), "another host") {
		t.Fatalf("a redirect to another host must not be followed: %v", err)
	}

	for _, bad := range []string{"ftp://example.test/x", "file:///etc/passwd", "https://"} {
		if _, _, _, err := db.CleanListSource(bad, time.Minute, ""); err == nil {
			t.Fatalf("%q was accepted as a source url", bad)
		}
	}
	if _, _, _, err := db.CleanListSource("https://example.test/x", 5*time.Second, ""); err == nil {
		t.Fatal("an interval below the minimum was accepted")
	}
	if u, iv, _, err := db.CleanListSource("https://example.test/x", 0, ""); err != nil || iv != 15*time.Minute || u == "" {
		t.Fatalf("default interval: %v %v %v", u, iv, err)
	}
}

func TestParseTakesTextAndJSON(t *testing.T) {
	text, err := listsource.Parse("dns", []byte("Example.COM\n*.internal.example\n# nothing\n"))
	if err != nil {
		t.Fatal(err)
	}
	js, err := listsource.Parse("dns", []byte(`["*.internal.example", "example.com"]`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(text, ",") != strings.Join(js, ",") || len(text) != 2 {
		t.Fatalf("text %v, json %v", text, js)
	}
	if _, err := listsource.Parse("sni", []byte(`{"entries": []}`)); err == nil {
		t.Fatal("an object was accepted")
	}
}
