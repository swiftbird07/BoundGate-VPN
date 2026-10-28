package db

import (
	"context"
	"errors"
	"testing"
)

// A fetch takes seconds; an admin who changed the source meanwhile must
// not get the old source's entries written over the new one's.
func TestSaveListFetchDropsTheResultOfAnOldSource(t *testing.T) {
	d := open(t)
	ctx := context.Background()
	l, _, err := d.CreateList(ctx, List{Name: "blocked", Kind: "ip", Entries: []string{"10.0.0.1"}, SourceURL: "https://b.example/list"}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveListFetch(ctx, l.ID, "https://a.example/list", []string{"10.9.9.9"}, `"old"`, ""); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("a result of the old source was stored: %v", err)
	}
	if _, err := d.SaveListFetch(ctx, l.ID, "https://a.example/list", nil, "", "timeout"); !errors.Is(err, ErrSourceChanged) {
		t.Fatalf("a failure of the old source was recorded: %v", err)
	}
	got, _ := d.ListByID(ctx, l.ID)
	if len(got.Entries) != 1 || got.Entries[0] != "10.0.0.1" || got.SourceETag != "" || got.SourceStatus != "" {
		t.Fatalf("the list changed: %+v", got)
	}
	v, err := d.SaveListFetch(ctx, l.ID, "https://b.example/list", []string{"10.9.9.9"}, `"new"`, "")
	if err != nil || v == 0 {
		t.Fatalf("the current source's result: version %d, %v", v, err)
	}
	if got, _ := d.ListByID(ctx, l.ID); len(got.Entries) != 1 || got.Entries[0] != "10.9.9.9" || got.SourceETag != `"new"` {
		t.Fatalf("after the fetch: %+v", got)
	}
}
