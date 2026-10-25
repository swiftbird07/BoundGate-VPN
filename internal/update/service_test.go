package update

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServiceCheckAndApply(t *testing.T) {
	const id, team = "de.swiftbird.boundgate", "ABCDE12345"
	signer, keys := newKey(t)
	g := newFakeGitea(t)
	zip := []byte(id + "\n" + team)
	a := asset("BoundGate.zip", zip)
	a.Arch = runtime.GOARCH
	a.OS = runtime.GOOS
	g.publish(t, signer, Namespace, Manifest{Type: ManifestType, Version: "v1.1.0", Created: time.Now().UTC(), Assets: []Asset{a}}, map[string][]byte{"BoundGate.zip": zip})

	tokenFile := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tokenFile, []byte("sekrit\n"), 0o600)
	bundle := installed(t, id, team)
	var idle atomic.Bool
	mac := &fakeMac{}
	restarted := make(chan struct{}, 1)
	restartDelay = 10 * time.Millisecond
	s := &Service{Source: Source{BaseURL: g.srv.URL, Repo: "o/r"}, TokenFile: tokenFile, Keys: keys, Current: "v1.0.0",
		Bundle: bundle, Idle: idle.Load, WorkDir: filepath.Join(t.TempDir(), "update"), Mac: MacApp{Run: mac.run}, Log: slog.New(slog.DiscardHandler),
		Restart: func() { restarted <- struct{}{} }}

	st := s.Check(context.Background())
	if st.Error != "" || !st.Available || st.Latest != "v1.1.0" || !st.CanInstall {
		t.Fatalf("check: %+v", st)
	}
	if g.sawToken["/api/v1/repos/o/r/releases/latest"] != "token sekrit" {
		t.Fatal("token file not used")
	}
	if err := s.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "disconnect") {
		t.Fatalf("installed while the node was up: %v", err)
	}
	idle.Store(true)
	if err := s.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	// the daemon ends right after the install, so that the app it opens
	// again meets the new release, not the old one for as long as it stays
	// connected
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon did not restart after the install")
	}
	if b, _ := os.ReadFile(filepath.Join(bundle, "Contents", "MacOS", "boundgate-node")); string(b) != "new" {
		t.Fatal("the app was not replaced")
	}
	if _, err := os.Stat(s.WorkDir); err == nil {
		t.Fatal("the download was left behind")
	}
	// until the daemon restarts from the new app it still is the old release:
	// the status says what happened instead of offering the same update again
	// (the app showed "Update available" and then "v… is the latest release")
	if st := s.Status(); st.Available || st.Installed != "v1.1.0" {
		t.Fatalf("after the install: %+v", st)
	}
	if st := s.Check(context.Background()); st.Available || st.Installed != "v1.1.0" {
		t.Fatalf("a check after the install offers it again: %+v", st)
	}

	// the same release again is not an update, and an older one never is
	s.Current = "v1.1.0"
	if err := s.Apply(context.Background()); err == nil || !strings.Contains(err.Error(), "latest") {
		t.Fatalf("reinstalled the same release: %v", err)
	}
	s.Current = "v2.0.0"
	if st := s.Check(context.Background()); st.Available {
		t.Fatal("a downgrade was offered")
	}
	// a development build looks but never installs
	s.Current = "dev"
	if st := s.Check(context.Background()); st.Available || st.Latest != "v1.1.0" {
		t.Fatalf("dev build: %+v", st)
	}
	// outside an app bundle there is nothing to install into
	s.Current, s.Bundle = "v1.0.0", ""
	if err := s.Apply(context.Background()); err == nil {
		t.Fatal("installed without a bundle")
	}
	if st := s.Status(); st.CanInstall || st.InstallHint == "" {
		t.Fatalf("status without bundle: %+v", st)
	}
}

// A node that was connected in the second between the install and the
// restart is not cut off: the daemon restarts the next time it is down.
func TestNoRestartUnderAConnectedNode(t *testing.T) {
	restartDelay = 10 * time.Millisecond
	var idle atomic.Bool
	restarted := make(chan struct{}, 1)
	s := &Service{Idle: idle.Load, Log: slog.New(slog.DiscardHandler), Restart: func() { restarted <- struct{}{} }}
	s.restartSoon()
	select {
	case <-restarted:
		t.Fatal("restarted under a connected node")
	case <-time.After(200 * time.Millisecond):
	}
	(&Service{Log: slog.New(slog.DiscardHandler)}).restartSoon() // unsupervised: nothing to call
}
