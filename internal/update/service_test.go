package update

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	idle := false
	mac := &fakeMac{}
	s := &Service{Source: Source{BaseURL: g.srv.URL, Repo: "o/r"}, TokenFile: tokenFile, Keys: keys, Current: "v1.0.0",
		Bundle: bundle, Idle: func() bool { return idle }, WorkDir: filepath.Join(t.TempDir(), "update"), Mac: MacApp{Run: mac.run}, Log: slog.New(slog.DiscardHandler)}

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
	idle = true
	if err := s.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(bundle, "Contents", "MacOS", "boundgate-node")); string(b) != "new" {
		t.Fatal("the app was not replaced")
	}
	if _, err := os.Stat(s.WorkDir); err == nil {
		t.Fatal("the download was left behind")
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
