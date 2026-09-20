package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

func newKey(t *testing.T) (ssh.Signer, binding.Signers) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := Keys(ssh.MarshalAuthorizedKey(s.PublicKey()))
	if err != nil {
		t.Fatal(err)
	}
	return s, keys
}

// fakeGitea serves one release; fields can be bent per test.
type fakeGitea struct {
	mu       sync.Mutex
	tag      string
	files    map[string][]byte
	status   int
	sawToken map[string]string // path -> Authorization
	srv      *httptest.Server
}

func newFakeGitea(t *testing.T) *fakeGitea {
	g := &fakeGitea{files: map[string][]byte{}, sawToken: map[string]string{}}
	g.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.sawToken[r.URL.Path] = r.Header.Get("Authorization")
		if g.status != 0 {
			http.Error(w, "no", g.status)
			return
		}
		if r.URL.Path == "/api/v1/repos/o/r/releases/latest" {
			var assets []map[string]string
			for name := range g.files {
				assets = append(assets, map[string]string{"name": name, "browser_download_url": g.srv.URL + "/dl/" + name})
			}
			json.NewEncoder(w).Encode(map[string]any{"tag_name": g.tag, "html_url": g.srv.URL + "/o/r/releases/tag/" + g.tag, "assets": assets})
			return
		}
		if b, ok := g.files[strings.TrimPrefix(r.URL.Path, "/dl/")]; ok {
			w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGitea) publish(t *testing.T, signer ssh.Signer, namespace string, m Manifest, payload map[string][]byte) {
	t.Helper()
	for name, b := range payload {
		g.files[name] = b
	}
	raw, _ := json.Marshal(m)
	sig, err := binding.Sign(signer, namespace, raw)
	if err != nil {
		t.Fatal(err)
	}
	g.files["manifest.json"], g.files["manifest.json.sig"] = raw, []byte(sig)
	g.tag = m.Version
}

func asset(name string, b []byte) Asset {
	sum := sha256.Sum256(b)
	return Asset{Name: name, Kind: "app", OS: "darwin", Arch: "universal", Size: int64(len(b)), SHA256: hex.EncodeToString(sum[:])}
}

func TestLatestAndDownload(t *testing.T) {
	signer, keys := newKey(t)
	g := newFakeGitea(t)
	app := []byte("pretend this is BoundGate.app.zip")
	m := Manifest{Type: ManifestType, Version: "v1.2.3", Created: time.Now().UTC(), Assets: []Asset{asset("BoundGate-v1.2.3.zip", app)},
		Image: &Image{Ref: "registry/boundgate", Digest: "sha256:" + strings.Repeat("a", 64)}}
	g.publish(t, signer, Namespace, m, map[string][]byte{"BoundGate-v1.2.3.zip": app})
	src := Source{BaseURL: g.srv.URL, Repo: "o/r", Token: "sekrit"}

	r, err := src.Latest(context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Manifest.Version != "v1.2.3" || r.Manifest.Image.Digest == "" {
		t.Fatalf("manifest: %+v", r.Manifest)
	}
	a, ok := r.Manifest.Find("app", "darwin", "arm64")
	if !ok {
		t.Fatal("no app asset for darwin/arm64 (universal)")
	}
	dir := t.TempDir()
	path, err := src.Download(context.Background(), r, a, dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != string(app) {
		t.Fatal("downloaded file differs")
	}
	if g.sawToken["/api/v1/repos/o/r/releases/latest"] != "token sekrit" {
		t.Fatal("the token did not reach the configured instance")
	}

	// what the server serves no longer matches the signed manifest
	g.files["BoundGate-v1.2.3.zip"] = []byte("pretend this is BoundGate.app.zip, with a backdoor")
	if _, err := src.Download(context.Background(), r, a, t.TempDir()); err == nil {
		t.Fatal("a tampered asset was accepted")
	}
	same := []byte("pretend this is BoundGate.app.zix")
	g.files["BoundGate-v1.2.3.zip"] = same // same size, other content
	d2 := t.TempDir()
	if _, err := src.Download(context.Background(), r, a, d2); err == nil {
		t.Fatal("an asset with another SHA-256 was accepted")
	}
	if entries, _ := os.ReadDir(d2); len(entries) != 0 {
		t.Fatalf("a refused download left files: %v", entries)
	}
}

func TestLatestRefuses(t *testing.T) {
	signer, keys := newKey(t)
	stranger, _ := newKey(t)
	good := Manifest{Type: ManifestType, Version: "v1.2.3", Created: time.Now().UTC(), Assets: []Asset{asset("a.zip", []byte("x"))}}
	for name, bend := range map[string]func(g *fakeGitea){
		"signed by a stranger":          func(g *fakeGitea) { g.publish(t, stranger, Namespace, good, nil) },
		"signature for another purpose": func(g *fakeGitea) { g.publish(t, signer, binding.Namespace, good, nil) },
		"manifest changed after signing": func(g *fakeGitea) {
			g.publish(t, signer, Namespace, good, nil)
			g.files["manifest.json"] = []byte(strings.Replace(string(g.files["manifest.json"]), "v1.2.3", "v1.2.4", 1))
			g.tag = "v1.2.4"
		},
		"old signed manifest under a new tag": func(g *fakeGitea) { g.publish(t, signer, Namespace, good, nil); g.tag = "v9.9.9" },
		"no signature asset":                  func(g *fakeGitea) { g.publish(t, signer, Namespace, good, nil); delete(g.files, "manifest.json.sig") },
		"asset name with a path": func(g *fakeGitea) {
			m := good
			m.Assets = []Asset{{Name: "../../etc/cron.d/x", Kind: "app", OS: "darwin", Arch: "arm64", Size: 1, SHA256: strings.Repeat("0", 64)}}
			g.publish(t, signer, Namespace, m, nil)
		},
		"not a version": func(g *fakeGitea) { m := good; m.Version = "latest"; g.publish(t, signer, Namespace, m, nil) },
		"wrong type": func(g *fakeGitea) {
			m := good
			m.Type = "boundgate-signer-set"
			g.publish(t, signer, Namespace, m, nil)
		},
		"server says 403": func(g *fakeGitea) { g.publish(t, signer, Namespace, good, nil); g.status = 403 },
	} {
		g := newFakeGitea(t)
		bend(g)
		if _, err := (Source{BaseURL: g.srv.URL, Repo: "o/r"}).Latest(context.Background(), keys); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "server says 403" && !strings.Contains(err.Error(), "token_file") {
			t.Errorf("%s: unhelpful error: %v", name, err)
		}
	}
	g := newFakeGitea(t)
	g.publish(t, signer, Namespace, good, nil)
	if _, err := (Source{BaseURL: g.srv.URL, Repo: "o/r"}).Latest(context.Background(), nil); !errors.Is(err, ErrNoReleaseKeys) {
		t.Fatalf("no keys: %v", err)
	}
	if _, err := (Source{BaseURL: "http://updates.example", Repo: "o/r"}).Latest(context.Background(), keys); err == nil {
		t.Fatal("plain http source accepted")
	}
}

// The token belongs to the configured instance; asset links are the server's
// to choose and may point anywhere.
func TestTokenStaysHome(t *testing.T) {
	signer, keys := newKey(t)
	var leaked string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		w.Write([]byte("x"))
	}))
	defer elsewhere.Close()
	g := newFakeGitea(t)
	m := Manifest{Type: ManifestType, Version: "v1.0.0", Created: time.Now().UTC(), Assets: []Asset{asset("a.zip", []byte("x"))}}
	g.publish(t, signer, Namespace, m, nil)
	src := Source{BaseURL: g.srv.URL, Repo: "o/r", Token: "sekrit"}
	r, err := src.Latest(context.Background(), keys)
	if err != nil {
		t.Fatal(err)
	}
	r.urls["a.zip"] = elsewhere.URL + "/a.zip"
	if _, err := src.Download(context.Background(), r, m.Assets[0], t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if leaked != "" {
		t.Fatalf("the token went to another host: %q", leaked)
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		cur, cand string
		want      bool
	}{
		{"v1.2.3", "v1.2.4", true}, {"v1.2.3", "v1.3.0", true}, {"v1.9.9", "v2.0.0", true}, {"v1.2.9", "v1.2.10", true},
		{"v1.2.3", "v1.2.3", false}, {"v1.2.4", "v1.2.3", false}, {"v2.0.0", "v1.9.9", false},
		{"dev", "v9.9.9", false}, {"v1.2.3", "latest", false}, {"v1.2.3", "v1.2", false}, {"v1.2.3", "v01.2.4", false}, {"v1.2.3", "1.2.4", false},
	} {
		if got := Newer(c.cur, c.cand); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.cur, c.cand, got)
		}
	}
}

func TestBuiltinKeysParse(t *testing.T) {
	if _, err := BuiltinKeys(); err != nil && !errors.Is(err, ErrNoReleaseKeys) {
		t.Fatalf("release_keys does not parse: %v", err)
	}
}

// testdata is what the release pipeline's own tools produce: the manifest
// from deploy/release/manifest.sh (jq), the signature from `ssh-keygen -Y
// sign -n boundgate-release`. The updater must read exactly that.
func TestManifestFromReleaseTools(t *testing.T) {
	raw, _ := os.ReadFile("testdata/manifest.json")
	sig, _ := os.ReadFile("testdata/manifest.json.sig")
	pub, _ := os.ReadFile("testdata/release_key.pub")
	keys, err := Keys(pub)
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifyManifest(raw, string(sig), keys)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "v1.2.3" || m.Commit != "abc1234" || m.Image == nil || !strings.HasPrefix(m.Image.Digest, "sha256:") || m.Created.IsZero() {
		t.Fatalf("manifest: %+v", m)
	}
	if a, ok := m.Find("app", "darwin", "arm64"); !ok || a.Name != "BoundGate-1.2.3-macos.zip" || a.Size != 11 {
		t.Fatalf("app asset: %+v %v", a, ok)
	}
	if a, ok := m.Find("binaries", "linux", "amd64"); !ok || a.Size != 19 {
		t.Fatalf("linux asset: %+v %v", a, ok)
	}
	if _, ok := m.Find("binaries", "linux", "arm64"); ok {
		t.Fatal("found an asset the release does not have")
	}
	if _, err := VerifyManifest(append(raw, ' '), string(sig), keys); err == nil {
		t.Fatal("a manifest with one more byte verified")
	}
}

// update.sh reads its own copy of the release keys (it is used without a
// checkout of this package); the two files must not drift apart.
func TestReleaseKeyCopiesAgree(t *testing.T) {
	kit, err := os.ReadFile("../../deploy/prod/release_keys")
	if err != nil {
		t.Fatal(err)
	}
	if string(kit) != string(builtinKeys) {
		t.Fatal("deploy/prod/release_keys differs from internal/update/release_keys (make release-key keeps them equal)")
	}
}
