// Package update finds and verifies releases. A release is a Gitea release
// whose assets include manifest.json and manifest.json.sig: the manifest
// names every other asset with its SHA-256 (and the container image by
// digest), the signature is an SSHSIG by a release key that is compiled into
// this build. The server that offers the download is not trusted with
// anything but availability: what it serves either matches a signed manifest
// or is refused, and a manifest that is not newer than this build is ignored.
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// Namespace separates release signatures from every other use of a key.
const Namespace = "boundgate-release"

// ManifestType is the "type" field of a manifest.
const ManifestType = "boundgate-release"

//go:embed release_keys
var builtinKeys []byte

var (
	// ErrNoReleaseKeys: this build has no release key and cannot verify updates.
	ErrNoReleaseKeys = errors.New("update: this build has no release signing key built in; updates cannot be verified")
	// ErrNotSigned: the release has no manifest or signature asset.
	ErrNotSigned = errors.New("update: the release has no signed manifest")
)

// Manifest is the signed description of a release.
type Manifest struct {
	Type    string    `json:"type"`
	Version string    `json:"version"`
	Commit  string    `json:"commit,omitempty"`
	Created time.Time `json:"created"`
	// Image is the container image of this release, by digest.
	Image  *Image  `json:"image,omitempty"`
	Assets []Asset `json:"assets"`
}

// Image names the release's container image; Digest pins it.
type Image struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// Asset is one downloadable file of a release.
type Asset struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"` // "app" (macOS bundle, zip) or "binaries" (tar.gz)
	OS     string `json:"os"`
	Arch   string `json:"arch"` // "amd64", "arm64" or "universal"
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Find returns the asset of a kind for a platform.
func (m *Manifest) Find(kind, goos, goarch string) (Asset, bool) {
	for _, a := range m.Assets {
		if a.Kind == kind && a.OS == goos && (a.Arch == goarch || a.Arch == "universal") {
			return a, true
		}
	}
	return Asset{}, false
}

// Keys parses release keys (authorized_keys lines, # comments).
func Keys(text []byte) (binding.Signers, error) {
	var lines [][]byte
	for _, l := range bytes.Split(text, []byte("\n")) {
		if l = bytes.TrimSpace(l); len(l) > 0 && l[0] != '#' {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return nil, ErrNoReleaseKeys
	}
	return binding.ParseSigners(bytes.Join(lines, []byte("\n")))
}

// BuiltinKeys are the release keys compiled into this build.
func BuiltinKeys() (binding.Signers, error) { return Keys(builtinKeys) }

// VerifyManifest checks the signature over the exact manifest bytes and then
// reads them. Nothing of an unverified manifest is returned.
func VerifyManifest(raw []byte, armoredSig string, keys binding.Signers) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, ErrNoReleaseKeys
	}
	sig, err := binding.ParseSSHSIG(armoredSig)
	if err != nil {
		return nil, fmt.Errorf("update: manifest signature: %w", err)
	}
	if sig.Namespace != Namespace {
		return nil, fmt.Errorf("update: manifest signature is for namespace %q", sig.Namespace)
	}
	if err := binding.CheckSignerType(sig.PublicKey); err != nil {
		return nil, fmt.Errorf("update: manifest signature: %w", err)
	}
	if !keys.Contains(sig.PublicKey) {
		return nil, errors.New("update: the manifest is signed by a key that is not a release key of this build")
	}
	if err := sig.Verify(raw); err != nil {
		return nil, fmt.Errorf("update: manifest signature does not verify: %w", err)
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("update: manifest: %w", err)
	}
	if m.Type != ManifestType {
		return nil, fmt.Errorf("update: manifest type %q", m.Type)
	}
	if _, err := parseVersion(m.Version); err != nil {
		return nil, err
	}
	for _, a := range m.Assets {
		if a.Name == "" || a.Name != filepath.Base(a.Name) || strings.HasPrefix(a.Name, ".") {
			return nil, fmt.Errorf("update: manifest names an asset %q", a.Name)
		}
		if b, err := hex.DecodeString(a.SHA256); err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("update: asset %s has no SHA-256", a.Name)
		}
		if a.Size <= 0 {
			return nil, fmt.Errorf("update: asset %s has no size", a.Name)
		}
	}
	return &m, nil
}

// parseVersion reads vMAJOR.MINOR.PATCH.
func parseVersion(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if !strings.HasPrefix(v, "v") || len(parts) != 3 {
		return out, fmt.Errorf("update: version %q is not vMAJOR.MINOR.PATCH", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strconv.Itoa(n) != p {
			return out, fmt.Errorf("update: version %q is not vMAJOR.MINOR.PATCH", v)
		}
		out[i] = n
	}
	return out, nil
}

// Newer reports whether candidate is a later release than current. A build
// that is not a release ("dev") is never older than anything: it does not
// update itself.
func Newer(current, candidate string) bool {
	c, err := parseVersion(current)
	if err != nil {
		return false
	}
	n, err := parseVersion(candidate)
	if err != nil {
		return false
	}
	for i := range c {
		if n[i] != c[i] {
			return n[i] > c[i]
		}
	}
	return false
}

// Source is where releases are looked up: a Gitea instance and repository.
type Source struct {
	// BaseURL of the Gitea instance, e.g. https://gitlab.net407.com
	BaseURL string
	// Repo is owner/name.
	Repo string
	// Token is an optional access token (read), for instances that do not
	// serve anonymous visitors.
	Token string
	HTTP  *http.Client
}

// Release is a verified release and where its assets are.
type Release struct {
	Manifest *Manifest
	PageURL  string
	urls     map[string]string // asset name -> download URL
}

const (
	maxManifest = 1 << 20
	maxAsset    = 512 << 20
)

type giteaRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (s Source) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (s Source) get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	base, err := url.Parse(s.BaseURL)
	if err != nil || base.Scheme != "https" && base.Hostname() != "127.0.0.1" && base.Hostname() != "localhost" {
		return nil, fmt.Errorf("update: source %q must be an https URL", s.BaseURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// the token goes to the configured instance only, never to where a
	// release's asset links may point
	if s.Token != "" && u.Host == base.Host && u.Scheme == base.Scheme {
		req.Header.Set("Authorization", "token "+s.Token)
	}
	rsp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		if rsp.StatusCode == http.StatusUnauthorized || rsp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("update: %s answers %s (the instance wants a signed-in user: configure update.token_file)", u.Host, rsp.Status)
		}
		return nil, fmt.Errorf("update: %s: %s", u.Path, rsp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(rsp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("update: %s is larger than %d bytes", u.Path, limit)
	}
	return b, nil
}

// Latest returns the latest release, verified against keys.
func (s Source) Latest(ctx context.Context, keys binding.Signers) (*Release, error) {
	if len(keys) == 0 {
		return nil, ErrNoReleaseKeys
	}
	api := strings.TrimRight(s.BaseURL, "/") + "/api/v1/repos/" + s.Repo + "/releases/latest"
	raw, err := s.get(ctx, api, maxManifest)
	if err != nil {
		return nil, err
	}
	var gr giteaRelease
	if err := json.Unmarshal(raw, &gr); err != nil {
		return nil, fmt.Errorf("update: release list: %w", err)
	}
	urls := map[string]string{}
	for _, a := range gr.Assets {
		urls[a.Name] = a.URL
	}
	if urls["manifest.json"] == "" || urls["manifest.json.sig"] == "" {
		return nil, fmt.Errorf("%w (%s)", ErrNotSigned, gr.TagName)
	}
	manifest, err := s.get(ctx, urls["manifest.json"], maxManifest)
	if err != nil {
		return nil, err
	}
	sig, err := s.get(ctx, urls["manifest.json.sig"], maxManifest)
	if err != nil {
		return nil, err
	}
	m, err := VerifyManifest(manifest, string(sig), keys)
	if err != nil {
		return nil, err
	}
	// The tag is the server's claim, the manifest is the signer's: a signed
	// manifest of an old release offered under a new tag is not that release.
	if m.Version != gr.TagName {
		return nil, fmt.Errorf("update: release %s carries the manifest of %s", gr.TagName, m.Version)
	}
	return &Release{Manifest: m, PageURL: gr.HTMLURL, urls: urls}, nil
}

// Download fetches an asset of the release into dir and returns its path. The
// file only exists under its name once size and SHA-256 match the manifest.
func (s Source) Download(ctx context.Context, r *Release, a Asset, dir string) (string, error) {
	link := r.urls[a.Name]
	if link == "" {
		return "", fmt.Errorf("update: the release does not offer %s", a.Name)
	}
	if a.Size > maxAsset {
		return "", fmt.Errorf("update: %s is larger than %d bytes", a.Name, maxAsset)
	}
	b, err := s.get(ctx, link, a.Size)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	if int64(len(b)) != a.Size || hex.EncodeToString(sum[:]) != strings.ToLower(a.SHA256) {
		return "", fmt.Errorf("update: %s does not match the signed manifest (size or SHA-256)", a.Name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, a.Name)
	tmp := path + ".part"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return path, nil
}
