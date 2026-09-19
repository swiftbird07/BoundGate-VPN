package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
)

// trustStore holds the admin key list this node accepts and follows the
// signed chain of its changes (binding.VerifyChain). The list is pinned on
// first contact (or checked against a provisioned genesis hash) and from
// then on only moves along links signed by a key of the current list. It is
// written to disk before it is used, so a restart never falls back.
type trustStore struct {
	path    string
	genesis string // provisioned hash of the genesis set; "" = trust on first use

	mu  sync.Mutex
	cur binding.Trust
}

// loadTrust reads the stored trust. A missing file means nothing is pinned
// yet; an unreadable one is an error, never a reason to pin again.
func loadTrust(stateDir, genesis string) (*trustStore, error) {
	ts := &trustStore{path: filepath.Join(stateDir, "admin_trust.json"), genesis: genesis}
	raw, err := os.ReadFile(ts.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if _, lerr := os.Stat(filepath.Join(stateDir, "admin_keys")); lerr == nil {
			return nil, fmt.Errorf("node: %s holds admin keys pinned before the admin list was signed. Remove that file to pin the signed list on the next contact (compare the key fingerprints in `boundgatectl status` with your administrator's), or re-enroll", filepath.Join(stateDir, "admin_keys"))
		}
		return ts, nil
	case err != nil:
		return nil, fmt.Errorf("node: admin trust: %w", err)
	}
	if err := json.Unmarshal(raw, &ts.cur); err != nil {
		return nil, fmt.Errorf("node: %s is damaged (%v); refusing to pin the admin keys again. Restore the file or re-enroll", ts.path, err)
	}
	if _, err := ts.cur.Signers(); err != nil || !ts.cur.Pinned() || ts.cur.Version == 0 || ts.cur.Hash == "" {
		return nil, fmt.Errorf("node: %s is damaged; refusing to pin the admin keys again. Restore the file or re-enroll", ts.path)
	}
	return ts, nil
}

func (ts *trustStore) current() binding.Trust {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.cur
}

func (ts *trustStore) signers() binding.Signers {
	s, _ := ts.current().Signers()
	return s
}

// apply verifies chain against the current trust and adopts the result.
// It reports whether trust moved and whether this was the first pin.
func (ts *trustStore) apply(chain []binding.SignedSet) (moved, first bool, err error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	next, err := binding.VerifyChain(ts.cur, chain, ts.genesis)
	if err != nil {
		return false, false, err
	}
	if next.Hash == ts.cur.Hash {
		return false, false, nil
	}
	if err := writeFileAtomic(ts.path, next); err != nil {
		return false, false, fmt.Errorf("store admin trust: %w", err) // not adopted: what is not on disk does not count
	}
	first = !ts.cur.Pinned()
	ts.cur = next
	return true, first, nil
}

func writeFileAtomic(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".admin_trust-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}
