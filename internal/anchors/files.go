package anchors

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/safefile"
)

// The files, in the node's state directory.
const (
	PinFile     = "control.pin"
	TrustFile   = "admin_trust.json"
	HistoryFile = "bindings_seen.json"
)

// Names are the files as a list: what stays the privileged parent's when
// the state directory goes to its worker.
var Names = []string{PinFile, TrustFile, HistoryFile}

// Options say where the anchors are and whose.
type Options struct {
	Dir string
	// Pin, when set, is the control plane's key from the configuration
	// (hex SPKI hash): nothing is pinned on first use, nothing is stored.
	Pin string
	// Genesis, when set, is the hash the first admin key list must have.
	Genesis string
	// Owner is the user the files must belong to; -1 is this process's.
	// They are read only as that user's plain files with one name
	// (internal/safefile): in a directory someone else writes to, another
	// file under their name is refused, not read.
	Owner int
	// Shared: another user reads the files (the worker its parent's), so
	// they are written 0644 instead of 0600. None of them is a secret.
	Shared bool
	// ReadOnly: a view for reading; every change is refused.
	ReadOnly bool
}

// Files are the anchors as files. It is the one implementation of the
// rules; every other Anchors ends at one.
type Files struct {
	o   Options
	pin *devicekey.SPKIHash

	mu   sync.Mutex
	book Book // loaded at first use, then kept: this is its only writer
}

// Open checks the options; it reads nothing yet.
func Open(o Options) (*Files, error) {
	f := &Files{o: o}
	f.o.Genesis = strings.ToLower(strings.TrimSpace(o.Genesis))
	if o.Pin != "" {
		h, err := devicekey.ParseSPKIHash(o.Pin)
		if err != nil {
			return nil, fmt.Errorf("control.pin: %w", err)
		}
		f.pin = &h
	}
	if o.Shared && !o.ReadOnly {
		// files from before the reader was another user: 0600, which it
		// could not open
		for _, n := range Names {
			fi, err := os.Lstat(f.path(n))
			if err != nil || fi.Mode().Perm() == 0o644 {
				continue // not there; or what it is, is found when it is read
			}
			b, err := f.read(n, maxHistoryBytes)
			if err == nil {
				err = f.write(n, b)
			}
			if err != nil {
				return nil, fmt.Errorf("anchors: %w", err)
			}
		}
	}
	return f, nil
}

const (
	maxPinBytes     = 256
	maxTrustBytes   = 256 << 10
	maxHistoryBytes = 8 << 20
)

func (f *Files) path(name string) string { return filepath.Join(f.o.Dir, name) }

func (f *Files) read(name string, max int64) ([]byte, error) {
	return safefile.ReadOf(f.path(name), f.o.Owner, max)
}

func (f *Files) write(name string, b []byte) error {
	if f.o.ReadOnly {
		return ErrReadOnly
	}
	if err := os.MkdirAll(f.o.Dir, 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if f.o.Shared {
		mode = 0o644
	}
	return safefile.WriteAtomicMode(f.path(name), b, mode)
}

func (f *Files) writeJSON(name string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return f.write(name, raw)
}

// Pin implements Anchors.
func (f *Files) Pin() (devicekey.SPKIHash, bool, error) {
	if f.pin != nil {
		return *f.pin, true, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.storedPin()
}

func (f *Files) storedPin() (devicekey.SPKIHash, bool, error) {
	b, err := f.read(PinFile, maxPinBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return devicekey.SPKIHash{}, false, nil
	case err != nil:
		return devicekey.SPKIHash{}, false, fmt.Errorf("control plane pin: %w", err)
	}
	h, err := devicekey.ParseSPKIHash(string(b))
	if err != nil {
		return devicekey.SPKIHash{}, false, fmt.Errorf("%s is damaged (%v); refusing to pin a control plane again. Restore the file, or remove it as root and enroll", f.path(PinFile), err)
	}
	return h, true, nil
}

// SetPin implements Anchors.
func (f *Files) SetPin(h devicekey.SPKIHash) error {
	if f.pin != nil {
		return ErrProvisioned
	}
	if f.o.ReadOnly {
		return ErrReadOnly
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch cur, ok, err := f.storedPin(); {
	case err != nil:
		return err
	case ok && cur == h:
		return nil
	case ok:
		return ErrPinned
	}
	if err := f.write(PinFile, []byte(h.String()+"\n")); err != nil {
		return fmt.Errorf("store the control plane pin: %w", err)
	}
	return nil
}

// Trust implements Anchors. A missing file means nothing is pinned yet; an
// unreadable one is an error, never a reason to pin again.
func (f *Files) Trust() (binding.Trust, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.trust()
}

func (f *Files) trust() (binding.Trust, error) {
	var t binding.Trust
	raw, err := f.read(TrustFile, maxTrustBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if _, lerr := os.Lstat(f.path("admin_keys")); lerr == nil {
			return t, fmt.Errorf("node: %s holds admin keys pinned before the admin list was signed. Remove that file to pin the signed list on the next contact (compare the key fingerprints in `boundgatectl status` with your administrator's), or re-enroll", f.path("admin_keys"))
		}
		return t, nil
	case err != nil:
		return t, fmt.Errorf("node: admin trust: %w", err)
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return binding.Trust{}, fmt.Errorf("node: %s is damaged (%v); refusing to pin the admin keys again. Restore the file or re-enroll", f.path(TrustFile), err)
	}
	if _, err := t.Signers(); err != nil || !t.Pinned() || t.Version == 0 || t.Hash == "" {
		return binding.Trust{}, fmt.Errorf("node: %s is damaged; refusing to pin the admin keys again. Restore the file or re-enroll", f.path(TrustFile))
	}
	return t, nil
}

// Follow implements Anchors: the chain is verified against what is stored,
// and the result is on disk before it is returned.
func (f *Files) Follow(chain []binding.SignedSet) (binding.Trust, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, err := f.trust()
	if err != nil {
		return cur, err
	}
	next, err := binding.VerifyChain(cur, chain, f.o.Genesis)
	if err != nil {
		return cur, err
	}
	if next.Hash == cur.Hash && next.Genesis == cur.Genesis {
		return cur, nil
	}
	if err := f.writeJSON(TrustFile, next); err != nil {
		return cur, fmt.Errorf("store admin trust: %w", err) // not adopted: what is not on disk does not count
	}
	return next, nil
}

// History implements Anchors; the book returned is a copy.
func (f *Files) History() (Book, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.load(); err != nil {
		return nil, err
	}
	out := make(Book, len(f.book))
	for k, v := range f.book {
		out[k] = v
	}
	return out, nil
}

func (f *Files) load() error {
	if f.book != nil && !f.o.ReadOnly {
		return nil
	}
	book := Book{}
	raw, err := f.read(HistoryFile, maxHistoryBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("node: binding history: %w", err)
	default:
		if err := json.Unmarshal(raw, &book); err != nil {
			// an empty history would forget what the node could refuse: the
			// person who removes the file decides that, not a damaged file
			return fmt.Errorf("node: %s is damaged (%v); restore it, or remove it to start with an empty history (older bindings a control plane still holds would then be accepted again)", f.path(HistoryFile), err)
		}
		if len(book) > 2*MaxHistory {
			return fmt.Errorf("node: %s holds %d nodes; it is not this node's", f.path(HistoryFile), len(book))
		}
	}
	f.book = book
	return nil
}

// Record implements Anchors. All of the evidence must verify, or none of
// it is recorded.
func (f *Files) Record(ev []Evidence) error {
	if f.o.ReadOnly {
		return ErrReadOnly
	}
	if len(ev) > MaxEvidence {
		return fmt.Errorf("anchors: %d pieces of evidence at once", len(ev))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t, err := f.trust()
	if err != nil {
		return err
	}
	signers, err := t.Signers()
	if err != nil || len(signers) == 0 {
		return errors.New("anchors: no admin keys pinned: nothing can be proven yet")
	}
	if err := f.load(); err != nil {
		return err
	}
	var changes []change
	for i, e := range ev {
		switch {
		case e.Binding != "" && e.Revocation == "":
			b, err := binding.Parse([]byte(e.Binding))
			if err == nil {
				_, err = binding.Verify([]byte(e.Binding), e.Signature, signers)
			}
			if err == nil && t.Genesis != "" && b.Deployment != "" && b.Deployment != t.Genesis {
				err = binding.ErrOtherDeployment
			}
			if err != nil {
				return fmt.Errorf("anchors: evidence %d: %w", i+1, err)
			}
			changes = append(changes, change{id: b.NodeID, issued: b.Issued})
		case e.Revocation != "" && e.Binding == "":
			var g collect
			g.dep = t.Genesis
			if _, err := binding.VerifyRevocation(registry.SignedRevocation{Revocation: e.Revocation, Signature: e.Signature}, signers, &g); err != nil {
				return fmt.Errorf("anchors: evidence %d: %w", i+1, err)
			}
			changes = append(changes, g.changes...)
		default:
			return fmt.Errorf("anchors: evidence %d is neither a binding nor a revocation", i+1)
		}
	}
	changed := false
	for _, c := range changes {
		if c.revoked {
			changed = f.book.Revoke(c.id, c.issued) || changed
		} else {
			changed = f.book.Saw(c.id, c.issued) || changed
		}
	}
	if !changed {
		return nil
	}
	if err := f.writeJSON(HistoryFile, f.book); err != nil {
		f.book = nil // what is in memory is not what is on disk: read again
		return fmt.Errorf("store binding history: %w", err)
	}
	return nil
}

// change is what one piece of evidence proves.
type change struct {
	id      string
	issued  int64
	revoked bool
}

// collect is the guard binding.VerifyRevocation hands a verified revocation
// to: it notes it, Record applies it with the rest.
type collect struct {
	dep     string
	changes []change
}

func (c *collect) Deployment() string          { return c.dep }
func (c *collect) Check(binding.Binding) error { return nil }
func (c *collect) Saw(binding.Binding)         {}
func (c *collect) Revoke(r binding.Revocation) {
	c.changes = append(c.changes, change{id: r.NodeID, issued: r.Issued, revoked: true})
}
