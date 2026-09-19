package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
)

// The admin key list is a signed chain (internal/binding/signerset.go). The
// control plane cannot change it: an administrator proposes the next list in
// the UI, `boundgatectl admin sign-signers` signs it with a key of the
// current list, and only a set that package binding verifies is stored and
// forwarded. Which keys may sign bindings is read from the verified head of
// that chain, never from the admin_signers directory, so editing the
// database grants nothing here, and nothing on any node.

// signerState is the verified chain head plus the directory rows of its keys.
type signerState struct {
	Trust binding.Trust
	Chain []db.SignerSetRow
	Keys  binding.Signers // keys of the head set
	Rows  []db.Signer     // directory rows of those keys
}

// signerState loads and verifies the stored chain. A chain that does not
// verify is an error: the control plane then neither signs nor distributes.
func (h *Handlers) signerState(ctx context.Context) (signerState, error) {
	var st signerState
	chain, err := h.d.DB.SignerChain(ctx)
	if err != nil {
		return st, err
	}
	st.Chain = chain
	links := make([]binding.SignedSet, 0, len(chain))
	for _, c := range chain {
		links = append(links, binding.SignedSet{Set: c.Set, Signature: c.Signature})
	}
	if st.Trust, err = binding.VerifyChain(binding.Trust{}, links, ""); err != nil {
		return st, errors.New("the stored admin key chain does not verify (database damaged or manipulated): " + err.Error())
	}
	if st.Keys, err = st.Trust.Signers(); err != nil {
		return st, err
	}
	dir, err := h.d.DB.ListSigners(ctx, false)
	if err != nil {
		return st, err
	}
	for _, s := range dir {
		if slices.Contains(st.Trust.Keys, s.PublicKey) {
			st.Rows = append(st.Rows, s)
		}
	}
	return st, nil
}

// SignerSetView describes the signed list and its history.
type SignerSetView struct {
	Version uint64 `json:"version"` // 0: no list has been signed yet
	Hash    string `json:"hash,omitempty"`
	// GenesisHash is what nodes can be provisioned with (control.signers_genesis).
	GenesisHash string            `json:"genesis_hash,omitempty"`
	History     []SignerSetChange `json:"history"`
}

// SignerSetChange is one link of the chain, as a diff.
type SignerSetChange struct {
	Version   uint64    `json:"version"`
	Hash      string    `json:"hash"`
	SignedBy  string    `json:"signed_by"`
	Admin     string    `json:"admin"`
	CreatedAt time.Time `json:"created_at"`
	Added     []string  `json:"added"`   // fingerprints
	Removed   []string  `json:"removed"` // fingerprints
}

func keyFingerprints(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err == nil {
			out = append(out, ssh.FingerprintSHA256(pub))
		}
	}
	return out
}

func diffKeys(prev, next []string) (added, removed []string) {
	for _, k := range next {
		if !slices.Contains(prev, k) {
			added = append(added, k)
		}
	}
	for _, k := range prev {
		if !slices.Contains(next, k) {
			removed = append(removed, k)
		}
	}
	return added, removed
}

func (h *Handlers) adminSignerSet(w http.ResponseWriter, r *http.Request) {
	st, err := h.signerState(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := SignerSetView{Version: st.Trust.Version, Hash: st.Trust.Hash, History: []SignerSetChange{}}
	var prev []string
	for i, c := range st.Chain {
		if i == 0 {
			out.GenesisHash = c.Hash
		}
		set, err := binding.ParseSignerSet([]byte(c.Set))
		if err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
		added, removed := diffKeys(prev, set.Keys)
		out.History = append(out.History, SignerSetChange{Version: c.Version, Hash: c.Hash, SignedBy: c.SignedBy, Admin: c.Admin, CreatedAt: c.CreatedAt,
			Added: keyFingerprints(added), Removed: keyFingerprints(removed)})
		prev = set.Keys
	}
	writeJSON(w, http.StatusOK, out)
}

// SignerChangeBody proposes the next list: keys to add (authorized_keys
// lines) and directory ids to remove, in one signature. With neither, and
// no signed list yet, it proposes the registered keys as the first list.
type SignerChangeBody struct {
	Add    []SignerBody `json:"add"`
	Remove []string     `json:"remove"`
}

// SignerChangeView is a proposal waiting for its signature.
type SignerChangeView struct {
	Version uint64       `json:"version"`
	Keys    []SignerView `json:"keys"`    // the proposed list
	Added   []string     `json:"added"`   // fingerprints
	Removed []string     `json:"removed"` // fingerprints
	// AffectedNodes are approved nodes whose binding was signed by a key
	// this change removes: they go back to "confirmed" and need a new
	// signature. Re-sign them with another key first to avoid the gap.
	AffectedNodes []NodeRef `json:"affected_nodes"`
	// SignableBy lists who can sign this change: the keys of the current
	// list (for the first list: the proposed keys themselves).
	SignableBy  []string  `json:"signable_by"`
	SignToken   string    `json:"sign_token"`
	SignCommand string    `json:"sign_command"`
	ExpiresAt   time.Time `json:"sign_expires_at"`
}

// NodeRef names a node.
type NodeRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func metaOf(s db.Signer) db.SignerKeyMeta {
	return db.SignerKeyMeta{PublicKey: s.PublicKey, Name: s.Name, Subject: s.Subject, KeyType: s.KeyType, Hardware: s.Hardware, Fingerprint: s.Fingerprint}
}

// proposeSigners builds, stores and describes the next set.
func (h *Handlers) proposeSigners(w http.ResponseWriter, r *http.Request, body SignerChangeBody) {
	a, _ := AdminFrom(r.Context())
	st, err := h.signerState(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	base := st.Rows
	if st.Trust.Version == 0 {
		// no signed list yet: keys registered before signed lists existed
		if base, err = h.d.DB.ListSigners(r.Context(), true); err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
	}
	var next []db.SignerKeyMeta
	var removedFP []string
	for _, s := range base {
		if slices.Contains(body.Remove, s.ID) {
			removedFP = append(removedFP, s.Fingerprint)
			continue
		}
		next = append(next, metaOf(s))
	}
	if len(removedFP) != len(body.Remove) {
		writeError(w, http.StatusNotFound, "remove: not a key of the current list")
		return
	}
	var addedFP []string
	for _, add := range body.Add {
		pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(add.PublicKey)))
		if err != nil {
			writeError(w, http.StatusBadRequest, "public_key: not an OpenSSH public key")
			return
		}
		if err := binding.CheckSignerType(pub); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ks := binding.KeyString(pub)
		if slices.ContainsFunc(next, func(m db.SignerKeyMeta) bool { return m.PublicKey == ks }) {
			writeError(w, http.StatusConflict, "this key is already in the list")
			return
		}
		name := strings.TrimSpace(add.Name)
		if name == "" {
			name = comment
		}
		fp := ssh.FingerprintSHA256(pub)
		next = append(next, db.SignerKeyMeta{PublicKey: ks, Name: clip(name, 64), Subject: a.Subject, KeyType: pub.Type(), Hardware: binding.IsHardwareKey(pub), Fingerprint: fp})
		addedFP = append(addedFP, fp)
	}
	if len(next) == 0 {
		writeError(w, http.StatusConflict, "the admin key list can never become empty: add a key in the same change")
		return
	}
	if st.Trust.Version > 0 && len(addedFP) == 0 && len(removedFP) == 0 {
		writeError(w, http.StatusBadRequest, "nothing to change")
		return
	}
	var keys binding.Signers
	for _, m := range next {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.PublicKey))
		if err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
		keys = append(keys, pub)
	}
	var prev *binding.Trust
	if st.Trust.Version > 0 {
		prev = &st.Trust
	}
	set, err := binding.NewSignerSet(prev, keys)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, err := set.Canonical()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, expires, err := h.d.DB.CreateSignerChange(r.Context(), string(raw), next, a.Subject)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := SignerChangeView{Version: set.Version, Keys: []SignerView{}, Added: orEmpty(addedFP), Removed: orEmpty(removedFP), AffectedNodes: []NodeRef{},
		SignableBy: []string{}, SignToken: token, ExpiresAt: expires,
		SignCommand: "boundgatectl admin sign-signers --control https://" + r.Host + " --token " + token}
	for _, m := range next {
		out.Keys = append(out.Keys, SignerView{Name: m.Name, Subject: m.Subject, PublicKey: m.PublicKey, KeyType: m.KeyType, Hardware: m.Hardware, Fingerprint: m.Fingerprint})
	}
	signable := st.Rows
	if prev == nil {
		for _, m := range next {
			out.SignableBy = append(out.SignableBy, m.Name+" "+m.Fingerprint)
		}
	}
	for _, s := range signable {
		out.SignableBy = append(out.SignableBy, s.Name+" "+s.Fingerprint)
	}
	if affected, err := h.d.DB.NodesSignedBy(r.Context(), removedFP); err == nil {
		for _, n := range affected {
			out.AffectedNodes = append(out.AffectedNodes, NodeRef{ID: n.ID, Name: n.Name})
		}
	}
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "admin key list change proposed", "",
		map[string]any{"version": set.Version, "added": addedFP, "removed": removedFP, "affected_nodes": len(out.AffectedNodes)})
	writeJSON(w, http.StatusAccepted, out)
}

func (h *Handlers) adminChangeSigners(w http.ResponseWriter, r *http.Request) {
	var body SignerChangeBody
	if r.ContentLength != 0 {
		if err := readJSON(r, &body, 64<<10); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
			return
		}
	}
	h.proposeSigners(w, r, body)
}

// --- the signing step (one-time token, no admin session) ---

// SignSigners is what the CLI receives for a signer-change token.
type SignSigners struct {
	// Set is the exact canonical JSON to sign.
	Set       string    `json:"set"`
	Namespace string    `json:"namespace"`
	ExpiresAt time.Time `json:"expires_at"`
	// Chain is the current signed chain: the CLI verifies that Set continues
	// it and shows the difference, without trusting any other field.
	Chain []binding.SignedSet `json:"chain"`
	// Names maps key strings to directory names, for display only.
	Names map[string]string `json:"names"`
}

func (h *Handlers) signerChangeToken(w http.ResponseWriter, r *http.Request) (db.SignerChange, string, bool) {
	ip := remoteIP(r)
	if !h.signLimit.allow(ip) {
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return db.SignerChange{}, "", false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "sign token required")
		return db.SignerChange{}, "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	c, err := h.d.DB.LookupSignerChange(r.Context(), token)
	switch {
	case errors.Is(err, db.ErrTokenUsed):
		writeError(w, http.StatusConflict, "sign token already used; propose the change again")
	case errors.Is(err, db.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "sign token expired; propose the change again")
	case errors.Is(err, db.ErrNotFound):
		h.d.Logs.AdminAuth.Warn("signer change token rejected", "src", ip)
		writeError(w, http.StatusUnauthorized, "unknown sign token")
	case err != nil:
		fail(w, err, h.d.Logs.System)
	default:
		return c, token, true
	}
	return db.SignerChange{}, "", false
}

func (h *Handlers) signGetSigners(w http.ResponseWriter, r *http.Request) {
	c, _, ok := h.signerChangeToken(w, r)
	if !ok {
		return
	}
	st, err := h.signerState(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := SignSigners{Set: c.Set, Namespace: binding.SignersNamespace, ExpiresAt: c.ExpiresAt, Chain: []binding.SignedSet{}, Names: map[string]string{}}
	for _, l := range st.Chain {
		out.Chain = append(out.Chain, binding.SignedSet{Set: l.Set, Signature: l.Signature})
	}
	for _, s := range st.Rows {
		out.Names[s.PublicKey] = s.Name
	}
	for _, m := range c.Keys {
		out.Names[m.PublicKey] = m.Name
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) signPostSigners(w http.ResponseWriter, r *http.Request) {
	c, token, ok := h.signerChangeToken(w, r)
	if !ok {
		return
	}
	var body SignatureBody
	if err := readJSON(r, &body, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	st, err := h.signerState(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	// The same verifier the nodes use decides: the stored chain plus the
	// proposed link must verify from its genesis, and end exactly one
	// version after the current head.
	links := make([]binding.SignedSet, 0, len(st.Chain)+1)
	for _, l := range st.Chain {
		links = append(links, binding.SignedSet{Set: l.Set, Signature: l.Signature})
	}
	links = append(links, binding.SignedSet{Set: c.Set, Signature: body.Signature})
	next, err := binding.VerifyChain(binding.Trust{}, links, "")
	if err == nil && (next.Version != st.Trust.Version+1 || next.Hash != binding.HashSet([]byte(c.Set))) {
		err = binding.ErrSetSequence
	}
	if err != nil {
		h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, c.Admin, "admin key list signature rejected", "",
			map[string]any{"reason": err.Error(), "src": remoteIP(r)})
		switch {
		case errors.Is(err, binding.ErrSetSigner):
			writeError(w, http.StatusForbidden, "not signed by a key of the current admin key list")
		case errors.Is(err, binding.ErrSetSequence), errors.Is(err, binding.ErrSetFork):
			writeError(w, http.StatusConflict, "the admin key list changed in the meantime; propose the change again")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	sig, err := binding.ParseSSHSIG(body.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	fp := ssh.FingerprintSHA256(sig.PublicKey)
	version, demoted, err := h.d.DB.ApplySignerSet(r.Context(), token,
		db.SignerSetRow{Version: next.Version, Set: c.Set, Signature: body.Signature, Hash: next.Hash, SignedBy: fp, Admin: c.Admin}, c.Keys)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrTokenUsed):
			writeError(w, http.StatusConflict, "sign token already used")
		case errors.Is(err, db.ErrConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			fail(w, err, h.d.Logs.System)
		}
		return
	}
	h.d.Snap.Notify(version)
	added, removed := diffKeys(st.Trust.Keys, next.Keys)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, c.Admin, "admin key list changed", "",
		map[string]any{"version": next.Version, "hash": next.Hash, "signed_by": fp, "added": keyFingerprints(added), "removed": keyFingerprints(removed),
			"demoted_nodes": demoted, "snapshot_version": version, "src": remoteIP(r)})
	writeJSON(w, http.StatusOK, map[string]any{"version": next.Version, "hash": next.Hash, "signed_by": fp,
		"keys": keyFingerprints(next.Keys), "demoted_nodes": orEmpty(demoted)})
}
