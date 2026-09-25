package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// The signing step: an admin confirmed a node in the UI and received a
// one-time token; on the machine with the security key, `boundgatectl admin
// sign` fetches the canonical binding with that token, signs it (ssh-agent
// or key file) and posts the SSHSIG back. The control plane verifies it
// against the registered admin keys and only then approves the node.
//
// These routes are served on the admin server name (TLS for browsers and
// CLIs) but authenticate with the sign token, not the admin session.

// SignBinding is what the CLI receives for a token.
type SignBinding struct {
	NodeID      string            `json:"node_id"`
	Name        string            `json:"name"`
	Fingerprint string            `json:"fingerprint"`
	KeyKind     string            `json:"key_kind"`
	Hardware    bool              `json:"hardware_bound"`
	Roles       []registry.Role   `json:"roles"`
	Prefixes    []registry.Prefix `json:"prefixes"`
	OverlayIP   string            `json:"overlay_ip"`
	PublicAddr  string            `json:"public_addr,omitempty"`
	// Binding is the exact canonical JSON to sign.
	Binding string `json:"binding"`
	// Revocation, instead of Binding, is the canonical JSON of a revoked
	// node's revocation (binding.Revocation) to sign.
	Revocation string    `json:"revocation,omitempty"`
	Namespace  string    `json:"namespace"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Signers lists the accepted admin keys (authorized_keys lines) so the
	// CLI can pick the matching agent key.
	Signers []string `json:"signers"`
}

// SignatureBody is what the CLI posts back.
type SignatureBody struct {
	Signature string `json:"signature"`
}

func (h *Handlers) signMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/sign/binding", h.signGetBinding)
	mux.HandleFunc("POST /api/v1/sign/signature", h.signPostSignature)
	mux.HandleFunc("GET /api/v1/sign/signers", h.signGetSigners)
	mux.HandleFunc("POST /api/v1/sign/signers", h.signPostSigners)
	return mux
}

// signToken authenticates the request by its one-time token; it writes the
// response on failure.
func (h *Handlers) signToken(w http.ResponseWriter, r *http.Request) (db.SignToken, string, bool) {
	ip := remoteIP(r)
	if !h.signLimit.allowClient(ip) {
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return db.SignToken{}, "", false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "sign token required")
		return db.SignToken{}, "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	t, err := h.d.DB.LookupSignToken(r.Context(), token)
	switch {
	case errors.Is(err, db.ErrTokenUsed):
		writeError(w, http.StatusConflict, "sign token already used; confirm the node again for a new one")
	case errors.Is(err, db.ErrTokenExpired):
		writeError(w, http.StatusUnauthorized, "sign token expired; confirm the node again for a new one")
	case errors.Is(err, db.ErrNotFound):
		h.d.Logs.AdminAuth.Warn("sign token rejected", "src", ip)
		writeError(w, http.StatusUnauthorized, "unknown sign token")
	case err != nil:
		fail(w, err, h.d.Logs.System)
	default:
		return t, token, true
	}
	return db.SignToken{}, "", false
}

// statement is what a sign token asks the admin to sign: the binding of a
// confirmed node, or the revocation of a revoked one.
type statement struct {
	n          db.Node
	raw        []byte
	revocation bool
	st         signerState
}

func (s statement) namespace() string {
	if s.revocation {
		return binding.RevocationNamespace
	}
	return binding.Namespace
}

// currentStatement loads the node behind a token and builds what it must
// be signed for, with the same key it had when the token was made. Both
// name the network (the genesis hash of the admin key list) and carry the
// token's time as issued: that is what lets a node refuse, later, whatever
// was signed before (binding.Guard).
func (h *Handlers) currentStatement(w http.ResponseWriter, r *http.Request, t db.SignToken) (statement, bool) {
	var out statement
	n, err := h.d.DB.NodeByID(r.Context(), t.NodeID)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return out, false
	}
	out.n = n
	if out.st, err = h.signerState(r.Context()); err != nil {
		fail(w, err, h.d.Logs.System)
		return out, false
	}
	if n.SPKI != t.SPKI {
		writeError(w, http.StatusConflict, "the node has another key than when this token was made; nothing to sign")
		return out, false
	}
	switch n.Status {
	case db.StatusConfirmed:
		b := binding.FromNode(nodeToRegistry(n))
		b.Deployment, b.Issued = out.st.Trust.Genesis, t.CreatedAt.Unix()
		out.raw, err = b.Canonical()
	case db.StatusRevoked:
		out.revocation = true
		out.raw, err = binding.Revocation{Type: binding.RevocationType, NodeID: n.ID, SPKI: n.SPKI, Deployment: out.st.Trust.Genesis, Issued: t.CreatedAt.Unix()}.Canonical()
	default:
		writeError(w, http.StatusConflict, "node is "+n.Status+"; nothing to sign")
		return out, false
	}
	if err != nil {
		writeError(w, http.StatusConflict, "grant is incomplete: "+err.Error())
		return out, false
	}
	return out, true
}

func nodeToRegistry(n db.Node) registry.Node {
	return registry.Node{ID: transport.DeviceID(n.ID), Name: n.Name, SPKI: n.SPKI, KeyVersion: n.KeyVersion, Kind: n.Kind, Roles: n.Roles, Prefixes: n.Prefixes, OverlayIP: n.OverlayIP, HardwareBound: n.HardwareBound, Tags: n.Tags}
}

func (h *Handlers) signGetBinding(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.signToken(w, r)
	if !ok {
		return
	}
	sm, ok := h.currentStatement(w, r, t)
	if !ok {
		return
	}
	n := sm.n
	out := SignBinding{
		NodeID: n.ID, Name: n.Name, Fingerprint: n.SPKI.Fingerprint(), KeyKind: n.KeyKind, Hardware: n.HardwareBound,
		Roles: orEmptyRoles(n.Roles), Prefixes: orEmptyPrefixes(n.Prefixes), PublicAddr: n.PublicAddr,
		Namespace: sm.namespace(), ExpiresAt: t.ExpiresAt, Signers: []string{},
	}
	if sm.revocation {
		out.Revocation = string(sm.raw)
	} else {
		out.Binding, out.OverlayIP = string(sm.raw), n.OverlayIP.String()
	}
	for _, s := range sm.st.Rows {
		out.Signers = append(out.Signers, s.AuthorizedKey())
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) signPostSignature(w http.ResponseWriter, r *http.Request) {
	t, token, ok := h.signToken(w, r)
	if !ok {
		return
	}
	var body SignatureBody
	if err := readJSON(r, &body, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	sm, ok := h.currentStatement(w, r, t)
	if !ok {
		return
	}
	n, raw, rows, keys := sm.n, sm.raw, sm.st.Rows, sm.st.Keys
	var pub ssh.PublicKey
	var err error
	if sm.revocation {
		pub, err = h.verifyRevocation(raw, body.Signature, keys)
	} else {
		pub, err = binding.Verify(raw, body.Signature, keys)
	}
	if err != nil {
		h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, t.Admin, "binding signature rejected", n.ID,
			map[string]any{"name": n.Name, "spki": n.SPKI.String(), "reason": err.Error(), "src": remoteIP(r)})
		switch {
		case errors.Is(err, binding.ErrUnknownSigner):
			writeError(w, http.StatusForbidden, "signed by a key that is not a registered admin key")
		case errors.Is(err, binding.ErrBadSignature):
			writeError(w, http.StatusConflict, "signature does not verify for the current grant; fetch the binding again")
		default:
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	fp := ssh.FingerprintSHA256(pub)
	signerName := fp
	for _, s := range rows {
		if s.Fingerprint == fp {
			signerName = s.Name
		}
	}
	if sm.revocation {
		version, err := h.d.DB.StoreRevocation(r.Context(), n.ID, token, string(raw), body.Signature, fp)
		if err != nil {
			if errors.Is(err, db.ErrTokenUsed) {
				writeError(w, http.StatusConflict, "sign token already used")
				return
			}
			fail(w, err, h.d.Logs.System)
			return
		}
		h.d.Snap.Notify(version)
		h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, t.Admin, "node revocation signed", n.ID,
			map[string]any{"name": n.Name, "spki": n.SPKI.String(), "signed_by": fp, "signer": signerName,
				"signer_hardware": binding.IsHardwareKey(pub), "snapshot_version": version})
		nv := nodeView(n)
		nv.RevocationSigned = true
		writeJSON(w, http.StatusOK, nv)
		return
	}
	version, err := h.d.DB.ApproveSigned(r.Context(), n.ID, token, string(raw), body.Signature, fp)
	if err != nil {
		if errors.Is(err, db.ErrTokenUsed) {
			writeError(w, http.StatusConflict, "sign token already used")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	n, _ = h.d.DB.NodeByID(r.Context(), n.ID)
	h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, t.Admin, "node approved", n.ID,
		map[string]any{"name": n.Name, "spki": n.SPKI.String(), "key_kind": n.KeyKind, "hardware_bound": n.HardwareBound,
			"roles": n.Roles, "prefixes": n.Prefixes, "overlay_ip": n.OverlayIP.String(), "public_addr": n.PublicAddr,
			"signed_by": fp, "signer": signerName, "signer_hardware": binding.IsHardwareKey(pub), "snapshot_version": version})
	writeJSON(w, http.StatusOK, nodeView(n))
}

// verifyRevocation checks an admin's signature over a revocation.
func (h *Handlers) verifyRevocation(raw []byte, sig string, keys binding.Signers) (ssh.PublicKey, error) {
	if strings.TrimSpace(sig) == "" {
		return nil, binding.ErrNoSignature
	}
	parsed, err := binding.ParseSSHSIG(sig)
	if err != nil {
		return nil, err
	}
	if _, err := binding.VerifyRevocation(registry.SignedRevocation{Revocation: string(raw), Signature: sig}, keys, nil); err != nil {
		return nil, err
	}
	return parsed.PublicKey, nil
}
