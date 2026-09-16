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
	Binding   string    `json:"binding"`
	Namespace string    `json:"namespace"`
	ExpiresAt time.Time `json:"expires_at"`
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
	return mux
}

// signToken authenticates the request by its one-time token; it writes the
// response on failure.
func (h *Handlers) signToken(w http.ResponseWriter, r *http.Request) (db.SignToken, string, bool) {
	ip := remoteIP(r)
	if !h.signLimit.allow(ip) {
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

// currentBinding loads the node behind a token and builds the binding it
// must be signed for. The node must still be confirmed with the same key.
func (h *Handlers) currentBinding(w http.ResponseWriter, r *http.Request, t db.SignToken) (db.Node, []byte, bool) {
	n, err := h.d.DB.NodeByID(r.Context(), t.NodeID)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return n, nil, false
	}
	if n.Status != db.StatusConfirmed || n.SPKI != t.SPKI {
		writeError(w, http.StatusConflict, "node is "+n.Status+"; nothing to sign")
		return n, nil, false
	}
	raw, err := binding.FromNode(nodeToRegistry(n)).Canonical()
	if err != nil {
		writeError(w, http.StatusConflict, "grant is incomplete: "+err.Error())
		return n, nil, false
	}
	return n, raw, true
}

func nodeToRegistry(n db.Node) registry.Node {
	return registry.Node{ID: transport.DeviceID(n.ID), Name: n.Name, SPKI: n.SPKI, KeyVersion: n.KeyVersion, Kind: n.Kind, Roles: n.Roles, Prefixes: n.Prefixes, OverlayIP: n.OverlayIP}
}

func (h *Handlers) activeSigners(r *http.Request) ([]db.Signer, binding.Signers, error) {
	rows, err := h.d.DB.ListSigners(r.Context(), true)
	if err != nil {
		return nil, nil, err
	}
	var lines []string
	for _, s := range rows {
		lines = append(lines, s.AuthorizedKey())
	}
	keys, err := binding.ParseSigners([]byte(strings.Join(lines, "\n")))
	return rows, keys, err
}

func (h *Handlers) signGetBinding(w http.ResponseWriter, r *http.Request) {
	t, _, ok := h.signToken(w, r)
	if !ok {
		return
	}
	n, raw, ok := h.currentBinding(w, r, t)
	if !ok {
		return
	}
	rows, _, err := h.activeSigners(r)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := SignBinding{
		NodeID: n.ID, Name: n.Name, Fingerprint: n.SPKI.Fingerprint(), KeyKind: n.KeyKind, Hardware: n.HardwareBound,
		Roles: orEmptyRoles(n.Roles), Prefixes: orEmptyPrefixes(n.Prefixes), OverlayIP: n.OverlayIP.String(), PublicAddr: n.PublicAddr,
		Binding: string(raw), Namespace: binding.Namespace, ExpiresAt: t.ExpiresAt, Signers: []string{},
	}
	for _, s := range rows {
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
	n, raw, ok := h.currentBinding(w, r, t)
	if !ok {
		return
	}
	rows, keys, err := h.activeSigners(r)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	pub, err := binding.Verify(raw, body.Signature, keys)
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
