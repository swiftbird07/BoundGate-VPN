package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

type adminKey struct{}

// AdminFrom returns the admin identity of a request.
func AdminFrom(ctx context.Context) (Admin, bool) {
	a, ok := ctx.Value(adminKey{}).(Admin)
	return a, ok
}

// AdminMux returns the admin API routes (wrapped in AdminAuth, see
// adminauth.go) plus the routes with their own authentication: the OIDC
// callback, the sign-token routes and the login entry points.
func (h *Handlers) AdminMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/admin/me", h.adminMe)
	mux.HandleFunc("POST /api/v1/admin/auth/logout", h.adminLogout)
	mux.HandleFunc("POST /api/v1/admin/auth/passkey/register/begin", h.passkeyRegisterBegin)
	mux.HandleFunc("POST /api/v1/admin/auth/passkey/register/finish", h.passkeyRegisterFinish)
	mux.HandleFunc("POST /api/v1/admin/auth/passkey/login/begin", h.passkeyLoginBegin)
	mux.HandleFunc("POST /api/v1/admin/auth/passkey/login/finish", h.passkeyLoginFinish)
	mux.HandleFunc("GET /api/v1/admin/passkeys", h.adminListPasskeys)
	mux.HandleFunc("POST /api/v1/admin/passkeys/{id}/approve", h.adminApprovePasskey)
	mux.HandleFunc("DELETE /api/v1/admin/passkeys/{id}", h.adminRevokePasskey)
	mux.HandleFunc("GET /api/v1/admin/tokens", h.adminListTokens)
	mux.HandleFunc("POST /api/v1/admin/tokens", h.adminCreateToken)
	mux.HandleFunc("DELETE /api/v1/admin/tokens/{id}", h.adminRevokeToken)
	mux.HandleFunc("GET /api/v1/admin/overview", h.adminOverview)
	mux.HandleFunc("GET /api/v1/admin/nodes", h.adminListNodes)
	mux.HandleFunc("GET /api/v1/admin/nodes/{id}", h.adminGetNode)
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/confirm", h.adminConfirmNode)
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/approve", h.adminConfirmNode) // alias
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/reject", h.adminRejectNode)
	mux.HandleFunc("PATCH /api/v1/admin/nodes/{id}", h.adminPatchNode)
	mux.HandleFunc("GET /api/v1/admin/tags", h.adminTags)
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", h.adminRevokeNode)
	mux.HandleFunc("GET /api/v1/admin/signers", h.adminListSigners)
	mux.HandleFunc("POST /api/v1/admin/signers", h.adminAddSigner)
	mux.HandleFunc("DELETE /api/v1/admin/signers/{id}", h.adminRevokeSigner)
	mux.HandleFunc("POST /api/v1/admin/signers/change", h.adminChangeSigners)
	mux.HandleFunc("GET /api/v1/admin/signers/set", h.adminSignerSet)
	mux.HandleFunc("GET /api/v1/admin/identity", h.adminIdentity)
	mux.HandleFunc("GET /api/v1/admin/settings/network", h.adminGetNetwork)
	mux.HandleFunc("PUT /api/v1/admin/settings/network", h.adminPutNetwork)
	mux.HandleFunc("GET /api/v1/admin/sessions", h.adminListSessions)
	mux.HandleFunc("DELETE /api/v1/admin/sessions/{id}", h.adminRevokeSession)
	mux.HandleFunc("GET /api/v1/admin/policies", h.adminListPolicies)
	mux.HandleFunc("POST /api/v1/admin/policies", h.adminCreatePolicy)
	mux.HandleFunc("POST /api/v1/admin/policies/validate", h.adminValidatePolicy)
	mux.HandleFunc("GET /api/v1/admin/policies/{id}", h.adminGetPolicy)
	mux.HandleFunc("PUT /api/v1/admin/policies/{id}", h.adminPutPolicy)
	mux.HandleFunc("DELETE /api/v1/admin/policies/{id}", h.adminDeletePolicy)
	mux.HandleFunc("POST /api/v1/admin/acl/evaluate", h.adminEvaluate)
	mux.HandleFunc("GET /api/v1/admin/tunnels", h.adminListTunnels)
	mux.HandleFunc("GET /api/v1/admin/flows", h.adminFlows)
	mux.HandleFunc("GET /api/v1/admin/snapshot", h.adminSnapshot)
	mux.HandleFunc("GET /api/v1/admin/logs", h.adminLogs)
	outer := http.NewServeMux()
	outer.HandleFunc("GET "+OIDCCallbackPath, h.oidcCallback)
	outer.HandleFunc("GET /api/v1/admin/auth/login", h.adminLoginStart)
	outer.HandleFunc("GET /api/v1/admin/auth/status", h.adminAuthStatus)
	outer.Handle("/api/v1/sign/", h.signMux())
	outer.Handle("/", h.AdminAuth(mux))
	return outer
}

// NodeView is the admin-facing node representation.
type NodeView struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Hostname          string            `json:"hostname,omitempty"`
	Platform          string            `json:"platform,omitempty"`
	KeyKind           string            `json:"key_kind,omitempty"`
	HardwareBound     bool              `json:"hardware_bound"`   // granted and signed
	HardwareClaimed   bool              `json:"hardware_claimed"` // reported by the node, unverified
	SPKI              string            `json:"spki"`
	Fingerprint       string            `json:"fingerprint"`
	Status            string            `json:"status"`
	Kind              registry.Kind     `json:"kind"`
	RequestedRoles    []registry.Role   `json:"requested_roles"`
	RequestedPrefixes []registry.Prefix `json:"requested_prefixes"`
	Roles             []registry.Role   `json:"roles"`
	Prefixes          []registry.Prefix `json:"prefixes"`
	OverlayIP         string            `json:"overlay_ip,omitempty"`
	PublicAddr        string            `json:"public_addr,omitempty"`
	Tags              []string          `json:"tags"` // the administrator's labels; part of the signed binding
	KeyVersion        int               `json:"key_version"`
	Signed            bool              `json:"signed"`
	SignedBy          string            `json:"signed_by,omitempty"`
	SignedAt          *time.Time        `json:"signed_at,omitempty"`
	RequestedAt       time.Time         `json:"requested_at"`
	RequestIP         string            `json:"request_ip,omitempty"`
	ConfirmedAt       *time.Time        `json:"confirmed_at,omitempty"`
	ConfirmedBy       string            `json:"confirmed_by,omitempty"`
	ApprovedAt        *time.Time        `json:"approved_at,omitempty"`
	ApprovedBy        string            `json:"approved_by,omitempty"`
	RevokedAt         *time.Time        `json:"revoked_at,omitempty"`
	RevokedBy         string            `json:"revoked_by,omitempty"`
	LastSeenAt        *time.Time        `json:"last_seen_at,omitempty"`
	SnapshotVersion   uint64            `json:"snapshot_version"`
	ActiveTunnels     int               `json:"active_tunnels"`
	Attrs             map[string]string `json:"attrs,omitempty"`
}

func nodeView(n db.Node) NodeView {
	v := NodeView{
		ID: n.ID, Name: n.Name, Hostname: n.Hostname, Platform: n.Platform, KeyKind: n.KeyKind,
		HardwareBound: n.HardwareBound, HardwareClaimed: n.HardwareClaimed, SPKI: n.SPKI.String(), Fingerprint: n.SPKI.Fingerprint(),
		Status: n.Status, Kind: n.Kind, RequestedRoles: orEmptyRoles(n.RequestedRoles), RequestedPrefixes: orEmptyPrefixes(n.RequestedPrefixes),
		Roles: orEmptyRoles(n.Roles), Prefixes: orEmptyPrefixes(n.Prefixes), PublicAddr: n.PublicAddr, Tags: append([]string{}, n.Tags...),
		RequestedAt: n.RequestedAt, RequestIP: n.RequestIP, ConfirmedBy: n.ConfirmedBy, ApprovedBy: n.ApprovedBy, RevokedBy: n.RevokedBy,
		SnapshotVersion: n.LastSnapshotVersion, ActiveTunnels: n.ActiveTunnels, Attrs: n.Attrs,
		KeyVersion: n.KeyVersion, Signed: n.Signature != "", SignedBy: n.SignedBy,
	}
	if n.OverlayIP.IsValid() {
		v.OverlayIP = n.OverlayIP.String()
	}
	if !n.SignedAt.IsZero() {
		v.SignedAt = &n.SignedAt
	}
	if !n.ConfirmedAt.IsZero() {
		v.ConfirmedAt = &n.ConfirmedAt
	}
	if !n.ApprovedAt.IsZero() {
		v.ApprovedAt = &n.ApprovedAt
	}
	if !n.RevokedAt.IsZero() {
		v.RevokedAt = &n.RevokedAt
	}
	if !n.LastSeenAt.IsZero() {
		v.LastSeenAt = &n.LastSeenAt
	}
	return v
}

func orEmptyRoles(r []registry.Role) []registry.Role {
	if r == nil {
		return []registry.Role{}
	}
	return r
}

func orEmptyPrefixes(p []registry.Prefix) []registry.Prefix {
	if p == nil {
		return []registry.Prefix{}
	}
	return p
}

func (h *Handlers) adminMe(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	a.SessionID = ""
	writeJSON(w, http.StatusOK, a)
}

func (h *Handlers) adminListNodes(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	switch state {
	case "", db.StatusPending, db.StatusConfirmed, db.StatusApproved, db.StatusRevoked:
	default:
		writeError(w, http.StatusBadRequest, "state must be pending, confirmed, approved or revoked")
		return
	}
	nodes, err := h.d.DB.ListNodes(r.Context(), state)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := make([]NodeView, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, nodeView(n))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) adminGetNode(w http.ResponseWriter, r *http.Request) {
	n, err := h.d.DB.NodeByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(n))
}

// GrantBody is what an admin decides for a node. Roles and prefixes are
// granted explicitly; nothing the node requested is taken over silently.
type GrantBody struct {
	// Fingerprint, when given, must match the node: the UI sends what the
	// admin confirmed so a stale page cannot approve a different request.
	Fingerprint string            `json:"fingerprint"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"` // interactive (needs a user login) | workload
	Roles       []string          `json:"roles"`
	Prefixes    []registry.Prefix `json:"prefixes"`
	OverlayIP   string            `json:"overlay_ip"`
	PublicAddr  string            `json:"public_addr"`
	// HardwareBound: omitted = what the node reported (confirm) or unchanged
	// (patch). False distrusts a reported hardware key; true without such a
	// report is refused.
	HardwareBound *bool `json:"hardware_bound"`
	// Tags: omitted = none (confirm) or unchanged (patch). Signed like roles:
	// changing them on an approved node asks for a new signature.
	Tags *[]string `json:"tags"`
}

func (b GrantBody) grant() (db.Grant, error) {
	g := db.Grant{Name: strings.TrimSpace(b.Name), Prefixes: b.Prefixes, PublicAddr: strings.TrimSpace(b.PublicAddr), HardwareBound: b.HardwareBound}
	if b.Kind != "" {
		k, err := registry.ParseKind(b.Kind)
		if err != nil {
			return g, err
		}
		g.Kind = k
	}
	if b.Roles != nil {
		roles, err := registry.ParseRoles(b.Roles)
		if err != nil {
			return g, err
		}
		g.Roles = roles
	}
	if b.Tags != nil {
		clean, err := db.CleanTags(*b.Tags)
		if err != nil {
			return g, errors.New(strings.TrimPrefix(err.Error(), db.ErrConflict.Error()+": "))
		}
		g.Tags = &clean
	}
	if b.OverlayIP != "" {
		ip, err := netip.ParseAddr(b.OverlayIP)
		if err != nil {
			return g, errors.New("overlay_ip: invalid address")
		}
		g.OverlayIP = ip
	}
	return g, nil
}

// ConfirmResponse is the node plus, when a signature is outstanding, the
// one-time token and the command the admin runs on the machine with the
// security key.
type ConfirmResponse struct {
	NodeView
	SignToken     string     `json:"sign_token,omitempty"`
	SignExpiresAt *time.Time `json:"sign_expires_at,omitempty"`
	SignCommand   string     `json:"sign_command,omitempty"`
}

// withSignToken mints a token for a confirmed node and fills the response.
func (h *Handlers) withSignToken(r *http.Request, a Admin, n db.Node) (ConfirmResponse, error) {
	out := ConfirmResponse{NodeView: nodeView(n)}
	if n.Status != db.StatusConfirmed {
		return out, nil
	}
	tok, exp, err := h.d.DB.CreateSignToken(r.Context(), n.ID, n.SPKI, a.Subject)
	if err != nil {
		return out, err
	}
	out.SignToken, out.SignExpiresAt = tok, &exp
	out.SignCommand = "boundgatectl admin sign --control https://" + r.Host + " --node " + n.ID + " --fingerprint " + n.SPKI.String() + " --token " + tok
	return out, nil
}

// adminConfirmNode records the grant after the admin compared the
// fingerprint and returns the one-time token for the signature step. On an
// already confirmed node without roles in the body it only issues a new
// token (the previous one expired).
func (h *Handlers) adminConfirmNode(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	var body GrantBody
	if r.ContentLength != 0 {
		if err := readJSON(r, &body, 64<<10); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
			return
		}
	}
	n, err := h.d.DB.NodeByID(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if body.Fingerprint != "" && strings.ReplaceAll(body.Fingerprint, " ", "") != n.SPKI.String() {
		writeError(w, http.StatusConflict, "fingerprint does not match this node")
		return
	}
	st, err := h.signerState(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if len(st.Keys) == 0 {
		writeError(w, http.StatusConflict, "no signed admin key list yet; add a signing key and sign the list first")
		return
	}
	g, err := body.grant()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(g.Roles) == 0 && n.Status == db.StatusConfirmed && len(n.Roles) > 0 {
		g.Roles, g.Prefixes = n.Roles, n.Prefixes // re-issue a token with the stored grant
		if !g.OverlayIP.IsValid() {
			g.OverlayIP = n.OverlayIP
		}
	}
	if len(g.Roles) == 0 {
		writeError(w, http.StatusBadRequest, "roles are required (the node requested: "+rolesString(n.RequestedRoles)+")")
		return
	}
	net, err := h.d.DB.Network(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if err := h.d.DB.ConfirmNode(r.Context(), id, a.Subject, g, net.Pool); err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	n, _ = h.d.DB.NodeByID(r.Context(), id)
	out, err := h.withSignToken(r, a, n)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, a.Subject, "node confirmed", id,
		map[string]any{"name": n.Name, "spki": n.SPKI.String(), "key_kind": n.KeyKind, "hardware_bound": n.HardwareBound,
			"kind": n.Kind, "roles": n.Roles, "prefixes": n.Prefixes, "overlay_ip": n.OverlayIP.String(), "public_addr": n.PublicAddr, "sign_token_expires": out.SignExpiresAt})
	writeJSON(w, http.StatusOK, out)
}

func rolesString(rs []registry.Role) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, string(r))
	}
	return strings.Join(parts, ", ")
}

func (h *Handlers) adminRejectNode(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	n, err := h.d.DB.NodeByID(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if err := h.d.DB.RejectNode(r.Context(), id); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, a.Subject, "enrollment rejected", id,
		map[string]any{"name": n.Name, "spki": n.SPKI.String()})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) adminPatchNode(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	var body GrantBody
	if err := readJSON(r, &body, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	g, err := body.grant()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	net, err := h.d.DB.Network(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	version, demoted, err := h.d.DB.UpdateNode(r.Context(), id, g, net.Pool)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	n, _ := h.d.DB.NodeByID(r.Context(), id)
	if n.Status == db.StatusApproved || demoted {
		h.d.Snap.Notify(version)
	}
	out := ConfirmResponse{NodeView: nodeView(n)}
	if demoted {
		// the signed content changed: the node left the snapshots and
		// needs a new signature
		if out, err = h.withSignToken(r, a, n); err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
	}
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "node updated", id,
		map[string]any{"name": n.Name, "roles": n.Roles, "prefixes": n.Prefixes, "overlay_ip": n.OverlayIP.String(), "public_addr": n.PublicAddr,
			"snapshot_version": version, "needs_signature": demoted})
	writeJSON(w, http.StatusOK, out)
}

// SignerView is an admin signing key as the API shows it.
type SignerView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Subject     string     `json:"subject"`
	PublicKey   string     `json:"public_key"`
	KeyType     string     `json:"key_type"`
	Hardware    bool       `json:"hardware"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	// Active: the key is in the signed list that nodes follow. A key that is
	// neither active nor revoked was registered before lists were signed.
	Active bool `json:"active"`
}

func signerView(s db.Signer) SignerView {
	v := SignerView{ID: s.ID, Name: s.Name, Subject: s.Subject, PublicKey: s.AuthorizedKey(), KeyType: s.KeyType, Hardware: s.Hardware, Fingerprint: s.Fingerprint, CreatedAt: s.CreatedAt}
	if !s.RevokedAt.IsZero() {
		v.RevokedAt = &s.RevokedAt
	}
	return v
}

func (h *Handlers) adminListSigners(w http.ResponseWriter, r *http.Request) {
	st, err := h.signerState(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	rows, err := h.d.DB.ListSigners(r.Context(), false)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := make([]SignerView, 0, len(rows))
	for _, s := range rows {
		v := signerView(s)
		v.Active = slices.Contains(st.Trust.Keys, s.PublicKey)
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// SignerBody names an admin key: an authorized_keys line (comment optional;
// sk-* types are the point, software keys are for development).
type SignerBody struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

// adminAddSigner and adminRevokeSigner do not change the list: they propose
// the next one (202) and return the command that signs it. See signersets.go.
func (h *Handlers) adminAddSigner(w http.ResponseWriter, r *http.Request) {
	var body SignerBody
	if err := readJSON(r, &body, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	h.proposeSigners(w, r, SignerChangeBody{Add: []SignerBody{body}})
}

func (h *Handlers) adminRevokeSigner(w http.ResponseWriter, r *http.Request) {
	h.proposeSigners(w, r, SignerChangeBody{Remove: []string{r.PathValue("id")}})
}

func (h *Handlers) adminRevokeNode(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	n, err := h.d.DB.NodeByID(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	version, err := h.d.DB.RevokeNode(r.Context(), id, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusConflict, "only approved nodes can be revoked; reject pending ones")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, a.Subject, "node revoked", id,
		map[string]any{"name": n.Name, "spki": n.SPKI.String(), "snapshot_version": version})
	w.WriteHeader(http.StatusNoContent)
}

// adminIdentity tells the admin the fingerprint of the node-channel key: what
// a device shows at its first contact (`boundgatectl enroll`, the app) and
// what its user compares before pinning it. The admin UI is the out-of-band
// source for that comparison.
func (h *Handlers) adminIdentity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"control_pin": h.d.ControlSPKI.Fingerprint(),
		"spki":        h.d.ControlSPKI.String(),
	})
}

func (h *Handlers) adminGetNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := h.d.DB.Network(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

// adminTags: what to offer where tags are edited.
func (h *Handlers) adminTags(w http.ResponseWriter, r *http.Request) {
	used, err := h.d.DB.UsedTags(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"defaults": db.DefaultTags, "used": used})
}

// adminPutNetwork stores the network settings. A pool that leaves nodes
// outside is refused, with the list of those nodes, unless the request says
// "renumber": true: then they move to the same host number in the new pool,
// and the approved ones need the administrator's signature again, because the
// overlay address is part of the signed binding.
func (h *Handlers) adminPutNetwork(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	var req struct {
		db.NetworkSettings
		Renumber bool `json:"renumber"`
	}
	if err := readJSON(r, &req, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	n := req.NetworkSettings
	if err := n.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	nodes, err := h.d.DB.ListNodes(r.Context(), "")
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	var outside []map[string]any
	for _, nd := range nodes {
		if (nd.Status == db.StatusApproved || nd.Status == db.StatusConfirmed) && nd.OverlayIP.IsValid() && !n.Pool.Contains(nd.OverlayIP) {
			outside = append(outside, map[string]any{"id": nd.ID, "name": nd.Name, "overlay_ip": nd.OverlayIP.String(), "status": nd.Status})
		}
	}
	if len(outside) > 0 && !req.Renumber {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":   fmt.Sprintf("%d node(s) have an overlay address outside %s. With \"renumber\" they move to the same host number in the new pool; approved nodes then need your signature again", len(outside), n.Pool),
			"outside": outside})
		return
	}
	version, moved, err := h.d.DB.RenumberNetwork(r.Context(), n, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "network settings changed", "",
		map[string]any{"pool": n.Pool.String(), "max_age_seconds": n.MaxAgeSeconds, "snapshot_version": version, "renumbered": moved})
	writeJSON(w, http.StatusOK, map[string]any{"pool": n.Pool, "max_age_seconds": n.MaxAgeSeconds, "renumbered": moved})
}

// adminSnapshot returns the global view, or the view of one node with
// ?node=<id>.
func (h *Handlers) adminSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := h.d.Snap.BuildFor(r.Context(), transport.DeviceID(r.URL.Query().Get("node")))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (h *Handlers) adminLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lq := db.LogQuery{Stream: q.Get("stream"), DeviceID: q.Get("node"), Actor: q.Get("actor"), Text: q.Get("q")}
	if lq.DeviceID == "" {
		lq.DeviceID = q.Get("device")
	}
	if v := q.Get("before"); v != "" {
		lq.Before, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("limit"); v != "" {
		lq.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("from"); v != "" {
		lq.Since, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("to"); v != "" {
		lq.Until, _ = time.Parse(time.RFC3339, v)
	}
	evs, err := h.d.DB.ListLogs(r.Context(), lq)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if evs == nil {
		evs = []db.LogEvent{}
	}
	writeJSON(w, http.StatusOK, evs)
}
