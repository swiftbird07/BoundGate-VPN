package api

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/binding"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Admin identity as established by the auth middleware.
type Admin struct {
	Subject string // "bootstrap" for the bootstrap token
	Email   string
}

type adminKey struct{}

// AdminFrom returns the admin identity of a request.
func AdminFrom(ctx context.Context) (Admin, bool) {
	a, ok := ctx.Value(adminKey{}).(Admin)
	return a, ok
}

// AdminAuth authenticates admin requests. M1: the bootstrap token as a
// bearer token. M4 adds cookie sessions (OIDC + passkey); the bootstrap
// token stays as the break-glass path.
func (h *Handlers) AdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			ok, err := h.d.DB.CheckBootstrapToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
			if err != nil {
				fail(w, err, h.d.Logs.System)
				return
			}
			if ok {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminKey{}, Admin{Subject: "bootstrap"})))
				return
			}
			h.d.Logs.AdminAuth.Warn("admin auth failed", "src", remoteIP(r), "reason", "bad bootstrap token")
		}
		writeError(w, http.StatusUnauthorized, "admin authentication required")
	})
}

// AdminMux returns the admin API routes (wrapped in AdminAuth) plus the
// sign-token routes (their own auth, see sign.go).
func (h *Handlers) AdminMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/admin/me", h.adminMe)
	mux.HandleFunc("GET /api/v1/admin/nodes", h.adminListNodes)
	mux.HandleFunc("GET /api/v1/admin/nodes/{id}", h.adminGetNode)
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/confirm", h.adminConfirmNode)
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/approve", h.adminConfirmNode) // alias
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/reject", h.adminRejectNode)
	mux.HandleFunc("PATCH /api/v1/admin/nodes/{id}", h.adminPatchNode)
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", h.adminRevokeNode)
	mux.HandleFunc("GET /api/v1/admin/signers", h.adminListSigners)
	mux.HandleFunc("POST /api/v1/admin/signers", h.adminAddSigner)
	mux.HandleFunc("DELETE /api/v1/admin/signers/{id}", h.adminRevokeSigner)
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
	outer.HandleFunc("GET /api/v1/oidc/callback", h.oidcCallback)
	outer.Handle("/api/v1/sign/", h.signMux())
	outer.Handle("/", h.AdminAuth(mux))
	return outer
}

// NodeView is the admin-facing node representation.
type NodeView struct {
	ID                string              `json:"id"`
	Name              string              `json:"name"`
	Hostname          string              `json:"hostname,omitempty"`
	Platform          string              `json:"platform,omitempty"`
	KeyKind           string              `json:"key_kind,omitempty"`
	HardwareBound     bool                `json:"hardware_bound"`
	SPKI              string              `json:"spki"`
	Fingerprint       string              `json:"fingerprint"`
	Status            string              `json:"status"`
	Kind              registry.Kind       `json:"kind"`
	RequestedRoles    []registry.Role     `json:"requested_roles"`
	RequestedPrefixes []registry.Prefix   `json:"requested_prefixes"`
	Roles             []registry.Role     `json:"roles"`
	Prefixes          []registry.Prefix   `json:"prefixes"`
	OverlayIP         string              `json:"overlay_ip,omitempty"`
	PublicAddr        string              `json:"public_addr,omitempty"`
	KeyVersion        int                 `json:"key_version"`
	Signed            bool                `json:"signed"`
	SignedBy          string              `json:"signed_by,omitempty"`
	SignedAt          *time.Time          `json:"signed_at,omitempty"`
	RequestedAt       time.Time           `json:"requested_at"`
	RequestIP         string              `json:"request_ip,omitempty"`
	ConfirmedAt       *time.Time          `json:"confirmed_at,omitempty"`
	ConfirmedBy       string              `json:"confirmed_by,omitempty"`
	ApprovedAt        *time.Time          `json:"approved_at,omitempty"`
	ApprovedBy        string              `json:"approved_by,omitempty"`
	RevokedAt         *time.Time          `json:"revoked_at,omitempty"`
	RevokedBy         string              `json:"revoked_by,omitempty"`
	LastSeenAt        *time.Time          `json:"last_seen_at,omitempty"`
	SnapshotVersion   uint64              `json:"snapshot_version"`
	ActiveTunnels     int                 `json:"active_tunnels"`
	Attrs             map[string]string   `json:"attrs,omitempty"`
}

func nodeView(n db.Node) NodeView {
	v := NodeView{
		ID: n.ID, Name: n.Name, Hostname: n.Hostname, Platform: n.Platform, KeyKind: n.KeyKind,
		HardwareBound: n.HardwareBound, SPKI: n.SPKI.String(), Fingerprint: n.SPKI.Fingerprint(),
		Status: n.Status, Kind: n.Kind, RequestedRoles: orEmptyRoles(n.RequestedRoles), RequestedPrefixes: orEmptyPrefixes(n.RequestedPrefixes),
		Roles: orEmptyRoles(n.Roles), Prefixes: orEmptyPrefixes(n.Prefixes), PublicAddr: n.PublicAddr,
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
}

func (b GrantBody) grant() (db.Grant, error) {
	g := db.Grant{Name: strings.TrimSpace(b.Name), Prefixes: b.Prefixes, PublicAddr: strings.TrimSpace(b.PublicAddr)}
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
	signers, err := h.d.DB.ListSigners(r.Context(), true)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if len(signers) == 0 {
		writeError(w, http.StatusConflict, "no admin signing key registered; add one under /api/v1/admin/signers first")
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
}

func signerView(s db.Signer) SignerView {
	v := SignerView{ID: s.ID, Name: s.Name, Subject: s.Subject, PublicKey: s.AuthorizedKey(), KeyType: s.KeyType, Hardware: s.Hardware, Fingerprint: s.Fingerprint, CreatedAt: s.CreatedAt}
	if !s.RevokedAt.IsZero() {
		v.RevokedAt = &s.RevokedAt
	}
	return v
}

func (h *Handlers) adminListSigners(w http.ResponseWriter, r *http.Request) {
	rows, err := h.d.DB.ListSigners(r.Context(), false)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := make([]SignerView, 0, len(rows))
	for _, s := range rows {
		out = append(out, signerView(s))
	}
	writeJSON(w, http.StatusOK, out)
}

// SignerBody registers an admin key: an authorized_keys line (comment
// optional; sk-* types are the point, software keys are for development).
type SignerBody struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

func (h *Handlers) adminAddSigner(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	var body SignerBody
	if err := readJSON(r, &body, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(body.PublicKey)))
	if err != nil {
		writeError(w, http.StatusBadRequest, "public_key: not an OpenSSH public key")
		return
	}
	if err := binding.CheckSignerType(pub); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = comment
	}
	s, err := h.d.DB.AddSigner(r.Context(), db.Signer{
		Subject: a.Subject, Name: clip(name, 64), PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))),
		KeyType: pub.Type(), Hardware: binding.IsHardwareKey(pub), Fingerprint: ssh.FingerprintSHA256(pub),
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, "this key is already registered")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "admin signing key added", "",
		map[string]any{"signer": s.ID, "name": s.Name, "key_type": s.KeyType, "hardware": s.Hardware, "fingerprint": s.Fingerprint})
	writeJSON(w, http.StatusCreated, signerView(s))
}

func (h *Handlers) adminRevokeSigner(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	s, err := h.d.DB.SignerByID(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if err := h.d.DB.RevokeSigner(r.Context(), id); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "admin signing key revoked", "",
		map[string]any{"signer": s.ID, "name": s.Name, "fingerprint": s.Fingerprint})
	w.WriteHeader(http.StatusNoContent)
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

func (h *Handlers) adminGetNetwork(w http.ResponseWriter, r *http.Request) {
	n, err := h.d.DB.Network(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (h *Handlers) adminPutNetwork(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	var n db.NetworkSettings
	if err := readJSON(r, &n, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if err := n.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// every assigned overlay address must still fit the pool
	nodes, err := h.d.DB.ApprovedNodes(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	for _, nd := range nodes {
		if nd.OverlayIP.IsValid() && !n.Pool.Contains(nd.OverlayIP) {
			writeError(w, http.StatusConflict, "node "+nd.Name+" has overlay ip "+nd.OverlayIP.String()+" outside the new pool")
			return
		}
	}
	version, err := h.d.DB.PutSetting(r.Context(), db.SettingNetwork, n, a.Subject, true)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "network settings changed", "",
		map[string]any{"pool": n.Pool.String(), "max_age_seconds": n.MaxAgeSeconds, "snapshot_version": version})
	writeJSON(w, http.StatusOK, n)
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
