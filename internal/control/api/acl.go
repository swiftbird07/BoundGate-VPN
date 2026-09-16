package api

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/acl"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/netparse"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// PolicyView is the admin-facing policy.
type PolicyView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Cedar       string    `json:"cedar"`
	Enabled     bool      `json:"enabled"`
	Scope       []string  `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

func policyView(p db.Policy) PolicyView {
	return PolicyView{ID: p.ID, Name: p.Name, Description: p.Description, Cedar: p.Cedar, Enabled: p.Enabled, Scope: p.Scope,
		CreatedAt: p.CreatedAt, CreatedBy: p.CreatedBy, UpdatedAt: p.UpdatedAt, UpdatedBy: p.UpdatedBy}
}

// PolicyBody creates or replaces a policy. Enabled defaults to true.
type PolicyBody struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Cedar       string   `json:"cedar"`
	Enabled     *bool    `json:"enabled"`
	Scope       []string `json:"scope"`
}

func (h *Handlers) readPolicy(w http.ResponseWriter, r *http.Request) (db.Policy, bool) {
	var body PolicyBody
	if err := readJSON(r, &body, 128<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return db.Policy{}, false
	}
	p := db.Policy{Name: clip(body.Name, 64), Description: clip(body.Description, 512), Cedar: body.Cedar, Enabled: true, Scope: []string{}}
	if body.Enabled != nil {
		p.Enabled = *body.Enabled
	}
	if p.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return db.Policy{}, false
	}
	if err := acl.Validate(p.Cedar); err != nil {
		writeError(w, http.StatusBadRequest, "cedar: "+err.Error())
		return db.Policy{}, false
	}
	for _, id := range body.Scope {
		if _, err := h.d.DB.NodeByID(r.Context(), id); err != nil {
			writeError(w, http.StatusBadRequest, "scope: unknown node "+id)
			return db.Policy{}, false
		}
		p.Scope = append(p.Scope, id)
	}
	return p, true
}

func (h *Handlers) adminListPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := h.d.DB.ListPolicies(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := make([]PolicyView, 0, len(ps))
	for _, p := range ps {
		out = append(out, policyView(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) adminGetPolicy(w http.ResponseWriter, r *http.Request) {
	p, err := h.d.DB.PolicyByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, policyView(p))
}

func (h *Handlers) adminCreatePolicy(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	p, ok := h.readPolicy(w, r)
	if !ok {
		return
	}
	p, version, err := h.d.DB.CreatePolicy(r.Context(), p, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, "a policy with that name exists")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "policy created", "", map[string]any{"policy": p.ID, "name": p.Name, "enabled": p.Enabled, "scope": p.Scope})
	writeJSON(w, http.StatusCreated, policyView(p))
}

func (h *Handlers) adminPutPolicy(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	p, ok := h.readPolicy(w, r)
	if !ok {
		return
	}
	p.ID = r.PathValue("id")
	version, err := h.d.DB.UpdatePolicy(r.Context(), p, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, "a policy with that name exists")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "policy updated", "", map[string]any{"policy": p.ID, "name": p.Name, "enabled": p.Enabled, "scope": p.Scope})
	p, _ = h.d.DB.PolicyByID(r.Context(), p.ID)
	writeJSON(w, http.StatusOK, policyView(p))
}

func (h *Handlers) adminDeletePolicy(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	p, err := h.d.DB.PolicyByID(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	version, err := h.d.DB.DeletePolicy(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "policy deleted", "", map[string]any{"policy": id, "name": p.Name})
	w.WriteHeader(http.StatusNoContent)
}

// ValidateResponse is the answer of POST /policies/validate.
type ValidateResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (h *Handlers) adminValidatePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Cedar string `json:"cedar"`
	}
	if err := readJSON(r, &body, 128<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := acl.Validate(body.Cedar); err != nil {
		writeJSON(w, http.StatusOK, ValidateResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ValidateResponse{OK: true})
}

// EvaluateBody is a dry run: would node reach dst?
type EvaluateBody struct {
	// Node is the originating node (id or name).
	Node string `json:"node"`
	Dst  string `json:"dst"`
	Port int    `json:"port"`
	// Proto is tcp, udp, icmp or a protocol number (default tcp).
	Proto   string `json:"proto"`
	SNI     string `json:"sni"`
	DNSName string `json:"dns_name"`
	// Enforcer is the node whose policy view is used (id or name); empty
	// means every enabled policy.
	Enforcer string `json:"enforcer"`
}

// EvaluateResponse is the decision with its reasons.
type EvaluateResponse struct {
	Allow        bool     `json:"allow"`
	Policies     []string `json:"policies"`
	Reasons      []string `json:"reasons"`
	Errors       []string `json:"errors,omitempty"`
	PolicyCount  int      `json:"policy_count"`
	PolicyErrors []string `json:"policy_errors,omitempty"`
	Principal    string   `json:"principal"`
	User         string   `json:"user,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	Owner        string   `json:"owner,omitempty"`
	OwnerName    string   `json:"owner_name,omitempty"`
}

func (h *Handlers) resolveNode(r *http.Request, ref string) (db.Node, bool) {
	if ref == "" {
		return db.Node{}, false
	}
	if n, err := h.d.DB.NodeByID(r.Context(), ref); err == nil {
		return n, true
	}
	nodes, err := h.d.DB.ListNodes(r.Context(), "")
	if err != nil {
		return db.Node{}, false
	}
	// prefer a live node with that name; the most recently enrolled revoked
	// one still resolves so its history (tunnels, flows) can be queried
	var revoked *db.Node
	for i, n := range nodes {
		if n.Name != ref {
			continue
		}
		if n.Status != db.StatusRevoked {
			return n, true
		}
		if revoked == nil || n.RequestedAt.After(revoked.RequestedAt) {
			revoked = &nodes[i]
		}
	}
	if revoked != nil {
		return *revoked, true
	}
	return db.Node{}, false
}

func (h *Handlers) adminEvaluate(w http.ResponseWriter, r *http.Request) {
	var body EvaluateBody
	if err := readJSON(r, &body, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	src, ok := h.resolveNode(r, body.Node)
	if !ok {
		writeError(w, http.StatusBadRequest, "node: unknown node")
		return
	}
	dst, err := netip.ParseAddr(body.Dst)
	if err != nil || !dst.Is4() {
		writeError(w, http.StatusBadRequest, "dst must be an IPv4 address")
		return
	}
	if body.Port < 0 || body.Port > 65535 {
		writeError(w, http.StatusBadRequest, "port out of range")
		return
	}
	var proto uint8
	switch strings.ToLower(body.Proto) {
	case "", "tcp":
		proto = netparse.ProtoTCP
	case "udp":
		proto = netparse.ProtoUDP
	case "icmp":
		proto = netparse.ProtoICMP
	default:
		n, err := strconv.Atoi(body.Proto)
		if err != nil || n < 0 || n > 255 {
			writeError(w, http.StatusBadRequest, "proto must be tcp, udp, icmp or a number")
			return
		}
		proto = uint8(n)
	}
	var enforcer transport.DeviceID
	if body.Enforcer != "" {
		n, ok := h.resolveNode(r, body.Enforcer)
		if !ok {
			writeError(w, http.StatusBadRequest, "enforcer: unknown node")
			return
		}
		enforcer = transport.DeviceID(n.ID)
	}
	snap, err := h.d.Snap.BuildFor(r.Context(), enforcer)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	eng := acl.New(snap)
	d := eng.Evaluate(acl.Request{Principal: transport.DeviceID(src.ID), Dst: dst, Port: uint16(body.Port), Proto: proto, SNI: clip(body.SNI, 253), DNSName: clip(body.DNSName, 253)})
	out := EvaluateResponse{Allow: d.Allow, Policies: orEmpty(d.Policies), Reasons: orEmpty(d.Reasons), Errors: d.Errors, PolicyCount: eng.Policies(), Principal: src.ID}
	for _, pe := range eng.Errors() {
		out.PolicyErrors = append(out.PolicyErrors, pe.Error())
	}
	if d.Session != nil {
		out.User, out.Groups = d.Session.Subject, d.Session.Groups
	}
	if d.Owner != nil {
		out.Owner, out.OwnerName = string(d.Owner.ID), d.Owner.Name
	}
	writeJSON(w, http.StatusOK, out)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// policyNames is a helper for logs: id -> name.
func policyNames(ps []registry.Policy) map[string]string {
	m := make(map[string]string, len(ps))
	for _, p := range ps {
		m[p.ID] = p.Name
	}
	return m
}
