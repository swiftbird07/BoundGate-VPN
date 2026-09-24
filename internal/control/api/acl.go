package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/acl"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/listsource"
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
	Group       string    `json:"group,omitempty"`
	Scope       []string  `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

func policyView(p db.Policy) PolicyView {
	return PolicyView{ID: p.ID, Name: p.Name, Description: p.Description, Cedar: p.Cedar, Enabled: p.Enabled, Group: p.Group, Scope: p.Scope,
		CreatedAt: p.CreatedAt, CreatedBy: p.CreatedBy, UpdatedAt: p.UpdatedAt, UpdatedBy: p.UpdatedBy}
}

// PolicyBody creates or replaces a policy. Enabled defaults to true.
type PolicyBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Cedar       string `json:"cedar"`
	Enabled     *bool  `json:"enabled"`
	// Group is a label for the admin UI; it does not affect evaluation.
	Group string   `json:"group"`
	Scope []string `json:"scope"`
}

func (h *Handlers) readPolicy(w http.ResponseWriter, r *http.Request) (db.Policy, bool) {
	var body PolicyBody
	if err := readJSON(r, &body, 128<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return db.Policy{}, false
	}
	p := db.Policy{Name: clip(body.Name, 64), Description: clip(body.Description, 512), Cedar: body.Cedar, Enabled: true, Group: clip(body.Group, 64), Scope: []string{}}
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
	if missing := h.unknownLists(r, p.Cedar); missing != "" {
		writeError(w, http.StatusBadRequest, "no list named "+missing+" (Lists)")
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
	// Draft is an unsaved policy from the editor: it replaces the stored
	// policy with the same id (or is added) before evaluating. DraftOnly
	// evaluates the draft alone.
	Draft     *DraftPolicy `json:"draft,omitempty"`
	DraftOnly bool         `json:"draft_only"`
}

// DraftPolicy is an unsaved policy for a dry run.
type DraftPolicy struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Cedar string `json:"cedar"`
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
	if body.Draft != nil {
		if err := acl.Validate(body.Draft.Cedar); err != nil {
			writeError(w, http.StatusBadRequest, "draft: "+err.Error())
			return
		}
		draft := registry.Policy{ID: body.Draft.ID, Name: body.Draft.Name, Cedar: body.Draft.Cedar}
		if draft.ID == "" {
			draft.ID = "draft"
		}
		if draft.Name == "" {
			draft.Name = "(draft)"
		}
		var kept []registry.Policy
		if !body.DraftOnly {
			for _, p := range snap.Policies {
				if p.ID != draft.ID {
					kept = append(kept, p)
				}
			}
		}
		snap.Policies = append(kept, draft)
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

// ---- lists ----------------------------------------------------------------

// ListView is the admin-facing list.
type ListView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	Description string    `json:"description,omitempty"`
	Entries     []string  `json:"entries"`
	UsedBy      []string  `json:"used_by"` // policy names
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	// a source the list follows (docs/ACL.md); the secret is never sent
	SourceURL       string     `json:"source_url,omitempty"`
	SourceInterval  int        `json:"source_interval,omitempty"` // seconds
	SourceHeader    string     `json:"source_header,omitempty"`
	SourceSecretSet bool       `json:"source_secret_set,omitempty"`
	SourceFetchedAt *time.Time `json:"source_fetched_at,omitempty"`
	SourceStatus    string     `json:"source_status,omitempty"` // empty: the last fetch worked
}

// ListBody creates or replaces a list. Entries: one address, prefix or
// name each; blank lines and # comments are dropped. With a source_url the
// control plane fetches the entries itself every source_interval seconds
// and what is sent as entries is only the starting point. source_secret is
// write-only: absent keeps what is stored, "" clears it.
type ListBody struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	Description    string   `json:"description"`
	Entries        []string `json:"entries"`
	SourceURL      string   `json:"source_url"`
	SourceInterval int      `json:"source_interval"`
	SourceHeader   string   `json:"source_header"`
	SourceSecret   *string  `json:"source_secret"`
}

var listRefRe = regexp.MustCompile(`BoundGate::List::"([^"]*)"`)

// unknownLists returns the first list a policy names that does not exist.
func (h *Handlers) unknownLists(r *http.Request, cedar string) string {
	refs := listRefRe.FindAllStringSubmatch(cedar, -1)
	if len(refs) == 0 {
		return ""
	}
	lists, err := h.d.DB.Lists(r.Context())
	if err != nil {
		return ""
	}
	known := map[string]bool{}
	for _, l := range lists {
		known[l.Name] = true
	}
	for _, m := range refs {
		if !known[m[1]] {
			return m[1]
		}
	}
	return ""
}

func (h *Handlers) listView(r *http.Request, l db.List, policies []db.Policy) ListView {
	v := ListView{ID: l.ID, Name: l.Name, Kind: l.Kind, Description: l.Description, Entries: l.Entries, UsedBy: []string{},
		CreatedAt: l.CreatedAt, CreatedBy: l.CreatedBy, UpdatedAt: l.UpdatedAt, UpdatedBy: l.UpdatedBy,
		SourceURL: l.SourceURL, SourceInterval: int(l.SourceInterval / time.Second), SourceHeader: l.SourceHeader,
		SourceSecretSet: l.SourceSecret != "", SourceStatus: l.SourceStatus}
	if !l.SourceFetchedAt.IsZero() {
		t := l.SourceFetchedAt
		v.SourceFetchedAt = &t
	}
	if policies == nil {
		policies, _ = h.d.DB.ListPolicies(r.Context())
	}
	ref := db.ListRef(l.Name)
	for _, p := range policies {
		if strings.Contains(p.Cedar, ref) {
			v.UsedBy = append(v.UsedBy, p.Name)
		}
	}
	return v
}

func (h *Handlers) readList(w http.ResponseWriter, r *http.Request) (db.List, bool) {
	var body ListBody
	if err := readJSON(r, &body, 2<<20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return db.List{}, false
	}
	name, err := db.CleanListName(body.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return db.List{}, false
	}
	entries, err := db.CleanListEntries(body.Kind, body.Entries)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return db.List{}, false
	}
	url, interval, header, err := db.CleanListSource(body.SourceURL, time.Duration(body.SourceInterval)*time.Second, body.SourceHeader)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return db.List{}, false
	}
	l := db.List{Name: name, Kind: body.Kind, Description: clip(body.Description, 512), Entries: entries,
		SourceURL: url, SourceInterval: interval, SourceHeader: header}
	if body.SourceSecret != nil {
		l.SourceSecret = strings.TrimSpace(*body.SourceSecret)
	} else if id := r.PathValue("id"); id != "" { // absent: keep what is stored
		if cur, err := h.d.DB.ListByID(r.Context(), id); err == nil {
			l.SourceSecret = cur.SourceSecret
		}
	}
	if l.SourceURL == "" {
		l.SourceHeader, l.SourceSecret = "", ""
	}
	return l, true
}

func (h *Handlers) adminLists(w http.ResponseWriter, r *http.Request) {
	ls, err := h.d.DB.Lists(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	ps, _ := h.d.DB.ListPolicies(r.Context())
	out := make([]ListView, 0, len(ls))
	for _, l := range ls {
		out = append(out, h.listView(r, l, ps))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) adminGetList(w http.ResponseWriter, r *http.Request) {
	l, err := h.d.DB.ListByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, h.listView(r, l, nil))
}

func (h *Handlers) adminCreateList(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	l, ok := h.readList(w, r)
	if !ok {
		return
	}
	l, version, err := h.d.DB.CreateList(r.Context(), l, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, "a list with that name exists")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "list created", "", map[string]any{"list": l.ID, "name": l.Name, "kind": l.Kind, "entries": len(l.Entries)})
	writeJSON(w, http.StatusCreated, h.listView(r, l, nil))
}

func (h *Handlers) adminPutList(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	l, ok := h.readList(w, r)
	if !ok {
		return
	}
	l.ID = r.PathValue("id")
	version, err := h.d.DB.UpdateList(r.Context(), l, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, strings.TrimPrefix(err.Error(), "db: conflict: "))
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "list updated", "", map[string]any{"list": l.ID, "name": l.Name, "kind": l.Kind, "entries": len(l.Entries)})
	l, _ = h.d.DB.ListByID(r.Context(), l.ID)
	writeJSON(w, http.StatusOK, h.listView(r, l, nil))
}

func (h *Handlers) adminDeleteList(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	id := r.PathValue("id")
	l, err := h.d.DB.ListByID(r.Context(), id)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	version, err := h.d.DB.DeleteList(r.Context(), id)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, strings.TrimPrefix(err.Error(), "db: conflict: "))
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "list deleted", "", map[string]any{"list": id, "name": l.Name})
	w.WriteHeader(http.StatusNoContent)
}

// adminExportList writes a list as a text file: one entry per line, with a
// header naming the list. It is what a source may hold, so an export can be
// committed to a repository and fetched back (docs/ACL.md).
func (h *Handlers) adminExportList(w http.ResponseWriter, r *http.Request) {
	l, err := h.d.DB.ListByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# BoundGate list %q (%s)\n", l.Name, l.Kind)
	if l.Description != "" {
		fmt.Fprintf(&b, "# %s\n", strings.ReplaceAll(l.Description, "\n", " "))
	}
	fmt.Fprintf(&b, "# %d entries, exported %s\n", len(l.Entries), time.Now().UTC().Format(time.RFC3339))
	for _, e := range l.Entries {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", l.Name+".list"))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, b.String())
}

// adminImportList replaces a list's entries with a text file (or a JSON
// array), the form an export writes. ?mode=add keeps what is there and adds
// to it.
func (h *Handlers) adminImportList(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	l, err := h.d.DB.ListByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, listsource.MaxBytes+1))
	if err != nil || len(body) > listsource.MaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("an import is at most %d bytes", listsource.MaxBytes))
		return
	}
	entries, err := listsource.Parse(l.Kind, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.URL.Query().Get("mode") == "add" {
		if entries, err = db.CleanListEntries(l.Kind, append(entries, l.Entries...)); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	before := len(l.Entries)
	l.Entries = entries
	version, err := h.d.DB.UpdateList(r.Context(), l, a.Subject)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "list imported", "", map[string]any{"list": l.ID, "name": l.Name, "entries": len(entries), "was": before})
	l, _ = h.d.DB.ListByID(r.Context(), l.ID)
	writeJSON(w, http.StatusOK, h.listView(r, l, nil))
}

// adminFetchList fetches a list's source now instead of waiting for its
// interval. A source that cannot be read is a 502 with the reason, and the
// list keeps its entries.
func (h *Handlers) adminFetchList(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	l, err := h.d.DB.ListByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if l.SourceURL == "" {
		writeError(w, http.StatusBadRequest, "this list has no source url")
		return
	}
	l, version, ferr := listsource.New(h.d.Logs.System).Fetch(r.Context(), h.d.DB, h.d.Snap, l)
	if ferr != nil {
		h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "list source fetched", "", map[string]any{"list": l.ID, "name": l.Name, "url": l.SourceURL, "err": ferr.Error()})
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": ferr.Error(), "list": h.listView(r, l, nil)})
		return
	}
	h.audit(r.Context(), h.d.Logs.Audit, logging.StreamAudit, a.Subject, "list source fetched", "", map[string]any{"list": l.ID, "name": l.Name, "url": l.SourceURL, "entries": len(l.Entries), "changed": version > 0})
	writeJSON(w, http.StatusOK, h.listView(r, l, nil))
}
