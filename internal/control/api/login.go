package api

import (
	"errors"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
)

// User login (M2). The node starts a flow over mTLS and shows the user a
// URL; the user's browser authenticates at the IdP and lands on the
// control plane's callback (admin name, WebPKI); the control plane redeems
// the code, verifies the ID token and stores a session bound to the node
// that started the flow. The node learns the result by polling the flow
// and, like every other node, from the snapshot. No token ever reaches a
// node.

// LoginStart is what a node gets back for a new flow.
type LoginStart struct {
	FlowID    string    `json:"flow_id"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionView is a user session as nodes and admins see it.
type SessionView struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id"`
	NodeName  string    `json:"node_name,omitempty"`
	Subject   string    `json:"subject"`
	Email     string    `json:"email,omitempty"`
	Username  string    `json:"username,omitempty"`
	Groups    []string  `json:"groups"`
	LoginIP   string    `json:"login_ip,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndedBy   string    `json:"ended_by,omitempty"`
	EndReason string    `json:"end_reason,omitempty"`
}

func sessionView(s db.Session) SessionView {
	v := SessionView{ID: s.ID, NodeID: s.NodeID, Subject: s.Subject, Email: s.Email, Username: s.Username, Groups: s.Groups,
		LoginIP: s.LoginIP, IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt, EndedBy: s.RevokedBy, EndReason: s.EndReason}
	if v.Groups == nil {
		v.Groups = []string{}
	}
	if !s.RevokedAt.IsZero() {
		v.EndedAt = &s.RevokedAt
	}
	return v
}

// LoginStatus is the state of a flow as the node polls it.
type LoginStatus struct {
	Status  string       `json:"status"` // pending | done | failed
	Session *SessionView `json:"session,omitempty"`
	Error   string       `json:"error,omitempty"`
}

func (h *Handlers) nodeLoginStart(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	p, err := h.d.OIDC.Get(r.Context())
	if err != nil {
		if errors.Is(err, oidc.ErrDisabled) {
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		h.d.Logs.UserAuth.Error("identity provider not reachable", "err", err)
		writeError(w, http.StatusBadGateway, "identity provider not reachable: "+err.Error())
		return
	}
	n, err := h.d.DB.NodeByID(r.Context(), string(peer.DeviceID()))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	f, err := oidc.NewFlow()
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	flow, err := h.d.DB.CreateLoginFlow(r.Context(), n.ID, f.State, f.Nonce, f.Verifier)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.UserAuth, logging.StreamUserAuth, "node", "login started", n.ID,
		map[string]any{"name": n.Name, "flow": flow.ID, "src": remoteIP(r)})
	writeJSON(w, http.StatusOK, LoginStart{FlowID: flow.ID, URL: p.AuthURL(f), ExpiresAt: flow.ExpiresAt})
}

// nodeLoginStatus long-polls a flow the node started: ?wait=30s.
func (h *Handlers) nodeLoginStatus(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	wait := 0 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 120*time.Second {
			wait = d
		}
	}
	deadline := time.Now().Add(wait)
	for {
		flow, err := h.d.DB.LoginFlowByID(r.Context(), r.PathValue("flow"))
		if err != nil || flow.NodeID != string(peer.DeviceID()) {
			writeError(w, http.StatusNotFound, "unknown login flow")
			return
		}
		switch {
		case flow.Status == "done":
			s, err := h.d.DB.SessionByID(r.Context(), flow.SessionID)
			if err != nil {
				fail(w, err, h.d.Logs.System)
				return
			}
			sv := sessionView(s)
			writeJSON(w, http.StatusOK, LoginStatus{Status: "done", Session: &sv})
			return
		case flow.Status == "failed":
			writeJSON(w, http.StatusOK, LoginStatus{Status: "failed", Error: flow.Error})
			return
		case !time.Now().Before(flow.ExpiresAt):
			writeJSON(w, http.StatusOK, LoginStatus{Status: "failed", Error: "login timed out"})
			return
		}
		if time.Now().After(deadline) || r.Context().Err() != nil {
			writeJSON(w, http.StatusOK, LoginStatus{Status: "pending"})
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (h *Handlers) nodeLogout(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	s, err := h.d.DB.SessionForNode(r.Context(), string(peer.DeviceID()))
	if errors.Is(err, db.ErrNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	version, err := h.d.DB.EndSession(r.Context(), s.ID, "node", "logout")
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		fail(w, err, h.d.Logs.System)
		return
	}
	if err == nil {
		h.d.Snap.Notify(version)
		h.auditSession(r, h.d.Logs.UserAuth, "node", "logout", s, map[string]any{"snapshot_version": version})
	}
	w.WriteHeader(http.StatusNoContent)
}

// oidcCallback is where the IdP sends the browser. No admin auth: the
// state binds the request to a flow a node started.
func (h *Handlers) oidcCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	flow, err := h.d.DB.LoginFlowByState(r.Context(), state)
	switch {
	case state == "" || errors.Is(err, db.ErrNotFound):
		h.d.Logs.UserAuth.Warn("login callback with unknown state", "src", remoteIP(r))
		loginPage(w, http.StatusBadRequest, "Unknown login", "This login link is not known. Start again with <code>boundgatectl login</code>.")
		return
	case errors.Is(err, db.ErrConflict):
		loginPage(w, http.StatusConflict, "Already used", "This login was already completed.")
		return
	case errors.Is(err, db.ErrTokenExpired):
		loginPage(w, http.StatusGone, "Login expired", "This login took too long. Start again with <code>boundgatectl login</code>.")
		return
	case err != nil:
		fail(w, err, h.d.Logs.System)
		return
	}
	n, err := h.d.DB.NodeByID(r.Context(), flow.NodeID)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	failFlow := func(reason string, status int, title, text string) {
		h.d.DB.FailLoginFlow(r.Context(), flow.ID, reason)
		h.audit(r.Context(), h.d.Logs.UserAuth, logging.StreamUserAuth, "idp", "login failed", n.ID,
			map[string]any{"name": n.Name, "flow": flow.ID, "reason": reason, "src": remoteIP(r)})
		loginPage(w, status, title, text)
	}
	if e := q.Get("error"); e != "" {
		failFlow("idp: "+e+": "+q.Get("error_description"), http.StatusForbidden, "Login refused", "The identity provider refused the login: "+html.EscapeString(e+" "+q.Get("error_description")))
		return
	}
	p, err := h.d.OIDC.Get(r.Context())
	if err != nil {
		failFlow(err.Error(), http.StatusBadGateway, "Identity provider unavailable", html.EscapeString(err.Error()))
		return
	}
	id, err := p.Exchange(r.Context(), oidc.Flow{State: flow.State, Nonce: flow.Nonce, Verifier: flow.PKCEVerifier}, q.Get("code"))
	if err != nil {
		failFlow(err.Error(), http.StatusForbidden, "Login failed", "The login could not be verified. Start again with <code>boundgatectl login</code>.")
		return
	}
	if n.Status != db.StatusApproved {
		failFlow("node is "+n.Status, http.StatusForbidden, "Node not approved", "The node that started this login is no longer approved.")
		return
	}
	sess, version, err := h.d.DB.CompleteLoginFlow(r.Context(), flow.ID, db.Session{
		NodeID: n.ID, Subject: id.Subject, Email: id.Email, Username: id.Username, Groups: id.Groups,
		LoginIP: remoteIP(r), ExpiresAt: time.Now().Add(p.SessionLifetime()),
	})
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.auditSession(r, h.d.Logs.UserAuth, "idp", "login completed", sess, map[string]any{"name": n.Name, "flow": flow.ID, "snapshot_version": version})
	who := id.Username
	if who == "" {
		who = id.Subject
	}
	loginPage(w, http.StatusOK, "Logged in", "You are logged in as <b>"+html.EscapeString(who)+"</b> on <b>"+html.EscapeString(n.Name)+"</b> until "+
		sess.ExpiresAt.Local().Format("2006-01-02 15:04")+". You can close this tab.")
}

func (h *Handlers) auditSession(r *http.Request, stream interface{ Info(string, ...any) }, actor, msg string, s db.Session, extra map[string]any) {
	attrs := map[string]any{"session": s.ID, "subject": s.Subject, "email": s.Email, "username": s.Username, "groups": s.Groups, "expires_at": s.ExpiresAt, "src": remoteIP(r)}
	for k, v := range extra {
		attrs[k] = v
	}
	args := []any{"actor", actor, "device", s.NodeID}
	for k, v := range attrs {
		args = append(args, k, v)
	}
	stream.Info(msg, args...)
	h.d.DB.InsertLog(r.Context(), db.LogEvent{Stream: logging.StreamUserAuth, Actor: actor, DeviceID: s.NodeID, SessionID: s.ID, Message: msg, Attrs: attrs})
}

func loginPage(w http.ResponseWriter, status int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><title>BoundGate: ` + html.EscapeString(title) + `</title>
<style>body{font-family:system-ui,sans-serif;max-width:40em;margin:4em auto;padding:0 1em;color:#222}h1{font-size:1.4em}</style>
<h1>BoundGate: ` + html.EscapeString(title) + `</h1><p>` + body + `</p>`))
}

// --- admin ---

func (h *Handlers) adminListSessions(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("all") != ""
	rows, err := h.d.DB.ListSessions(r.Context(), all)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	names := map[string]string{}
	if nodes, err := h.d.DB.ListNodes(r.Context(), ""); err == nil {
		for _, n := range nodes {
			names[n.ID] = n.Name
		}
	}
	out := make([]SessionView, 0, len(rows))
	for _, s := range rows {
		v := sessionView(s)
		v.NodeName = names[s.NodeID]
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) adminRevokeSession(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	s, err := h.d.DB.SessionByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	version, err := h.d.DB.EndSession(r.Context(), s.ID, a.Subject, "revoked")
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusConflict, "session already ended")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	h.auditSession(r, h.d.Logs.UserAuth, a.Subject, "session revoked", s, map[string]any{"snapshot_version": version})
	w.WriteHeader(http.StatusNoContent)
}

var _ = strconv.Itoa
var _ = strings.TrimSpace
