package api

import (
	"context"
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
// the code and verifies the ID token. Nothing ties that browser to the
// device that started the flow, so the callback does not complete it: it
// shows which device is about to be signed in and asks (R120). Only the
// button on that page stores the session, bound to the node that started
// the flow. The node learns the result by polling the flow and, like every
// other node, from the snapshot. No token ever reaches a node.

// Bounds per node: open flows (a new one fails the oldest) and status
// long-polls waiting at the same time.
const (
	maxOpenLoginFlows = 3
	maxLoginPolls     = 2
)

// LoginStart is what a node gets back for a new flow.
type LoginStart struct {
	FlowID    string    `json:"flow_id"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionView is a user session as nodes and admins see it.
type SessionView struct {
	ID        string     `json:"id"`
	NodeID    string     `json:"node_id"`
	NodeName  string     `json:"node_name,omitempty"`
	Subject   string     `json:"subject"`
	Email     string     `json:"email,omitempty"`
	Username  string     `json:"username,omitempty"`
	Groups    []string   `json:"groups"`
	LoginIP   string     `json:"login_ip,omitempty"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	EndedBy   string     `json:"ended_by,omitempty"`
	EndReason string     `json:"end_reason,omitempty"`
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
	flow, err := h.d.DB.CreateLoginFlow(r.Context(), n.ID, f.State, f.Nonce, f.Verifier, remoteIP(r), maxOpenLoginFlows)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.UserAuth, logging.StreamUserAuth, "node", "login started", n.ID,
		map[string]any{"name": n.Name, "flow": flow.ID, "src": remoteIP(r)})
	writeJSON(w, http.StatusOK, LoginStart{FlowID: flow.ID, URL: p.AuthURL(f), ExpiresAt: flow.ExpiresAt})
}

// nodeLoginStatus long-polls a flow the node started: ?wait=30s. A flow
// awaiting the person's confirmation in the browser is still pending here.
func (h *Handlers) nodeLoginStatus(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	if !h.enterLoginPoll(string(peer.DeviceID())) {
		writeError(w, http.StatusTooManyRequests, "too many login status requests waiting for this node")
		return
	}
	defer h.leaveLoginPoll(string(peer.DeviceID()))
	wait := 0 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= MaxLongPoll {
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

// enterLoginPoll counts a waiting status request of a node; false when the
// node has maxLoginPolls waiting already.
func (h *Handlers) enterLoginPoll(node string) bool {
	h.pollMu.Lock()
	defer h.pollMu.Unlock()
	if h.loginPolls[node] >= maxLoginPolls {
		return false
	}
	h.loginPolls[node]++
	return true
}

func (h *Handlers) leaveLoginPoll(node string) {
	h.pollMu.Lock()
	defer h.pollMu.Unlock()
	if h.loginPolls[node]--; h.loginPolls[node] <= 0 {
		delete(h.loginPolls, node)
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

// OIDCCallbackPath is where the identity provider sends browsers back, for
// user and admin logins alike.
const OIDCCallbackPath = "/api/v1/oidc/callback"

// OIDCConfirmPath receives the button of the page that asks a person to
// confirm the device a user login signs in (POST, a form).
const OIDCConfirmPath = "/api/v1/oidc/confirm"

type adminDeniedKey struct{}

// WithAdminDenied marks a request from an address outside admin_allow that
// was let through to the callback for a user's sign-in.
func WithAdminDenied(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), adminDeniedKey{}, true))
}

func adminDenied(r *http.Request) bool { v, _ := r.Context().Value(adminDeniedKey{}).(bool); return v }

// oidcCallback is where the IdP sends the browser. No admin auth: the
// state binds the request to a flow a node started (user login) or a
// browser started (admin login).
func (h *Handlers) oidcCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	if af, err := h.d.DB.AdminLoginFlowByState(r.Context(), state); state != "" && err == nil {
		if adminDenied(r) {
			// the flow stays open: finishing it from an allowed address still works
			h.d.Logs.AdminAuth.Warn("admin login callback from outside admin_allow refused", "src", remoteIP(r), "flow", af.ID)
			loginPage(w, http.StatusForbidden, "Not allowed from here", "Admin logins are only accepted from the networks in <code>admin_allow</code>.")
			return
		}
		h.adminCallback(w, r, af)
		return
	} else if errors.Is(err, db.ErrConflict) || errors.Is(err, db.ErrTokenExpired) {
		loginPage(w, http.StatusGone, "Login expired", "This admin login was already used or took too long. <a href=\"/api/v1/admin/auth/login\">Start again</a>.")
		return
	}
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
	// The browser proved who the person is, not that the device is theirs:
	// whoever controls a node can send anybody its login link. Ask first.
	ident := db.LoginIdentity{Subject: id.Subject, Email: id.Email, Username: id.Username, Groups: id.Groups}
	src := remoteIP(r)
	token, expires, err := h.d.DB.AwaitLoginConfirmation(r.Context(), flow.ID, ident, src)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			loginPage(w, http.StatusConflict, "Already used", "This login was already completed.")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	differs := !sameClientNetwork(flow.StartIP, src)
	h.audit(r.Context(), h.d.Logs.UserAuth, logging.StreamUserAuth, "idp", "login awaiting confirmation", n.ID,
		map[string]any{"name": n.Name, "flow": flow.ID, "subject": id.Subject, "username": id.Username, "src": src, "started_from": flow.StartIP, "address_differs": differs})
	flow.Identity, flow.CallbackIP, flow.ConfirmExpiresAt = ident, src, expires
	confirmPage(w, n, flow, token, differs)
}

// confirmPage asks the person whether the device that started the login
// is theirs. The form carries the flow's single-use confirmation token,
// which a cross-site page cannot know.
func confirmPage(w http.ResponseWriter, n db.Node, flow db.LoginFlow, token string, addressDiffers bool) {
	who := flow.Identity.Username
	if who == "" {
		who = flow.Identity.Subject
	}
	if flow.Identity.Email != "" && flow.Identity.Email != who {
		who += " (" + flow.Identity.Email + ")"
	}
	since := n.ApprovedAt
	if since.IsZero() {
		since = n.RequestedAt
	}
	fp := n.SPKI.Fingerprint()
	if len(fp) > 19 {
		fp = fp[:19] + " …"
	}
	row := func(k, v string) string {
		if v == "" {
			v = "–"
		}
		return "<dt>" + k + "</dt><dd>" + html.EscapeString(v) + "</dd>"
	}
	var b strings.Builder
	b.WriteString(`You signed in as <b>` + html.EscapeString(who) + `</b>. Continuing signs this device in with your account:</p>`)
	b.WriteString(`<dl>` + row("Device", n.Name) + row("Hostname", n.Hostname) + row("Platform", n.Platform) +
		row("Approved", since.Local().Format("2006-01-02 15:04")) + `<dt>Key</dt><dd><code>` + html.EscapeString(fp) + `</code></dd></dl>`)
	if addressDiffers {
		b.WriteString(`<div class="warn strong"><b>This sign-in was started from another network.</b> The device asked from ` +
			html.EscapeString(flow.StartIP) + `, your browser comes from ` + html.EscapeString(flow.CallbackIP) +
			`. That can be harmless (mobile data, IPv6, a VPN), but if you did not just start this sign-in on this device yourself, someone is trying to get your access: press Cancel.</div>`)
	}
	b.WriteString(`<div class="warn">Only continue if you started this sign-in on this device yourself. Whoever holds this device gets your access.</div>`)
	b.WriteString(`<form method="post" action="` + OIDCConfirmPath + `"><input type="hidden" name="flow" value="` + html.EscapeString(flow.ID) +
		`"><input type="hidden" name="token" value="` + html.EscapeString(token) + `"><button class="primary" name="action" value="confirm">Sign in this device</button>` +
		`<button name="action" value="cancel">Cancel</button></form><p class="small">This page is valid until ` + flow.ConfirmExpiresAt.Local().Format("15:04") + `.`)
	page(w, http.StatusOK, "ask", "Sign in this device?", b.String())
}

// oidcConfirm is the button on the confirmation page: it completes the
// login or cancels it.
func (h *Handlers) oidcConfirm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		loginPage(w, http.StatusBadRequest, "Bad request", "This request could not be read.")
		return
	}
	action := r.PostForm.Get("action")
	flow, err := h.d.DB.LoginFlowForConfirmation(r.Context(), r.PostForm.Get("flow"), r.PostForm.Get("token"))
	switch {
	case errors.Is(err, db.ErrNotFound):
		h.d.Logs.UserAuth.Warn("login confirmation with an unknown flow or token", "src", remoteIP(r))
		loginPage(w, http.StatusBadRequest, "Unknown login", "This confirmation is not known. Start again with <code>boundgatectl login</code>.")
		return
	case errors.Is(err, db.ErrConflict):
		loginPage(w, http.StatusConflict, "Already decided", "This sign-in was already completed, cancelled or replaced by a newer one.")
		return
	case errors.Is(err, db.ErrTokenExpired):
		h.d.DB.FailLoginFlow(r.Context(), flow.ID, "not confirmed in time")
		loginPage(w, http.StatusGone, "Login expired", "This confirmation took too long. Start again with <code>boundgatectl login</code>.")
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
	attrs := map[string]any{"name": n.Name, "flow": flow.ID, "subject": flow.Identity.Subject, "username": flow.Identity.Username,
		"src": remoteIP(r), "started_from": flow.StartIP, "address_differs": !sameClientNetwork(flow.StartIP, flow.CallbackIP)}
	switch action {
	case "cancel":
		h.d.DB.FailLoginFlow(r.Context(), flow.ID, "cancelled in the browser")
		h.audit(r.Context(), h.d.Logs.UserAuth, logging.StreamUserAuth, flow.Identity.Subject, "login cancelled", n.ID, attrs)
		page(w, http.StatusOK, "bad", "Sign-in cancelled", "Nothing was signed in. You can close this tab.")
		return
	case "confirm":
	default:
		loginPage(w, http.StatusBadRequest, "Bad request", "Choose to sign in the device or to cancel.")
		return
	}
	if n.Status != db.StatusApproved {
		h.d.DB.FailLoginFlow(r.Context(), flow.ID, "node is "+n.Status)
		h.audit(r.Context(), h.d.Logs.UserAuth, logging.StreamUserAuth, flow.Identity.Subject, "login failed", n.ID, map[string]any{"name": n.Name, "flow": flow.ID, "reason": "node is " + n.Status, "src": remoteIP(r)})
		loginPage(w, http.StatusForbidden, "Node not approved", "The node that started this login is no longer approved.")
		return
	}
	p, err := h.d.OIDC.Get(r.Context())
	if err != nil {
		loginPage(w, http.StatusBadGateway, "Identity provider unavailable", html.EscapeString(err.Error()))
		return
	}
	id := flow.Identity
	sess, version, err := h.d.DB.CompleteLoginFlow(r.Context(), flow.ID, db.Session{
		NodeID: n.ID, Subject: id.Subject, Email: id.Email, Username: id.Username, Groups: id.Groups,
		LoginIP: remoteIP(r), ExpiresAt: time.Now().Add(p.SessionLifetime()),
	})
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			loginPage(w, http.StatusConflict, "Already decided", "This sign-in was already completed, cancelled or replaced by a newer one.")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.Snap.Notify(version)
	delete(attrs, "subject")
	delete(attrs, "username")
	delete(attrs, "src")
	attrs["snapshot_version"] = version
	h.auditSession(r, h.d.Logs.UserAuth, id.Subject, "login completed", sess, attrs)
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

// loginPageCSS styles the pages a person sees in the browser around a login
// (result, expiry, errors). Self-contained: no script, no external resource.
const loginPageCSS = `:root{color-scheme:dark light;--bg:#1d1d1d;--card:#2a2a2a;--line:rgba(255,255,255,.1);--text:#f5f2ea;--dim:#b9b4a8;--tile:#ffcc00;--mark:#2a2a2a;--link:#ffcc00;--code:#343434}
@media(prefers-color-scheme:light){:root{--bg:#f4f2eb;--card:#fff;--line:rgba(42,42,42,.12);--text:#2a2a2a;--dim:#5d594f;--tile:#2a2a2a;--mark:#ffcc00;--link:#2a2a2a;--code:#f0ede4}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:var(--bg);color:var(--text);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{width:min(440px,100%);background:var(--card);border:1px solid var(--line);border-radius:20px;padding:30px 28px 26px;text-align:center;box-shadow:0 14px 36px rgba(0,0,0,.18)}
svg{display:block;margin:0 auto 14px}.brand{font:750 13px/1 ui-rounded,"SF Pro Rounded",system-ui,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:var(--dim)}
h1{font:750 24px/1.2 ui-rounded,"SF Pro Rounded",system-ui,sans-serif;letter-spacing:-.02em;margin:10px 0 10px}h1.ok::before,h1.bad::before{content:"";display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:10px;vertical-align:middle;position:relative;top:-2px}
h1.ok::before{background:#5fd38d}h1.bad::before{background:#ff6b6b}p{margin:0;color:var(--dim)}b{color:var(--text)}
a{color:var(--link);font-weight:600;text-decoration:underline;text-decoration-color:#ffcc00;text-decoration-thickness:2px;text-underline-offset:3px}code{font:13px ui-monospace,"SF Mono",Menlo,monospace;background:var(--code);padding:1px 6px;border-radius:6px;color:var(--text)}
h1.ask::before{background:#ffcc00}dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:16px 0;text-align:left}dt{color:var(--dim)}dd{margin:0;color:var(--text);overflow-wrap:anywhere}
.warn{margin:12px 0;padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:var(--code);color:var(--text);text-align:left}.warn.strong{border-color:#ff6b6b}
form{display:flex;gap:10px;justify-content:center;margin:18px 0 10px}button{font:650 15px/1 system-ui,sans-serif;padding:11px 18px;border-radius:12px;border:1px solid var(--line);background:var(--code);color:var(--text);cursor:pointer}
button.primary{background:#ffcc00;border-color:#ffcc00;color:#2a2a2a}.small{font-size:13px}`

// loginPage renders title and body (trusted HTML, callers escape) in the
// BoundGate look; the status decides the tone.
func loginPage(w http.ResponseWriter, status int, title, body string) {
	tone := "bad"
	if status < 300 {
		tone = "ok"
	}
	page(w, status, tone, title, body)
}

// page renders a login page with a tone (ok, bad, ask). It runs no script,
// loads nothing but the icon, posts forms only to itself and cannot be
// framed (the confirmation button must not be clickjacked).
func page(w http.ResponseWriter, status int, tone, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark light">
<title>BoundGate: ` + html.EscapeString(title) + `</title><link rel="icon" href="/favicon.svg" type="image/svg+xml"><style>` + loginPageCSS + `</style>
<main><svg width="64" height="64" viewBox="0 0 1024 1024" role="img" aria-label="BoundGate"><rect width="1024" height="1024" rx="232" fill="var(--tile)"/><g fill="none" stroke="var(--mark)" stroke-width="57" stroke-linecap="round" stroke-linejoin="round"><rect x="148" y="268" width="462" height="300" rx="76"/><rect x="414" y="456" width="462" height="300" rx="76"/></g></svg>
<div class="brand">BoundGate</div><h1 class="` + tone + `">` + html.EscapeString(title) + `</h1><p>` + body + `</p></main></html>`))
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
