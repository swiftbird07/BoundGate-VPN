package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
)

// Admin authentication (M4).
//
// Three credentials reach the admin API:
//
//   - a browser session cookie, created by an OIDC login of a member of the
//     admin group; its level is oidc_only until a passkey assertion
//     succeeded, and only /admin/auth/* and /admin/me work at that level
//   - an API token (bgapi_…) minted by a full admin, for automation
//   - the bootstrap token, only while no admin passkey exists: it lets the
//     first admin register a passkey and drives the lab; afterwards it is
//     dead
//
// Mutating requests with a cookie must carry X-Requested-With: BoundGate
// (the SPA does; a cross-site form cannot).

// Admin identity as established by the auth middleware.
type Admin struct {
	Subject   string // "bootstrap", "token:<name>" or the OIDC subject
	Email     string
	Name      string
	Level     db.AdminLevel
	Via       string // bootstrap | token | session
	SessionID string
}

// AdminConfig configures browser logins.
type AdminConfig struct {
	// RPID is the WebAuthn relying party id (a registrable domain, e.g. the
	// admin server name); Origins the browser origins allowed.
	RPID    string
	Origins []string
	// Group is the OIDC group that grants admin access (default "admins").
	Group string
	// SessionLifetime of a browser session (default 1h).
	SessionLifetime time.Duration
}

// Cookie names.
const (
	cookieSession = "bg_admin"
	cookieFlow    = "bg_login"
	csrfHeader    = "X-Requested-With"
	csrfValue     = "BoundGate"
)

// errNoAuth and friends explain a refusal.
var (
	errNoAuth        = errors.New("admin authentication required")
	errBootstrapDead = errors.New("the bootstrap token is disabled: an admin passkey exists; sign in with a passkey or use an API token")
	errCSRF          = errors.New("missing " + csrfHeader + " header")
)

func (h *Handlers) newWebAuthn() (*webauthn.WebAuthn, error) {
	c := h.d.Admin
	if c.RPID == "" {
		return nil, nil
	}
	origins := c.Origins
	if len(origins) == 0 {
		origins = []string{"https://" + c.RPID}
	}
	return webauthn.New(&webauthn.Config{RPID: c.RPID, RPDisplayName: "BoundGate", RPOrigins: origins})
}

// secureCookie: cookies are Secure on TLS requests, except when the browser
// reached the control plane through a plain-HTTP origin that the operator
// listed in admin.origins (the lab's devproxy on http://localhost): such a
// browser would drop a Secure cookie.
func (h *Handlers) secureCookie(r *http.Request) bool {
	if r.TLS == nil {
		return false
	}
	for _, o := range h.d.Admin.Origins {
		if strings.HasPrefix(o, "http://") && strings.TrimPrefix(o, "http://") == r.Host {
			return false
		}
	}
	return true
}

// resolveAdmin identifies the caller or returns why not.
func (h *Handlers) resolveAdmin(r *http.Request) (Admin, error) {
	ctx := r.Context()
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if strings.HasPrefix(tok, "bgapi_") {
			t, err := h.d.DB.LookupAPIToken(ctx, tok)
			if err != nil {
				h.d.Logs.AdminAuth.Warn("admin auth failed", "src", remoteIP(r), "reason", "bad api token")
				return Admin{}, errNoAuth
			}
			return Admin{Subject: "token:" + t.Name, Name: t.Name, Level: db.AdminLevelFull, Via: "token"}, nil
		}
		ok, err := h.d.DB.CheckBootstrapToken(ctx, tok)
		if err != nil {
			return Admin{}, err
		}
		if !ok {
			h.d.Logs.AdminAuth.Warn("admin auth failed", "src", remoteIP(r), "reason", "bad bootstrap token")
			return Admin{}, errNoAuth
		}
		if n, err := h.d.DB.CountActivePasskeys(ctx); err != nil {
			return Admin{}, err
		} else if n > 0 {
			h.d.Logs.AdminAuth.Warn("admin auth failed", "src", remoteIP(r), "reason", "bootstrap token used after a passkey exists")
			return Admin{}, errBootstrapDead
		}
		return Admin{Subject: "bootstrap", Name: "bootstrap", Level: db.AdminLevelFull, Via: "bootstrap"}, nil
	}
	c, err := r.Cookie(cookieSession)
	if err != nil || c.Value == "" {
		return Admin{}, errNoAuth
	}
	s, err := h.d.DB.AdminSessionByID(ctx, c.Value)
	if err != nil {
		return Admin{}, errNoAuth
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != csrfValue {
		return Admin{}, errCSRF
	}
	return Admin{Subject: s.Subject, Email: s.Email, Name: s.Name, Level: s.Level, Via: "session", SessionID: s.ID}, nil
}

// AdminAuth authenticates admin requests and enforces the level.
func (h *Handlers) AdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := h.resolveAdmin(r)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, errCSRF) {
				status = http.StatusForbidden
			}
			if !errors.Is(err, errNoAuth) && !errors.Is(err, errBootstrapDead) && !errors.Is(err, errCSRF) {
				fail(w, err, h.d.Logs.System)
				return
			}
			writeError(w, status, err.Error())
			return
		}
		if a.Level != db.AdminLevelFull && !levelOIDCAllowed(r.URL.Path) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "passkey required", "level": a.Level})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminKey{}, a)))
	})
}

func levelOIDCAllowed(p string) bool {
	return strings.HasPrefix(p, "/api/v1/admin/auth/") || p == "/api/v1/admin/me"
}

// --- browser login (OIDC) --------------------------------------------------

// adminLoginStart redirects the browser to the IdP.
func (h *Handlers) adminLoginStart(w http.ResponseWriter, r *http.Request) {
	p, err := h.d.OIDC.Get(r.Context())
	if err != nil {
		if errors.Is(err, oidc.ErrDisabled) {
			loginPage(w, http.StatusServiceUnavailable, "No identity provider", "Admin logins need an OIDC identity provider; this control plane has none configured.")
			return
		}
		loginPage(w, http.StatusBadGateway, "Identity provider unavailable", html.EscapeString(err.Error()))
		return
	}
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	f, err := oidc.NewFlow()
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	flow, err := h.d.DB.CreateAdminLoginFlow(r.Context(), f.State, f.Nonce, f.Verifier, next)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieFlow, Value: flow.ID, Path: "/api/v1/", HttpOnly: true, Secure: h.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: int(db.LoginFlowTTL.Seconds())})
	h.d.Logs.AdminAuth.Info("admin login started", "flow", flow.ID, "src", remoteIP(r))
	http.Redirect(w, r, p.AuthURL(f), http.StatusFound)
}

// adminCallback completes an admin flow found by state (called from the
// shared OIDC callback).
func (h *Handlers) adminCallback(w http.ResponseWriter, r *http.Request, flow db.AdminLoginFlow) {
	q := r.URL.Query()
	failFlow := func(reason string, status int, title, text string) {
		h.d.DB.FinishAdminLoginFlow(r.Context(), flow.ID, "failed", reason)
		h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, "idp", "admin login failed", "", map[string]any{"flow": flow.ID, "reason": reason, "src": remoteIP(r)})
		loginPage(w, status, title, text)
	}
	if c, err := r.Cookie(cookieFlow); err != nil || c.Value != flow.ID {
		failFlow("flow cookie missing", http.StatusBadRequest, "Wrong browser", "Finish the login in the browser that started it.")
		return
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
		failFlow(err.Error(), http.StatusForbidden, "Login failed", "The login could not be verified. Try again.")
		return
	}
	group := h.d.Admin.Group
	if group == "" {
		group = "admins"
	}
	isAdmin := false
	for _, g := range id.Groups {
		if g == group {
			isAdmin = true
		}
	}
	if !isAdmin {
		failFlow("subject "+id.Subject+" not in group "+group, http.StatusForbidden, "Not an administrator", "Your account is not in the <b>"+html.EscapeString(group)+"</b> group.")
		return
	}
	lifetime := h.d.Admin.SessionLifetime
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	s, err := h.d.DB.CreateAdminSession(r.Context(), db.AdminSession{Subject: id.Subject, Email: id.Email, Name: id.Username, Groups: id.Groups, Level: db.AdminLevelOIDC, LoginIP: remoteIP(r)}, lifetime)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.d.DB.FinishAdminLoginFlow(r.Context(), flow.ID, "done", "")
	http.SetCookie(w, &http.Cookie{Name: cookieSession, Value: s.ID, Path: "/", HttpOnly: true, Secure: h.secureCookie(r), SameSite: http.SameSiteLaxMode, MaxAge: int(lifetime.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: cookieFlow, Value: "", Path: "/api/v1/", HttpOnly: true, MaxAge: -1})
	h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, id.Subject, "admin login (oidc)", "", map[string]any{"email": id.Email, "username": id.Username, "groups": id.Groups, "flow": flow.ID, "src": remoteIP(r), "session": s.ID[:12]})
	http.Redirect(w, r, flow.Next, http.StatusFound)
}

// AuthStatus tells the SPA where it stands.
type AuthStatus struct {
	Level           string `json:"level"` // none | oidc_only | full
	Subject         string `json:"subject,omitempty"`
	Email           string `json:"email,omitempty"`
	Name            string `json:"name,omitempty"`
	Via             string `json:"via,omitempty"`
	OwnActive       int    `json:"own_passkeys"`
	OwnPending      int    `json:"own_pending"`
	TotalActive     int    `json:"total_passkeys"`
	BootstrapActive bool   `json:"bootstrap_active"`
	OIDCConfigured  bool   `json:"oidc_configured"`
	PasskeysEnabled bool   `json:"passkeys_enabled"`
	RPID            string `json:"rp_id,omitempty"`
	Error           string `json:"error,omitempty"`
}

func (h *Handlers) adminAuthStatus(w http.ResponseWriter, r *http.Request) {
	st := AuthStatus{Level: "none", OIDCConfigured: h.d.OIDC != nil, PasskeysEnabled: h.wa != nil, RPID: h.d.Admin.RPID}
	if n, err := h.d.DB.CountActivePasskeys(r.Context()); err == nil {
		st.TotalActive, st.BootstrapActive = n, n == 0
	}
	a, err := h.resolveAdmin(r)
	if err != nil {
		if errors.Is(err, errBootstrapDead) {
			st.Error = err.Error()
		}
		writeJSON(w, http.StatusOK, st)
		return
	}
	st.Level, st.Subject, st.Email, st.Name, st.Via = string(a.Level), a.Subject, a.Email, a.Name, a.Via
	if a.Via == "session" {
		if pks, err := h.d.DB.ListPasskeys(r.Context(), a.Subject); err == nil {
			for _, p := range pks {
				switch p.Status {
				case "active":
					st.OwnActive++
				case "pending":
					st.OwnPending++
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, st)
}

func (h *Handlers) adminLogout(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	if a.SessionID != "" {
		_ = h.d.DB.RevokeAdminSession(r.Context(), a.SessionID)
		h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "admin logout", "", map[string]any{"src": remoteIP(r)})
	}
	http.SetCookie(w, &http.Cookie{Name: cookieSession, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

// --- passkeys ----------------------------------------------------------------

// adminUser adapts an admin to webauthn.User.
type adminUser struct {
	subject, name, display string
	creds                  []webauthn.Credential
}

func (u adminUser) WebAuthnID() []byte {
	sum := sha256.Sum256([]byte("boundgate-admin:" + u.subject))
	return sum[:]
}
func (u adminUser) WebAuthnName() string                       { return u.name }
func (u adminUser) WebAuthnDisplayName() string                { return u.display }
func (u adminUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (h *Handlers) adminUserFor(ctx context.Context, a Admin, activeOnly bool) (adminUser, []db.Passkey, error) {
	u := adminUser{subject: a.Subject, name: a.Email, display: a.Name}
	if u.name == "" {
		u.name = a.Subject
	}
	if u.display == "" {
		u.display = u.name
	}
	pks, err := h.d.DB.ListPasskeys(ctx, a.Subject)
	if err != nil {
		return u, nil, err
	}
	for _, p := range pks {
		if p.Status == "revoked" || activeOnly && p.Status != "active" {
			continue
		}
		var c webauthn.Credential
		if json.Unmarshal(p.Credential, &c) == nil {
			u.creds = append(u.creds, c)
		}
	}
	return u, pks, nil
}

type ceremony struct {
	Kind    string               `json:"kind"` // register | login
	Label   string               `json:"label,omitempty"`
	Mode    string               `json:"mode,omitempty"` // first | self | pending
	Session webauthn.SessionData `json:"session"`
}

func (h *Handlers) requireSession(w http.ResponseWriter, r *http.Request) (Admin, bool) {
	a, _ := AdminFrom(r.Context())
	if a.Via != "session" {
		writeError(w, http.StatusBadRequest, "passkeys belong to browser sessions; sign in with OIDC first")
		return a, false
	}
	if h.wa == nil {
		writeError(w, http.StatusServiceUnavailable, "passkeys are not configured (admin.rp_id)")
		return a, false
	}
	return a, true
}

// RegisterBeginBody names the passkey; the bootstrap token is required for
// the very first passkey of the control plane.
type RegisterBeginBody struct {
	Label          string `json:"label"`
	BootstrapToken string `json:"bootstrap_token"`
}

func (h *Handlers) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	a, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	var body RegisterBeginBody
	if err := readJSON(r, &body, 4096); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	total, err := h.d.DB.CountActivePasskeys(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	u, own, err := h.adminUserFor(r.Context(), a, false)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	mode := "pending"
	switch {
	case total == 0:
		ok, err := h.d.DB.CheckBootstrapToken(r.Context(), body.BootstrapToken)
		if err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
		if !ok {
			h.d.Logs.AdminAuth.Warn("first passkey refused: bad bootstrap token", "subject", a.Subject, "src", remoteIP(r))
			writeError(w, http.StatusForbidden, "the first passkey needs the bootstrap token from the control plane's state directory")
			return
		}
		mode = "first"
	case a.Level == db.AdminLevelFull:
		mode = "self"
	}
	var exclude []protocol.CredentialDescriptor
	for _, p := range own {
		if p.Status != "revoked" {
			exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: p.CredentialID})
		}
	}
	creation, sd, err := h.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationRequired}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(exclude))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	c, _ := json.Marshal(ceremony{Kind: "register", Label: clip(body.Label, 64), Mode: mode, Session: *sd})
	if err := h.d.DB.SetAdminCeremony(r.Context(), a.SessionID, string(c)); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "options": creation})
}

func (h *Handlers) loadCeremony(r *http.Request, a Admin, kind string) (ceremony, error) {
	s, err := h.d.DB.AdminSessionByID(r.Context(), a.SessionID)
	if err != nil {
		return ceremony{}, err
	}
	var c ceremony
	if s.Ceremony == "" || json.Unmarshal([]byte(s.Ceremony), &c) != nil || c.Kind != kind {
		return ceremony{}, errors.New("no " + kind + " ceremony in progress; call begin first")
	}
	_ = h.d.DB.SetAdminCeremony(r.Context(), a.SessionID, "")
	return c, nil
}

func (h *Handlers) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	a, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	c, err := h.loadCeremony(r, a, "register")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, _, err := h.adminUserFor(r.Context(), a, false)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	cred, err := h.wa.FinishRegistration(u, c.Session, r)
	if err != nil {
		h.d.Logs.AdminAuth.Warn("passkey registration failed", "subject", a.Subject, "err", err, "src", remoteIP(r))
		writeError(w, http.StatusBadRequest, "passkey registration failed: "+err.Error())
		return
	}
	status := "active"
	if c.Mode == "pending" {
		status = "pending"
	}
	raw, _ := json.Marshal(cred)
	pk, err := h.d.DB.AddPasskey(r.Context(), db.Passkey{Subject: a.Subject, Email: a.Email, Label: c.Label, Credential: raw, CredentialID: cred.ID, Status: status}, a.Subject)
	if err != nil {
		if errors.Is(err, db.ErrConflict) {
			writeError(w, http.StatusConflict, "this passkey is already registered")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	if status == "active" {
		// user verification happened on the authenticator: the session is full
		if err := h.d.DB.SetAdminSessionLevel(r.Context(), a.SessionID, db.AdminLevelFull); err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
	}
	h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "passkey registered", "", map[string]any{"passkey": pk.ID, "label": pk.Label, "status": status, "mode": c.Mode, "src": remoteIP(r)})
	writeJSON(w, http.StatusCreated, map[string]any{"id": pk.ID, "status": status, "level": levelAfter(status)})
}

func levelAfter(status string) db.AdminLevel {
	if status == "active" {
		return db.AdminLevelFull
	}
	return db.AdminLevelOIDC
}

func (h *Handlers) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	a, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	u, own, err := h.adminUserFor(r.Context(), a, true)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if len(u.creds) == 0 {
		pending := 0
		for _, p := range own {
			if p.Status == "pending" {
				pending++
			}
		}
		writeJSON(w, http.StatusConflict, map[string]any{"error": "no active passkey for this account", "pending": pending})
		return
	}
	assertion, sd, err := h.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	c, _ := json.Marshal(ceremony{Kind: "login", Session: *sd})
	if err := h.d.DB.SetAdminCeremony(r.Context(), a.SessionID, string(c)); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"options": assertion})
}

func (h *Handlers) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	a, ok := h.requireSession(w, r)
	if !ok {
		return
	}
	c, err := h.loadCeremony(r, a, "login")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	u, own, err := h.adminUserFor(r.Context(), a, true)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	cred, err := h.wa.FinishLogin(u, c.Session, r)
	if err != nil {
		h.d.Logs.AdminAuth.Warn("passkey login failed", "subject", a.Subject, "err", err, "src", remoteIP(r))
		writeError(w, http.StatusForbidden, "passkey verification failed")
		return
	}
	for _, p := range own {
		if p.Status == "active" && string(p.CredentialID) == string(cred.ID) {
			raw, _ := json.Marshal(cred)
			_ = h.d.DB.UpdatePasskeyCredential(r.Context(), p.ID, raw)
			if err := h.d.DB.SetAdminSessionLevel(r.Context(), a.SessionID, db.AdminLevelFull); err != nil {
				fail(w, err, h.d.Logs.System)
				return
			}
			h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "admin login (passkey)", "", map[string]any{"passkey": p.ID, "label": p.Label, "src": remoteIP(r)})
			writeJSON(w, http.StatusOK, map[string]any{"level": db.AdminLevelFull})
			return
		}
	}
	writeError(w, http.StatusForbidden, "unknown credential")
}

// PasskeyView is a passkey as admins see it.
type PasskeyView struct {
	ID         string     `json:"id"`
	Subject    string     `json:"subject"`
	Email      string     `json:"email,omitempty"`
	Label      string     `json:"label,omitempty"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
}

func passkeyView(p db.Passkey) PasskeyView {
	v := PasskeyView{ID: p.ID, Subject: p.Subject, Email: p.Email, Label: p.Label, Status: p.Status, CreatedAt: p.CreatedAt, ApprovedBy: p.ApprovedBy, RevokedBy: p.RevokedBy}
	if !p.ApprovedAt.IsZero() {
		v.ApprovedAt = &p.ApprovedAt
	}
	if !p.LastUsedAt.IsZero() {
		v.LastUsedAt = &p.LastUsedAt
	}
	if !p.RevokedAt.IsZero() {
		v.RevokedAt = &p.RevokedAt
	}
	return v
}

func (h *Handlers) adminListPasskeys(w http.ResponseWriter, r *http.Request) {
	pks, err := h.d.DB.ListPasskeys(r.Context(), "")
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := make([]PasskeyView, 0, len(pks))
	for _, p := range pks {
		out = append(out, passkeyView(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) adminApprovePasskey(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	p, err := h.d.DB.PasskeyByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if p.Subject == a.Subject {
		writeError(w, http.StatusForbidden, "another admin must approve your passkey")
		return
	}
	if err := h.d.DB.ApprovePasskey(r.Context(), p.ID, a.Subject); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusConflict, "passkey is not pending")
			return
		}
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "passkey approved", "", map[string]any{"passkey": p.ID, "subject": p.Subject, "label": p.Label})
	p, _ = h.d.DB.PasskeyByID(r.Context(), p.ID)
	writeJSON(w, http.StatusOK, passkeyView(p))
}

func (h *Handlers) adminRevokePasskey(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	p, err := h.d.DB.PasskeyByID(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if err := h.d.DB.RevokePasskey(r.Context(), p.ID, a.Subject); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "passkey revoked", "", map[string]any{"passkey": p.ID, "subject": p.Subject, "label": p.Label})
	w.WriteHeader(http.StatusNoContent)
}

// --- API tokens ----------------------------------------------------------------

// TokenView is an API token without its secret.
type TokenView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedBy  string     `json:"created_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  string     `json:"revoked_by,omitempty"`
	// Token is the secret, returned once at creation.
	Token string `json:"token,omitempty"`
}

func tokenView(t db.APIToken) TokenView {
	v := TokenView{ID: t.ID, Name: t.Name, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, RevokedBy: t.RevokedBy}
	if !t.ExpiresAt.IsZero() {
		v.ExpiresAt = &t.ExpiresAt
	}
	if !t.LastUsedAt.IsZero() {
		v.LastUsedAt = &t.LastUsedAt
	}
	if !t.RevokedAt.IsZero() {
		v.RevokedAt = &t.RevokedAt
	}
	return v
}

func (h *Handlers) adminListTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := h.d.DB.ListAPITokens(r.Context())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	out := make([]TokenView, 0, len(ts))
	for _, t := range ts {
		out = append(out, tokenView(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) adminCreateToken(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	var body struct {
		Name      string `json:"name"`
		ExpiresIn string `json:"expires_in"` // duration, "" = never
	}
	if err := readJSON(r, &body, 4096); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	name := clip(body.Name, 64)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	var expires time.Time
	if body.ExpiresIn != "" {
		d, err := time.ParseDuration(body.ExpiresIn)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "expires_in must be a duration like 720h")
			return
		}
		expires = time.Now().Add(d)
	}
	t, secret, err := h.d.DB.CreateAPIToken(r.Context(), name, a.Subject, expires)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "api token created", "", map[string]any{"token": t.ID, "name": name, "expires_at": expires})
	v := tokenView(t)
	v.Token = secret
	writeJSON(w, http.StatusCreated, v)
}

func (h *Handlers) adminRevokeToken(w http.ResponseWriter, r *http.Request) {
	a, _ := AdminFrom(r.Context())
	if err := h.d.DB.RevokeAPIToken(r.Context(), r.PathValue("id"), a.Subject); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.AdminAuth, logging.StreamAdminAuth, a.Subject, "api token revoked", "", map[string]any{"token": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

// --- overview ----------------------------------------------------------------

// Overview feeds the SPA's start page.
type Overview struct {
	Nodes           map[string]int `json:"nodes"` // by status
	ActiveSessions  int            `json:"active_sessions"`
	ActiveTunnels   int            `json:"active_tunnels"`
	Policies        int            `json:"policies"`
	PoliciesEnabled int            `json:"policies_enabled"`
	DeniedLast24h   int            `json:"denied_last_24h"`
	PendingPasskeys int            `json:"pending_passkeys"`
	Signers         int            `json:"signers"`
	SnapshotVersion uint64         `json:"snapshot_version"`
}

func (h *Handlers) adminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	o := Overview{Nodes: map[string]int{"pending": 0, "confirmed": 0, "approved": 0, "revoked": 0}}
	nodes, err := h.d.DB.ListNodes(ctx, "")
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	for _, n := range nodes {
		o.Nodes[n.Status]++
	}
	if ss, err := h.d.DB.ActiveSessions(ctx); err == nil {
		o.ActiveSessions = len(ss)
	}
	if ts, err := h.d.DB.ListTunnels(ctx, db.TunnelQuery{Active: true, Limit: 5000}); err == nil {
		o.ActiveTunnels = len(ts)
	}
	if ps, err := h.d.DB.ListPolicies(ctx); err == nil {
		o.Policies = len(ps)
		for _, p := range ps {
			if p.Enabled {
				o.PoliciesEnabled++
			}
		}
	}
	if evs, err := h.d.DB.ListLogs(ctx, db.LogQuery{Stream: logging.StreamFlow, Attrs: map[string]string{"event": "deny"}, Since: time.Now().Add(-24 * time.Hour), Limit: 1000}); err == nil {
		o.DeniedLast24h = len(evs)
	}
	if pks, err := h.d.DB.ListPasskeys(ctx, ""); err == nil {
		for _, p := range pks {
			if p.Status == "pending" {
				o.PendingPasskeys++
			}
		}
	}
	if sg, err := h.d.DB.ListSigners(ctx, true); err == nil {
		o.Signers = len(sg)
	}
	o.SnapshotVersion, _ = h.d.DB.SnapshotVersion(ctx)
	writeJSON(w, http.StatusOK, o)
}
