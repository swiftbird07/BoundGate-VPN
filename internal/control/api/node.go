package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// NodeMux returns the routes served behind the node server name. The TLS
// configuration accepts any structurally valid device certificate; only the
// enrollment routes work for unapproved keys.
func (h *Handlers) NodeMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/node/enroll", h.nodeEnroll)
	mux.HandleFunc("GET /api/v1/node/enroll/status", h.nodeEnrollStatus)
	mux.HandleFunc("GET /api/v1/node/snapshot", h.nodeSnapshot)
	mux.HandleFunc("POST /api/v1/node/heartbeat", h.nodeHeartbeat)
	mux.HandleFunc("POST /api/v1/node/login/start", h.nodeLoginStart)
	mux.HandleFunc("GET /api/v1/node/login/{flow}", h.nodeLoginStatus)
	mux.HandleFunc("POST /api/v1/node/logout", h.nodeLogout)
	mux.HandleFunc("POST /api/v1/node/logs", h.nodeShipLogs)
	return mux
}

// EnrollRequest is the node's enrollment body. Everything in it is a claim;
// roles and prefixes are what the node asks for, an admin grants them.
type EnrollRequest struct {
	Name          string            `json:"name"`
	Hostname      string            `json:"hostname"`
	Platform      string            `json:"platform"`
	KeyKind       string            `json:"key_kind"`
	HardwareBound bool              `json:"hardware_bound"`
	Roles         []string          `json:"roles"`
	Prefixes      []registry.Prefix `json:"prefixes"`
	PublicAddr    string            `json:"public_addr"`
}

// EnrollStatus is returned by enroll and enroll/status.
type EnrollStatus struct {
	NodeID      string          `json:"node_id"`
	Name        string          `json:"name"`
	Status      string          `json:"status"` // unknown | pending | confirmed | approved | revoked
	Fingerprint string          `json:"fingerprint"`
	Roles       []registry.Role `json:"roles,omitempty"`
	OverlayIP   string          `json:"overlay_ip,omitempty"`
	// SignerChain is the signed history of the admin key list; the node
	// verifies it (binding.VerifyChain) and pins its newest set.
	SignerChain []registry.SignerLink `json:"signer_chain,omitempty"`
	// ControlSPKI is the hash of the node-channel key the node should have
	// pinned from the TLS handshake (a cross-check, not a source of trust).
	ControlSPKI string `json:"control_spki,omitempty"`
}

func (h *Handlers) enrollStatus(r *http.Request, n db.Node) EnrollStatus {
	st := EnrollStatus{NodeID: n.ID, Name: n.Name, Status: n.Status, Fingerprint: n.SPKI.Fingerprint(), Roles: n.Roles, ControlSPKI: h.d.ControlSPKI.String()}
	if n.OverlayIP.IsValid() {
		st.OverlayIP = n.OverlayIP.String()
	}
	// The signed chain, exactly as stored: the node verifies it itself.
	if chain, err := h.d.DB.SignerLinks(r.Context()); err == nil {
		st.SignerChain = chain
	}
	return st
}

func (h *Handlers) nodeEnroll(w http.ResponseWriter, r *http.Request) {
	spki, err := transport.UnverifiedSPKI(r.TLS)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device certificate required")
		return
	}
	// Idempotent: a known key learns its status instead of creating a
	// duplicate request. Revoked keys stay revoked.
	if n, err := h.d.DB.NodeBySPKI(r.Context(), spki); err == nil {
		writeJSON(w, http.StatusOK, h.enrollStatus(r, n))
		return
	}
	ip := remoteIP(r)
	// Without an admin signing key no node can ever be approved, and the
	// node would pin an empty key set. Refuse until one is registered.
	if st, err := h.signerState(r.Context()); err != nil {
		fail(w, err, h.d.Logs.System)
		return
	} else if len(st.Keys) == 0 {
		h.d.Logs.Enrollment.Warn("enrollment refused: no admin signing key registered", "src", ip)
		writeError(w, http.StatusServiceUnavailable, "no admin signing key registered yet; ask the administrator")
		return
	}
	if !h.limit.allowClient(ip) {
		h.d.Logs.Enrollment.Warn("enrollment rate limited", "src", ip)
		writeError(w, http.StatusTooManyRequests, "too many enrollment requests")
		return
	}
	var body EnrollRequest
	if err := readJSON(r, &body, 16<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	roles, err := registry.ParseRoles(body.Roles)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, p := range body.Prefixes {
		if err := p.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if len(body.Prefixes) > 16 {
		writeError(w, http.StatusBadRequest, "too many prefixes")
		return
	}
	n, err := h.d.DB.CreatePending(r.Context(), db.EnrollRequest{
		Name: clip(body.Name, 64), Hostname: clip(body.Hostname, 128), Platform: clip(body.Platform, 32), KeyKind: clip(body.KeyKind, 32),
		HardwareBound: body.HardwareBound, SPKI: spki, CertDER: r.TLS.PeerCertificates[0].Raw, RequestIP: ip,
		Roles: roles, Prefixes: body.Prefixes, PublicAddr: clip(body.PublicAddr, 256),
	})
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	h.audit(r.Context(), h.d.Logs.Enrollment, logging.StreamEnrollment, "node", "enrollment requested", n.ID,
		map[string]any{"name": n.Name, "hostname": n.Hostname, "platform": n.Platform, "key_kind": n.KeyKind,
			"hardware_claimed": n.HardwareClaimed, "spki": n.SPKI.String(), "src": ip,
			"requested_roles": n.RequestedRoles, "requested_prefixes": n.RequestedPrefixes, "public_addr": n.PublicAddr})
	writeJSON(w, http.StatusAccepted, h.enrollStatus(r, n))
}

func (h *Handlers) nodeEnrollStatus(w http.ResponseWriter, r *http.Request) {
	spki, err := transport.UnverifiedSPKI(r.TLS)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "device certificate required")
		return
	}
	n, err := h.d.DB.NodeBySPKI(r.Context(), spki)
	if err != nil {
		writeJSON(w, http.StatusNotFound, EnrollStatus{Status: "unknown", Fingerprint: spki.Fingerprint()})
		return
	}
	writeJSON(w, http.StatusOK, h.enrollStatus(r, n))
}

// approvedPeer authenticates an approved node or writes a 403.
func (h *Handlers) approvedPeer(w http.ResponseWriter, r *http.Request) (transport.AuthenticatedPeer, bool) {
	src, _ := netip.ParseAddr(remoteIP(r))
	peer, err := transport.PeerFromTLSState(r.TLS, h.lookup, src)
	if err != nil {
		writeError(w, http.StatusForbidden, "node not approved")
		return transport.AuthenticatedPeer{}, false
	}
	return peer, true
}

// nodeSnapshot long-polls: ?since=N&wait=30s. 200 with the node's snapshot
// when the version exceeds N, 304 otherwise. Only approved nodes get here;
// a revoked node sees 403 and knows it has been unenrolled.
func (h *Handlers) nodeSnapshot(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	wait := 30 * time.Second
	if v := r.URL.Query().Get("wait"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 120*time.Second {
			wait = d
		}
	}
	newer, err := h.d.Snap.Wait(r.Context(), since, wait)
	if err != nil && r.Context().Err() != nil {
		return // client went away
	}
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if !newer {
		h.d.DB.TouchNode(r.Context(), string(peer.DeviceID()))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	snap, err := h.d.Snap.BuildFor(r.Context(), peer.DeviceID())
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if snap.Self.ID == "" {
		// approved a moment ago, then revoked: the lookup passed but the
		// snapshot has no self record any more
		writeError(w, http.StatusForbidden, "node not approved")
		return
	}
	h.d.DB.TouchNode(r.Context(), string(peer.DeviceID()))
	writeJSON(w, http.StatusOK, snap)
}

func (h *Handlers) nodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	var body struct {
		Version       uint64 `json:"version"`
		ActiveTunnels int    `json:"active_tunnels"`
	}
	if err := readJSON(r, &body, 4096); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	h.d.DB.Heartbeat(r.Context(), string(peer.DeviceID()), body.Version, body.ActiveTunnels)
	w.WriteHeader(http.StatusNoContent)
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
