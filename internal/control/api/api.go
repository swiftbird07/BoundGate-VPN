// Package api implements the control plane's two HTTP surfaces:
//
//   - admin API (/api/v1/admin/...) for operators; bootstrap token in M1,
//     OIDC + passkey sessions from M4
//   - node API  (/api/v1/node/...) behind the mTLS server name; enrollment
//     for any device certificate, everything else (snapshots, heartbeat)
//     for approved nodes only
//
// Both are served on port 443; the TLS server name picks the surface (see
// Root). Handlers never construct identities: node identity comes from
// transport.PeerFromTLSState, admin identity from the auth middleware.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/oidc"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// Deps are shared by all handlers.
type Deps struct {
	DB   *db.DB
	Snap *snapshot.Source
	Logs *logging.Streams
	// PendingTTL is how long an enrollment request stays open.
	PendingTTL time.Duration
	// ControlSPKI is the hash of the node-channel key; it is told to nodes
	// at enrollment so they can cross-check the key they pinned.
	ControlSPKI devicekey.SPKIHash
	// OIDC is the identity provider for user logins; nil disables logins.
	OIDC *oidc.Lazy
	// Admin configures browser logins (OIDC admin group + passkeys).
	Admin AdminConfig
	// SPA serves the admin UI for non-API paths on the admin name; nil = 404.
	SPA http.Handler
}

// Handlers holds the muxes.
type Handlers struct {
	d         Deps
	limit     *rateLimiter // enrollment, per source IP
	signLimit *rateLimiter // sign-token routes, per source IP
	lookup    transport.DeviceLookup
	admin     http.Handler
	node      http.Handler
	wa        *webauthn.WebAuthn // nil: passkeys not configured
}

// New wires the handlers; it panics on an invalid passkey configuration
// (see NewWithError).
func New(d Deps) *Handlers {
	h, err := NewWithError(d)
	if err != nil {
		panic(err)
	}
	return h
}

// NewWithError is New with the configuration error surfaced.
func NewWithError(d Deps) (*Handlers, error) {
	if d.PendingTTL == 0 {
		d.PendingTTL = 24 * time.Hour
	}
	h := &Handlers{d: d, limit: newRateLimiter(5, time.Minute), signLimit: newRateLimiter(30, time.Minute), lookup: dbLookup{d.DB}}
	wa, err := h.newWebAuthn()
	if err != nil {
		return nil, fmt.Errorf("admin passkeys: %w", err)
	}
	h.wa = wa
	h.admin = h.AdminMux()
	h.node = h.NodeMux()
	return h, nil
}

// dbLookup answers registry lookups straight from the database: only
// approved nodes exist as far as transport is concerned.
type dbLookup struct{ db *db.DB }

func (l dbLookup) LookupSPKI(h devicekey.SPKIHash) (transport.DeviceInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n, err := l.db.NodeBySPKI(ctx, h)
	if err != nil || n.Status != db.StatusApproved || n.Signature == "" {
		return transport.DeviceInfo{}, false
	}
	return transport.DeviceInfo{ID: transport.DeviceID(n.ID), HardwareBound: n.HardwareBound}, true
}

// Lookup exposes the node lookup for the mTLS listener.
func (h *Handlers) Lookup() transport.DeviceLookup { return h.lookup }

// Root dispatches by TLS server name: connections that negotiated the node
// server name (and therefore presented a device certificate, enforced by
// the TLS configuration) reach the node API, everything else the admin API.
// A request without TLS (tests, a dev listener) is treated as admin.
func (h *Handlers) Root(nodeServerName string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && r.TLS.ServerName == nodeServerName {
			if len(r.TLS.PeerCertificates) == 0 {
				writeError(w, http.StatusUnauthorized, "device certificate required")
				return
			}
			h.node.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") && h.d.SPA != nil {
			h.d.SPA.ServeHTTP(w, r)
			return
		}
		h.admin.ServeHTTP(w, r)
	})
}

// --- helpers -------------------------------------------------------------

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

func readJSON(r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// fail maps storage errors to HTTP statuses.
func fail(w http.ResponseWriter, err error, log *slog.Logger) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, db.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")
	default:
		log.Error("request failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

// audit writes to the audit stream and the log table.
func (h *Handlers) audit(ctx context.Context, stream *slog.Logger, streamName, actor, msg, deviceID string, attrs map[string]any) {
	args := []any{"actor", actor}
	if deviceID != "" {
		args = append(args, "device", deviceID)
	}
	for k, v := range attrs {
		args = append(args, k, v)
	}
	stream.Info(msg, args...)
	h.d.DB.InsertLog(ctx, db.LogEvent{Stream: streamName, Actor: actor, DeviceID: deviceID, Message: msg, Attrs: attrs})
}

func remoteIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}
