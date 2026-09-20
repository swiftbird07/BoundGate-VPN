package api

import (
	"net/http"
	"strconv"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/logging"
)

// Streams a node may ship.
const (
	ShipStreamFlow   = logging.StreamFlow
	ShipStreamTunnel = "tunnel"
)

// ShippedEvent is one log record a node sends to the control plane.
type ShippedEvent struct {
	TS      time.Time      `json:"ts"`
	Stream  string         `json:"stream"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// ShipRequest is the body of POST /node/logs.
type ShipRequest struct {
	Events []ShippedEvent `json:"events"`
}

// ShipLimits bound one batch.
const (
	ShipMaxEvents = 2000
	ShipMaxBytes  = 4 << 20
)

// nodeShipLogs stores flow records and tunnel reports of an approved node.
// The reporter is authenticated by mTLS; its id overrides whatever the
// records claim. A tunnel is reported by the node that accepted it: a hub,
// or since M7 a spoke that a peer reached directly or through a relay.
func (h *Handlers) nodeShipLogs(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	var body ShipRequest
	if err := readJSON(r, &body, ShipMaxBytes); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(body.Events) > ShipMaxEvents {
		writeError(w, http.StatusRequestEntityTooLarge, "too many events")
		return
	}
	self, err := h.d.DB.NodeByID(r.Context(), string(peer.DeviceID()))
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	var rows []db.LogEvent
	accepted, rejected := 0, 0
	for _, ev := range body.Events {
		if ev.Attrs == nil {
			ev.Attrs = map[string]any{}
		}
		ev.Attrs["node_id"] = self.ID
		ev.Attrs["node_name"] = self.Name
		if ev.TS.IsZero() || ev.TS.After(time.Now().Add(5*time.Minute)) {
			ev.TS = time.Now().UTC()
		}
		switch ev.Stream {
		case ShipStreamFlow:
			sess, _ := ev.Attrs["session"].(string)
			rows = append(rows, db.LogEvent{TS: ev.TS, Stream: ShipStreamFlow, Actor: "node", DeviceID: self.ID, SessionID: sess, Message: clip(ev.Message, 64), Attrs: ev.Attrs})
			accepted++
		case ShipStreamTunnel:
			if ev.Message == "reset" {
				// the hub (re)started: whatever it had is gone
				if _, err := h.d.DB.CloseHubTunnels(r.Context(), self.ID, "hub restarted"); err != nil {
					h.d.Logs.System.Warn("tunnel reset", "err", err)
				}
				accepted++
				continue
			}
			rep, ok := tunnelReport(self.ID, ev)
			if !ok {
				rejected++
				continue
			}
			peer, err := h.d.DB.NodeByID(r.Context(), rep.PeerID)
			if err != nil || rep.PeerID == self.ID {
				rejected++
				continue
			}
			// a revoked node and its hub both learn of the revocation from
			// their snapshots; whichever closes first, the cause is the same
			if ev.Message == "close" && rep.CloseReason == "closed by peer" && peer.Status == "revoked" {
				rep.CloseReason = "peer revoked"
			}
			if err := h.d.DB.UpsertTunnel(r.Context(), rep); err != nil {
				h.d.Logs.System.Warn("tunnel report", "err", err)
				rejected++
				continue
			}
			if ev.Message != "update" {
				rows = append(rows, db.LogEvent{TS: ev.TS, Stream: ShipStreamTunnel, Actor: "node", DeviceID: self.ID, GatewayID: rep.PeerID, Message: clip(ev.Message, 64), Attrs: ev.Attrs})
			}
			accepted++
		default:
			rejected++
		}
	}
	if len(rows) > 0 {
		if err := h.d.DB.InsertLogs(r.Context(), rows); err != nil {
			fail(w, err, h.d.Logs.System)
			return
		}
	}
	h.d.DB.TouchNode(r.Context(), self.ID)
	writeJSON(w, http.StatusOK, map[string]int{"accepted": accepted, "rejected": rejected})
}

func tunnelReport(hubID string, ev ShippedEvent) (db.TunnelReport, bool) {
	str := func(k string) string { s, _ := ev.Attrs[k].(string); return clip(s, 128) }
	num := func(k string) uint64 {
		switch v := ev.Attrs[k].(type) {
		case float64:
			if v < 0 {
				return 0
			}
			return uint64(v)
		case string:
			n, _ := strconv.ParseUint(v, 10, 64)
			return n
		}
		return 0
	}
	ts := func(k string) time.Time {
		t, _ := time.Parse(time.RFC3339Nano, str(k))
		return t
	}
	rep := db.TunnelReport{ID: str("tunnel"), HubID: hubID, PeerID: str("peer"), PeerAddr: str("peer_addr"), Transport: str("transport"), OpenedAt: ts("opened_at"), ClosedAt: ts("closed_at"),
		CloseReason: str("reason"), BytesIn: num("bytes_in"), BytesOut: num("bytes_out"), PacketsIn: num("packets_in"), PacketsOut: num("packets_out")}
	if rep.ID == "" || rep.PeerID == "" || rep.OpenedAt.IsZero() {
		return db.TunnelReport{}, false
	}
	if ev.Message == "close" && rep.ClosedAt.IsZero() {
		rep.ClosedAt = ev.TS
	}
	return rep, true
}

func (h *Handlers) adminListTunnels(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tq := db.TunnelQuery{Node: q.Get("node"), Active: q.Get("active") == "1" || q.Get("active") == "true"}
	if v := q.Get("since"); v != "" {
		tq.Since, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("limit"); v != "" {
		tq.Limit, _ = strconv.Atoi(v)
	}
	if n, ok := h.resolveNode(r, tq.Node); ok {
		tq.Node = n.ID
	}
	ts, err := h.d.DB.ListTunnels(r.Context(), tq)
	if err != nil {
		fail(w, err, h.d.Logs.System)
		return
	}
	if ts == nil {
		ts = []db.Tunnel{}
	}
	writeJSON(w, http.StatusOK, ts)
}

// adminFlows lists shipped flow records: ?node= (reporter), ?principal=
// (originating node), ?user=, ?decision=allow|deny, ?event=open|deny|close,
// ?dst=, ?from=, ?to=, ?before=, ?limit=.
func (h *Handlers) adminFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lq := db.LogQuery{Stream: logging.StreamFlow, Attrs: map[string]string{}}
	if n, ok := h.resolveNode(r, q.Get("node")); ok {
		lq.DeviceID = n.ID
	} else if v := q.Get("node"); v != "" {
		lq.DeviceID = v
	}
	if n, ok := h.resolveNode(r, q.Get("principal")); ok {
		lq.Attrs["principal"] = n.ID
	} else if v := q.Get("principal"); v != "" {
		lq.Attrs["principal"] = v
	}
	for _, k := range []string{"user", "decision", "dst", "sni", "dns_name"} {
		if v := q.Get(k); v != "" {
			lq.Attrs[k] = v
		}
	}
	if v := q.Get("event"); v != "" {
		lq.Text = "" // message filter below
		lq.Attrs["event"] = v
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
