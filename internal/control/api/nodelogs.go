package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
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

// ShipBatchesPerMinute bounds how often one node may ship. A node sends a
// batch every 5 s and drains what it buffered during an outage (at most 5
// batches) at once.
const ShipBatchesPerMinute = 30

// ShipBytesPerMinute bounds how much one node may ship: the batches above
// are small, and the budget lets a few full ones through after an outage
// without letting one node write the database full at 4 MiB a batch (R146).
const ShipBytesPerMinute = 16 << 20

// NodeFlowLog is which of the flow decisions that nodes report the control
// plane writes to its own flow log as well (`log_node_flows`).
//
// Every node writes its decisions to its own log, but whatever collects logs
// for a SIEM collects them on the machines it runs on. A spoke that decides
// at the far end of a path -- a subnet router in someone else's network --
// has no such collector, and its denies existed only in the database behind
// the admin UI (#17). The control plane's own log is collected wherever it
// runs, so it is the one place that holds the decisions of every node. A
// node's records keep its name (`node_name`, `reported_by`) and get the
// principal's and owner's names from the registry; `component: control`
// tells them apart from the same records in a hub's own log.
type NodeFlowLog string

const (
	// NodeFlowsDeny writes the refusals: few, and the ones that matter.
	NodeFlowsDeny NodeFlowLog = "deny"
	// NodeFlowsAll writes every open, deny and close.
	NodeFlowsAll NodeFlowLog = "all"
	// NodeFlowsOff writes none of them.
	NodeFlowsOff NodeFlowLog = "off"
)

// ParseNodeFlowLog reads the setting; empty is the default, deny.
func ParseNodeFlowLog(s string) (NodeFlowLog, error) {
	switch NodeFlowLog(s) {
	case "":
		return NodeFlowsDeny, nil
	case NodeFlowsDeny, NodeFlowsAll, NodeFlowsOff:
		return NodeFlowLog(s), nil
	}
	return "", fmt.Errorf("log_node_flows: %q is not deny, all or off", s)
}

// logs says whether a reported event of this kind goes to the flow log.
func (m NodeFlowLog) logs(event string) bool {
	switch m {
	case NodeFlowsAll:
		return true
	case NodeFlowsOff:
		return false
	}
	return event == "deny" // the default, also for a zero value
}

// nodeShipLogs stores flow records and tunnel reports of an approved node.
// The reporter is authenticated by mTLS; its id overrides whatever the
// records claim and is kept as reported_by. What a record says about
// others (principal, user, session) is the reporter's word: the control
// plane names the principal and the owner from its own registry and links
// a session only when it belongs to that principal, but it cannot know
// whether the flow happened (R47). A tunnel is reported by the node that
// accepted it: a hub, or since M7 a spoke that a peer reached directly or
// through a relay.
func (h *Handlers) nodeShipLogs(w http.ResponseWriter, r *http.Request) {
	peer, ok := h.approvedPeer(w, r)
	if !ok {
		return
	}
	if !h.shipLimit.allow(string(peer.DeviceID())) {
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusTooManyRequests, "too many log batches from this node; try again later")
		return
	}
	// the bytes as well as the batches: a batch may be large once in a
	// while (an outage drained), not thirty times a minute (R146)
	raw, err := io.ReadAll(io.LimitReader(r.Body, ShipMaxBytes+1))
	if err != nil || len(raw) > ShipMaxBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "the batch is too large")
		return
	}
	if !h.shipBytes.allowN(string(peer.DeviceID()), float64(len(raw))) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many log bytes from this node; try again later")
		return
	}
	var body ShipRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
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
	names := map[string]string{self.ID: self.Name} // node id → name, "" unknown
	nodeName := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		n, err := h.d.DB.NodeByID(r.Context(), id)
		if err != nil {
			names[id] = ""
			return ""
		}
		names[id] = n.Name
		return n.Name
	}
	sessionOf := map[string]string{} // session id → node id, "" unknown
	var rows []db.LogEvent
	accepted, rejected := 0, 0
	for _, ev := range body.Events {
		if ev.Attrs == nil {
			ev.Attrs = map[string]any{}
		}
		boundAttrs(ev.Attrs)
		ev.Attrs["node_id"] = self.ID
		ev.Attrs["node_name"] = self.Name
		ev.Attrs["reported_by"] = self.ID
		if ev.TS.IsZero() || ev.TS.After(time.Now().Add(5*time.Minute)) {
			ev.TS = time.Now().UTC()
		}
		switch ev.Stream {
		case ShipStreamFlow:
			// names come from the registry, not from the reporter
			for _, k := range [][2]string{{"principal", "principal_name"}, {"owner", "owner_name"}} {
				delete(ev.Attrs, k[1])
				if id, _ := ev.Attrs[k[0]].(string); id != "" {
					if n := nodeName(id); n != "" {
						ev.Attrs[k[1]] = n
					}
				}
			}
			sess, _ := ev.Attrs["session"].(string)
			principal, _ := ev.Attrs["principal"].(string)
			if sess != "" {
				owner, seen := sessionOf[sess]
				if !seen {
					if s, err := h.d.DB.SessionByID(r.Context(), sess); err == nil {
						owner = s.NodeID
					}
					sessionOf[sess] = owner
				}
				if owner == "" || owner != principal {
					sess = "" // not linked: the session is not the principal's
				}
			}
			if p, hint, ok := hintFrom(ev, self.Name); ok {
				h.signIn.note(p, hint)
			}
			rows = append(rows, db.LogEvent{TS: ev.TS, Stream: ShipStreamFlow, Actor: "node", DeviceID: self.ID, SessionID: sess, Message: clip(ev.Message, 64), Attrs: ev.Attrs})
			if h.d.NodeFlows.logs(ev.Message) && h.d.Logs != nil && h.d.Logs.Flow != nil {
				logNodeFlow(h.d.Logs.Flow, ev, sess)
			}
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
				h.d.Logs.System.Warn("tunnel report", "node", self.ID, "err", err)
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

// logNodeFlow writes one reported decision the way the node wrote it --
// "flow deny" and the node's fields -- with the time the node saw it, the
// session only when it is the principal's, and the names the registry gives.
func logNodeFlow(l *slog.Logger, ev ShippedEvent, sess string) {
	keys := make([]string, 0, len(ev.Attrs))
	for k := range ev.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	args := make([]any, 0, 2*len(keys)+4)
	args = append(args, "event_time", ev.TS.UTC().Format(time.RFC3339Nano))
	for _, k := range keys {
		if k == "session" {
			continue
		}
		if reservedLogKey(k) {
			// slog writes a duplicate key as it is, and whatever reads
			// the file takes the last one: a node could otherwise write
			// its own "level", "msg" or "time" into the control plane's
			// record (R146)
			k = "node_" + k
		}
		args = append(args, k, ev.Attrs[k])
	}
	if sess != "" {
		args = append(args, "session", sess)
	}
	l.Info("flow "+clip(ev.Message, 64), args...)
}

// reservedLogKey says whether k is a key the control plane's own log line
// carries, which a reported attribute must not take over.
func reservedLogKey(k string) bool {
	switch k {
	case slog.TimeKey, slog.LevelKey, slog.MessageKey, slog.SourceKey, "stream", "component", "event_time", "session":
		return true
	}
	return false
}

// Bounds on what one reported event may carry. The node's own records are a
// few dozen short attributes; a node that sends more sends it to fill the
// database (R146).
const (
	shipMaxAttrs    = 64
	shipMaxString   = 512
	shipMaxListed   = 32
	shipMaxListItem = 253 // a host name
)

// boundAttrs cuts a reported event's attributes to size: at most
// shipMaxAttrs keys (the rest dropped, by sorted name, so that the result
// is the same whichever order they came in), strings to shipMaxString, lists
// to shipMaxListed strings, and nothing nested.
func boundAttrs(attrs map[string]any) {
	if len(attrs) > shipMaxAttrs {
		keys := make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[shipMaxAttrs:] {
			delete(attrs, k)
		}
	}
	for k, v := range attrs {
		switch v := v.(type) {
		case string:
			attrs[k] = clip(v, shipMaxString)
		case []any:
			if len(v) > shipMaxListed {
				v = v[:shipMaxListed]
			}
			for i, item := range v {
				switch item := item.(type) {
				case string:
					v[i] = clip(item, shipMaxListItem)
				case float64, bool, nil:
				default:
					v[i] = nil
				}
			}
			attrs[k] = v
		case map[string]any:
			delete(attrs, k)
		}
	}
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
