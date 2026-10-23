package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/snapshot"
)

// A flow record is what the reporting node says about others. The control
// plane stamps who reported it, names the principal and the owner from the
// registry instead of taking the reporter's names, and links a session
// only when it is the principal's (R47).
func TestShippedFlowsAreTheReportersWord(t *testing.T) {
	e := newEnv(t)
	e.withIdP(t, time.Hour)
	e.registerSigner()
	laptop, hub := e.device("laptop"), e.device("hub1")
	lid := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`).NodeID
	hid := e.enroll(hub, `{"name":"hub1","roles":["hub"]}`).NodeID
	e.approve(lid, `{"roles":["endpoint"]}`)
	e.approve(hid, `{"kind":"workload","roles":["hub"],"public_addr":"hub1:443"}`)

	// the laptop's user signs in: a session of the laptop
	code, b := e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	if code != http.StatusOK {
		t.Fatalf("login start: %d %s", code, b)
	}
	var ls api.LoginStart
	_ = json.Unmarshal(b, &ls)
	if code, page := e.browser(t, ls.URL); code != http.StatusOK {
		t.Fatalf("login: %d %s", code, page)
	}
	_, b = e.nodeCall(laptop, "GET", "/api/v1/node/login/"+ls.FlowID+"?wait=0s", "")
	var st api.LoginStatus
	_ = json.Unmarshal(b, &st)
	if st.Session == nil {
		t.Fatalf("no session: %s", b)
	}
	sess := st.Session.ID

	batch := `{"events":[
		{"stream":"flow","message":"open","attrs":{"flow":"f1","principal":"` + lid + `","principal_name":"the CEO's laptop","owner":"` + hid + `","owner_name":"bank","session":"` + sess + `","node_id":"forged","reported_by":"forged"}},
		{"stream":"flow","message":"open","attrs":{"flow":"f2","principal":"` + hid + `","principal_name":"somebody","session":"` + sess + `"}},
		{"stream":"flow","message":"open","attrs":{"flow":"f3","principal":"no-such-node","principal_name":"laptop"}}]}`
	if code, b := e.nodeCall(hub, "POST", "/api/v1/node/logs", batch); code != http.StatusOK {
		t.Fatalf("ship: %d %s", code, b)
	}
	var flows []db.LogEvent
	e.adminCall("GET", "/api/v1/admin/flows?node=hub1", "", http.StatusOK, &flows)
	byFlow := map[string]db.LogEvent{}
	for _, f := range flows {
		byFlow[f.Attrs["flow"].(string)] = f
	}
	f1, f2, f3 := byFlow["f1"], byFlow["f2"], byFlow["f3"]
	if f1.Attrs["reported_by"] != hid || f1.Attrs["node_id"] != hid || f1.DeviceID != hid {
		t.Fatalf("reporter not stamped: %+v", f1)
	}
	// the principal stays what the reporter said; its name is the registry's
	if f1.Attrs["principal"] != lid || f1.Attrs["principal_name"] != "laptop" || f1.Attrs["owner_name"] != "hub1" {
		t.Fatalf("names: %+v", f1.Attrs)
	}
	if f1.SessionID != sess {
		t.Fatalf("the principal's own session was not linked: %+v", f1)
	}
	if f2.Attrs["principal_name"] != "hub1" || f2.SessionID != "" {
		t.Fatalf("another node's session was linked to a flow: %+v", f2)
	}
	if _, named := f3.Attrs["principal_name"]; named || f3.Attrs["principal"] != "no-such-node" {
		t.Fatalf("an unknown principal got a name: %+v", f3.Attrs)
	}
}

// A node may ship ShipBatchesPerMinute batches in a burst, then waits.
func TestLogShippingIsRateLimited(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	hub, other := e.device("hub1"), e.device("hub2")
	hid := e.enroll(hub, `{"name":"hub1","roles":["hub"]}`).NodeID
	oid := e.enroll(other, `{"name":"hub2","roles":["hub"]}`).NodeID
	e.approve(hid, `{"kind":"workload","roles":["hub"],"public_addr":"hub1:443"}`)
	e.approve(oid, `{"kind":"workload","roles":["hub"],"public_addr":"hub2:443"}`)
	for i := 0; i < api.ShipBatchesPerMinute; i++ {
		if code, b := e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[]}`); code != http.StatusOK {
			t.Fatalf("batch %d: %d %s", i, code, b)
		}
	}
	if code, _ := e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[]}`); code != http.StatusTooManyRequests {
		t.Fatalf("batch beyond the limit: %d", code)
	}
	// per node, not for everyone
	if code, b := e.nodeCall(other, "POST", "/api/v1/node/logs", `{"events":[]}`); code != http.StatusOK {
		t.Fatalf("another node was limited too: %d %s", code, b)
	}
}

// A hub's deny record that says a sign-in would have permitted the flow
// reaches the principal, once, in the answer to its heartbeat; nothing
// reaches another node, and nothing comes of a record without the flag or
// for a principal the registry does not know.
func TestASignInHintReachesItsDeviceOnce(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	laptop, phone, hub := e.device("laptop"), e.device("phone"), e.device("hub1")
	lid := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`).NodeID
	pid := e.enroll(phone, `{"name":"phone","roles":["endpoint"]}`).NodeID
	hid := e.enroll(hub, `{"name":"hub1","roles":["hub"]}`).NodeID
	e.approve(lid, `{"roles":["endpoint"]}`)
	e.approve(pid, `{"roles":["endpoint"]}`)
	e.approve(hid, `{"kind":"workload","roles":["hub"],"public_addr":"hub1:443"}`)

	beat := func(d dev) (int, api.HeartbeatReply) {
		code, b := e.nodeCall(d, "POST", "/api/v1/node/heartbeat", `{"version":1,"active_tunnels":0}`)
		var r api.HeartbeatReply
		if len(b) > 0 {
			_ = json.Unmarshal(b, &r)
		}
		return code, r
	}
	if code, _ := beat(laptop); code != http.StatusNoContent {
		t.Fatalf("heartbeat with nothing to say: %d", code)
	}
	batch := `{"events":[
		{"stream":"flow","message":"deny","attrs":{"flow":"f1","principal":"` + lid + `","dst":"192.168.178.10","dport":443,"proto":"tcp","sni":"nas.home","sign_in":true}},
		{"stream":"flow","message":"deny","attrs":{"flow":"f2","principal":"` + pid + `","dst":"192.168.178.11","dport":22,"proto":"tcp"}},
		{"stream":"flow","message":"deny","attrs":{"flow":"f3","principal":"no-such-node","dst":"10.0.0.1","dport":80,"proto":"tcp","sign_in":true}}]}`
	if code, b := e.nodeCall(hub, "POST", "/api/v1/node/logs", batch); code != http.StatusOK {
		t.Fatalf("ship: %d %s", code, b)
	}
	code, r := beat(laptop)
	if code != http.StatusOK || r.SignIn == nil {
		t.Fatalf("the laptop got no hint: %d %+v", code, r)
	}
	if h := r.SignIn; h.Dst != "192.168.178.10" || h.Port != 443 || h.Proto != "tcp" || h.Name != "nas.home" || h.Via != "hub1" {
		t.Fatalf("hint: %+v", h)
	}
	if code, _ := beat(laptop); code != http.StatusNoContent {
		t.Fatal("the hint came twice")
	}
	if code, _ := beat(phone); code != http.StatusNoContent {
		t.Fatal("a deny without the flag became a hint")
	}
}

// A flow decision a node reports also goes to the control plane's own flow
// log, where whatever collects logs for a SIEM finds it: a spoke at the far
// end of a path has no collector of its own (#17). By default the denies
// only; `all` writes every record, `off` none. Names are the registry's, as
// in the database.
func TestReportedFlowsReachTheControlPlanesFlowLog(t *testing.T) {
	for _, tc := range []struct {
		mode api.NodeFlowLog
		want []string
	}{
		{"", []string{"flow deny"}},
		{api.NodeFlowsAll, []string{"flow open", "flow deny", "flow close"}},
		{api.NodeFlowsOff, nil},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			e := newEnv(t)
			e.handlers = api.New(api.Deps{DB: e.store, Snap: snapshot.New(e.store), Logs: e.logs, NodeFlows: tc.mode})
			e.admin.Config.Handler = e.handlers.AdminMux()
			e.node.Config.Handler = e.handlers.NodeMux()
			e.registerSigner()
			router, laptop := e.device("orkus"), e.device("laptop")
			rid := e.enroll(router, `{"name":"orkus","roles":["subnet-router"]}`).NodeID
			lid := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`).NodeID
			e.approve(rid, `{"kind":"workload","roles":["subnet-router"]}`)
			e.approve(lid, `{"roles":["endpoint"]}`)

			batch := `{"events":[
				{"stream":"flow","message":"open","attrs":{"flow":"f1","principal":"` + lid + `","dst":"192.168.3.20:443"}},
				{"stream":"flow","message":"deny","ts":"2026-10-23T06:00:00Z","attrs":{"flow":"f2","principal":"` + lid + `","principal_name":"forged","dst":"192.168.3.20:22","reason":"no permit"}},
				{"stream":"flow","message":"close","attrs":{"flow":"f1","principal":"` + lid + `"}},
				{"stream":"tunnel","message":"reset"}]}`
			if code, b := e.nodeCall(router, "POST", "/api/v1/node/logs", batch); code != http.StatusOK {
				t.Fatalf("ship: %d %s", code, b)
			}
			raw, err := os.ReadFile(filepath.Join(filepath.Dir(e.dbPath), "logs", "flow.jsonl"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			var got []string
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if line == "" {
					continue
				}
				var rec map[string]any
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("%q: %v", line, err)
				}
				got = append(got, rec["msg"].(string))
				if rec["node_name"] != "orkus" || rec["reported_by"] != rid || rec["principal_name"] != "laptop" {
					t.Fatalf("not the registry's names: %s", line)
				}
				if rec["msg"] == "flow deny" && (rec["event_time"] != "2026-10-23T06:00:00Z" || rec["reason"] != "no permit" || rec["dst"] != "192.168.3.20:22") {
					t.Fatalf("the node's fields did not come through: %s", line)
				}
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("flow log %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := api.ParseNodeFlowLog("denies"); err == nil {
		t.Fatal("an unknown setting was taken")
	}
}
