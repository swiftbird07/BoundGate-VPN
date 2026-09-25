package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
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
