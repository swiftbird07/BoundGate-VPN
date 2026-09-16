package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
)

func TestPoliciesAndEvaluation(t *testing.T) {
	e := newEnv(t)
	e.withIdP(t, time.Hour)
	e.registerSigner()
	laptop, hub, router := e.device("laptop"), e.device("hub1"), e.device("router")
	lid := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`).NodeID
	hid := e.enroll(hub, `{"name":"hub1","roles":["hub"],"public_addr":"hub1:443"}`).NodeID
	rid := e.enroll(router, `{"name":"router","roles":["subnet-router"]}`).NodeID
	e.approve(lid, `{"fingerprint":"`+laptop.spki+`","roles":["endpoint"]}`)
	e.approve(hid, `{"fingerprint":"`+hub.spki+`","kind":"workload","roles":["hub"],"public_addr":"hub1:443"}`)
	e.approve(rid, `{"fingerprint":"`+router.spki+`","kind":"workload","roles":["subnet-router"],"prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}]}`)

	// no policies: snapshot carries none, evaluation denies
	_, snap := e.snapshot(hub, 0, "1s")
	if len(snap.Policies) != 0 {
		t.Fatalf("policies before any exist: %+v", snap.Policies)
	}
	var ev api.EvaluateResponse
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":80}`, http.StatusOK, &ev)
	if ev.Allow || ev.PolicyCount != 0 || ev.Owner != rid {
		t.Fatalf("%+v", ev)
	}

	// validation
	var vr api.ValidateResponse
	e.adminCall("POST", "/api/v1/admin/policies/validate", `{"cedar":"permit(principal, action, resource) when { nope };"}`, http.StatusOK, &vr)
	if vr.OK || vr.Error == "" {
		t.Fatalf("%+v", vr)
	}
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"broken","cedar":"permit(principal, action, resource) when { nope };"}`, http.StatusBadRequest, nil)
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"","cedar":"permit(principal, action, resource);"}`, http.StatusBadRequest, nil)
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"x","cedar":"permit(principal, action, resource);","scope":["nope"]}`, http.StatusBadRequest, nil)

	// a group policy, scoped to the hub only
	var pv api.PolicyView
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"vpn-users reach the LAN","cedar":"permit(principal in BoundGate::Group::\"vpn-users\", action, resource in BoundGate::Network::\"192.168.178.0/24\");","scope":["`+hid+`"]}`, http.StatusCreated, &pv)
	if !pv.Enabled || len(pv.Scope) != 1 || pv.CreatedBy != "bootstrap" {
		t.Fatalf("%+v", pv)
	}
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"vpn-users reach the LAN","cedar":"permit(principal, action, resource);"}`, http.StatusConflict, nil)
	v0 := snap.Version
	_, snap = e.snapshot(hub, v0, "2s")
	if snap == nil || len(snap.Policies) != 1 || snap.Policies[0].Name != "vpn-users reach the LAN" {
		t.Fatalf("hub snapshot policies: %+v", snap)
	}
	if _, rs := e.snapshot(router, v0, "300ms"); rs == nil || len(rs.Policies) != 0 {
		t.Fatalf("router received a policy scoped to the hub: %+v", rs)
	}

	// without a session the laptop is not in the group; after login it is
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":80,"enforcer":"hub1"}`, http.StatusOK, &ev)
	if ev.Allow || ev.PolicyCount != 1 {
		t.Fatalf("before login: %+v", ev)
	}
	code, b := e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
	if code != http.StatusOK {
		t.Fatalf("login start: %d %s", code, b)
	}
	var ls api.LoginStart
	_ = json.Unmarshal(b, &ls)
	if code, body := e.browser(t, ls.URL); code != http.StatusOK {
		t.Fatalf("browser: %d %s", code, body)
	}
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":80,"enforcer":"hub1"}`, http.StatusOK, &ev)
	if !ev.Allow || ev.User != "u1" || len(ev.Groups) != 1 || ev.Policies[0] != "vpn-users reach the LAN" || ev.OwnerName != "router" {
		t.Fatalf("after login: %+v", ev)
	}
	// the router's view has no policy: denied there
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":80,"enforcer":"router"}`, http.StatusOK, &ev)
	if ev.Allow || ev.PolicyCount != 0 {
		t.Fatalf("router view: %+v", ev)
	}
	// the global view (no enforcer) has every policy
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":80}`, http.StatusOK, &ev)
	if !ev.Allow {
		t.Fatalf("global view: %+v", ev)
	}
	// SNI and DNS attributes reach the policy
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"no secrets","cedar":"forbid(principal, action, resource) when { resource has sni && resource.sni like \"secret.*\" };"}`, http.StatusCreated, &pv)
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":443,"sni":"secret.lab"}`, http.StatusOK, &ev)
	if ev.Allow || ev.Policies[0] != "no secrets" {
		t.Fatalf("sni: %+v", ev)
	}
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":443,"sni":"public.lab","proto":"tcp"}`, http.StatusOK, &ev)
	if !ev.Allow {
		t.Fatalf("other sni: %+v", ev)
	}
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":443,"proto":"bogus"}`, http.StatusBadRequest, nil)
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"nobody","dst":"192.168.178.10"}`, http.StatusBadRequest, nil)

	// update: disable, widen scope; list; delete
	body, _ := json.Marshal(api.PolicyBody{Name: "no secrets", Cedar: pv.Cedar, Enabled: boolp(false)})
	e.adminCall("PUT", "/api/v1/admin/policies/"+pv.ID, string(body), http.StatusOK, &pv)
	if pv.Enabled {
		t.Fatal("still enabled")
	}
	e.adminCall("POST", "/api/v1/admin/acl/evaluate", `{"node":"laptop","dst":"192.168.178.10","port":443,"sni":"secret.lab"}`, http.StatusOK, &ev)
	if !ev.Allow {
		t.Fatalf("disabled policy still applied: %+v", ev)
	}
	var list []api.PolicyView
	e.adminCall("GET", "/api/v1/admin/policies", "", http.StatusOK, &list)
	if len(list) != 2 {
		t.Fatalf("list %d", len(list))
	}
	e.adminCall("PUT", "/api/v1/admin/policies/nope", string(body), http.StatusNotFound, nil)
	e.adminCall("DELETE", "/api/v1/admin/policies/"+pv.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/policies/"+pv.ID, "", http.StatusNotFound, nil)
	e.adminCall("GET", "/api/v1/admin/policies", "", http.StatusOK, &list)
	if len(list) != 1 {
		t.Fatalf("list after delete %d", len(list))
	}
	var logs []db.LogEvent
	e.adminCall("GET", "/api/v1/admin/logs?stream=audit", "", http.StatusOK, &logs)
	var msgs []string
	for _, l := range logs {
		msgs = append(msgs, l.Message)
	}
	joined := strings.Join(msgs, ",")
	for _, m := range []string{"policy created", "policy updated", "policy deleted"} {
		if !strings.Contains(joined, m) {
			t.Fatalf("audit missing %q: %v", m, msgs)
		}
	}
}

func boolp(b bool) *bool { return &b }

func TestLogShipping(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	laptop, hub := e.device("laptop"), e.device("hub1")
	lid := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`).NodeID
	hid := e.enroll(hub, `{"name":"hub1","roles":["hub"],"public_addr":"hub1:443"}`).NodeID
	if code, _ := e.nodeCall(laptop, "POST", "/api/v1/node/logs", `{"events":[]}`); code != http.StatusForbidden {
		t.Fatalf("unapproved node shipped logs: %d", code)
	}
	e.approve(lid, `{"fingerprint":"`+laptop.spki+`","kind":"workload","roles":["endpoint"]}`)
	e.approve(hid, `{"fingerprint":"`+hub.spki+`","kind":"workload","roles":["hub"],"public_addr":"hub1:443"}`)

	opened := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	batch := `{"events":[
	  {"ts":"` + opened + `","stream":"tunnel","message":"open","attrs":{"tunnel":"t1","peer":"` + lid + `","peer_addr":"172.30.0.20:5000","opened_at":"` + opened + `"}},
	  {"ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","stream":"tunnel","message":"update","attrs":{"tunnel":"t1","peer":"` + lid + `","opened_at":"` + opened + `","bytes_in":100,"bytes_out":200,"packets_in":3,"packets_out":4}},
	  {"ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","stream":"flow","message":"open","attrs":{"flow":"f1","principal":"` + lid + `","node_id":"forged","src":"10.21.0.2","dst":"10.60.0.10","dport":80,"proto":"tcp","decision":"allow","policies":["web"],"user":"u1"}},
	  {"ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","stream":"flow","message":"deny","attrs":{"flow":"f2","principal":"` + lid + `","dst":"10.60.0.10","dport":22,"proto":"tcp","decision":"deny"}},
	  {"stream":"tunnel","message":"open","attrs":{"tunnel":"t2","peer":"unknown-node","opened_at":"` + opened + `"}},
	  {"stream":"bogus","message":"x"}
	]}`
	code, b := e.nodeCall(hub, "POST", "/api/v1/node/logs", batch)
	if code != http.StatusOK || !strings.Contains(string(b), `"accepted":4`) || !strings.Contains(string(b), `"rejected":2`) {
		t.Fatalf("ship: %d %s", code, b)
	}
	// a non-hub may ship flows but not tunnels
	code, b = e.nodeCall(laptop, "POST", "/api/v1/node/logs", `{"events":[{"stream":"tunnel","message":"open","attrs":{"tunnel":"t9","peer":"`+hid+`","opened_at":"`+opened+`"}},{"stream":"flow","message":"open","attrs":{"flow":"f3"}}]}`)
	if code != http.StatusOK || !strings.Contains(string(b), `"accepted":1`) {
		t.Fatalf("laptop ship: %d %s", code, b)
	}

	var tunnels []db.Tunnel
	e.adminCall("GET", "/api/v1/admin/tunnels?active=1", "", http.StatusOK, &tunnels)
	if len(tunnels) != 1 || tunnels[0].ID != "t1" || tunnels[0].HubName != "hub1" || tunnels[0].PeerName != "laptop" || tunnels[0].BytesIn != 100 || tunnels[0].PeerAddr != "172.30.0.20:5000" || tunnels[0].ClosedAt != nil {
		t.Fatalf("tunnels: %+v", tunnels)
	}
	// close, counters keep growing, a late update cannot reopen
	closeTS := time.Now().UTC().Format(time.RFC3339Nano)
	e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[{"ts":"`+closeTS+`","stream":"tunnel","message":"close","attrs":{"tunnel":"t1","peer":"`+lid+`","opened_at":"`+opened+`","reason":"peer left","bytes_in":150,"bytes_out":50}}]}`)
	e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[{"stream":"tunnel","message":"update","attrs":{"tunnel":"t1","peer":"`+lid+`","opened_at":"`+opened+`","bytes_in":10}}]}`)
	e.adminCall("GET", "/api/v1/admin/tunnels?active=1", "", http.StatusOK, &tunnels)
	if len(tunnels) != 0 {
		t.Fatalf("closed tunnel still active: %+v", tunnels)
	}
	e.adminCall("GET", "/api/v1/admin/tunnels?node=laptop", "", http.StatusOK, &tunnels)
	if len(tunnels) != 1 || tunnels[0].ClosedAt == nil || tunnels[0].CloseReason != "peer left" || tunnels[0].BytesIn != 150 || tunnels[0].BytesOut != 200 {
		t.Fatalf("closed tunnel: %+v", tunnels)
	}
	// a hub restart closes whatever it still had open
	e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[{"stream":"tunnel","message":"open","attrs":{"tunnel":"t3","peer":"`+lid+`","opened_at":"`+opened+`"}}]}`)
	e.adminCall("GET", "/api/v1/admin/tunnels?active=1", "", http.StatusOK, &tunnels)
	if len(tunnels) != 1 {
		t.Fatalf("t3 not open: %+v", tunnels)
	}
	e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[{"stream":"tunnel","message":"reset"}]}`)
	e.adminCall("GET", "/api/v1/admin/tunnels?active=1", "", http.StatusOK, &tunnels)
	if len(tunnels) != 0 {
		t.Fatalf("reset left tunnels open: %+v", tunnels)
	}
	e.adminCall("GET", "/api/v1/admin/tunnels?node=laptop", "", http.StatusOK, &tunnels)
	reasons := map[string]string{}
	for _, tn := range tunnels {
		reasons[tn.ID] = tn.CloseReason
	}
	if len(tunnels) != 2 || reasons["t3"] != "hub restarted" || reasons["t1"] != "peer left" {
		t.Fatalf("after reset: %+v", tunnels)
	}

	var flows []db.LogEvent
	e.adminCall("GET", "/api/v1/admin/flows?node=hub1", "", http.StatusOK, &flows)
	if len(flows) != 2 || flows[0].Message != "deny" || flows[1].Message != "open" || flows[1].DeviceID != hid || flows[1].Attrs["node_id"] != hid || flows[1].Attrs["node_name"] != "hub1" {
		t.Fatalf("flows: %+v", flows)
	}
	e.adminCall("GET", "/api/v1/admin/flows?principal=laptop&decision=allow", "", http.StatusOK, &flows)
	if len(flows) != 1 || flows[0].Attrs["flow"] != "f1" {
		t.Fatalf("filtered flows: %+v", flows)
	}
	e.adminCall("GET", "/api/v1/admin/flows?user=u1&dst=10.60.0.10", "", http.StatusOK, &flows)
	if len(flows) != 1 {
		t.Fatalf("user filter: %+v", flows)
	}
	var tlog []db.LogEvent // fresh: json.Unmarshal into a reused slice would merge attribute maps
	e.adminCall("GET", "/api/v1/admin/logs?stream=tunnel", "", http.StatusOK, &tlog)
	if len(tlog) != 3 || tlog[0].Message != "open" || tlog[1].Message != "close" || tlog[2].Message != "open" { // t3 open, t1 close, t1 open; no update, no reset
		t.Fatalf("tunnel log: %+v", tlog)
	}
	if _, leaked := tlog[1].Attrs["flow"]; leaked {
		t.Fatalf("flow attributes in a tunnel record: %+v", tlog[1].Attrs)
	}
	// limits
	if code, _ := e.nodeCall(hub, "POST", "/api/v1/node/logs", `{"events":[`+strings.Repeat(`{"stream":"flow","message":"open"},`, api.ShipMaxEvents)+`{"stream":"flow","message":"open"}]}`); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized batch: %d", code)
	}
}
