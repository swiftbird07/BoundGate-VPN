package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
)

func TestListsAndPolicyGroups(t *testing.T) {
	e := newEnv(t)
	var l api.ListView
	e.adminCall("POST", "/api/v1/admin/lists", `{"name":" Allowed-Sites ","kind":"sni","description":"the few","entries":["myip.wtf","# a comment","","*.GitHub.com","myip.wtf"]}`, http.StatusCreated, &l)
	if l.Name != "allowed-sites" || len(l.Entries) != 2 || l.Entries[0] != "*.github.com" || l.Entries[1] != "myip.wtf" {
		t.Fatalf("cleaned list: %+v", l)
	}
	for _, bad := range []string{`{"name":"x","kind":"ip","entries":["not an address"]}`, `{"name":"x","kind":"dns","entries":["a.*.b"]}`, `{"name":"x","kind":"tcp","entries":[]}`, `{"name":"Has Space","kind":"ip","entries":[]}`} {
		e.adminCall("POST", "/api/v1/admin/lists", bad, http.StatusBadRequest, nil)
	}
	e.adminCall("POST", "/api/v1/admin/lists", `{"name":"allowed-sites","kind":"ip","entries":[]}`, http.StatusConflict, nil)
	var ipl api.ListView
	e.adminCall("POST", "/api/v1/admin/lists", `{"name":"blocked","kind":"ip","entries":["10.60.0.11","10.60.0.128/25"]}`, http.StatusCreated, &ipl)
	if ipl.Entries[0] != "10.60.0.11/32" || ipl.Entries[1] != "10.60.0.128/25" {
		t.Fatalf("ip entries: %v", ipl.Entries)
	}

	// a policy may only name lists that exist; it is grouped for the UI
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"p1","cedar":"permit(principal, action, resource in BoundGate::List::\"nope\");"}`, http.StatusBadRequest, nil)
	var p api.PolicyView
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"p1","group":"NAS","cedar":"permit(principal, action, resource in BoundGate::List::\"allowed-sites\");"}`, http.StatusCreated, &p)
	if p.Group != "NAS" {
		t.Fatalf("group: %+v", p)
	}
	var got api.ListView
	e.adminCall("GET", "/api/v1/admin/lists/"+l.ID, "", http.StatusOK, &got)
	if len(got.UsedBy) != 1 || got.UsedBy[0] != "p1" {
		t.Fatalf("used_by: %+v", got.UsedBy)
	}
	// a list in use keeps its name and kind and cannot be deleted; its entries can change
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"other","kind":"sni","entries":["myip.wtf"]}`, http.StatusConflict, nil)
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"allowed-sites","kind":"dns","entries":["myip.wtf"]}`, http.StatusConflict, nil)
	e.adminCall("DELETE", "/api/v1/admin/lists/"+l.ID, "", http.StatusConflict, nil)
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"allowed-sites","kind":"sni","entries":["myip.wtf","ifconfig.co"]}`, http.StatusOK, &got)
	if len(got.Entries) != 2 {
		t.Fatalf("entries after update: %v", got.Entries)
	}
	// the lists travel in every snapshot
	e.registerSigner()
	hub := e.device("hub1")
	hst := e.enroll(hub, `{}`)
	e.approve(hst.NodeID, `{"kind":"workload","roles":["hub"]}`)
	_, snap := e.snapshot(hub, 0, "1s")
	if len(snap.Lists) != 2 || snap.Lists[0].Name != "allowed-sites" || snap.Lists[0].Kind != "sni" || len(snap.Lists[0].Entries) != 2 {
		b, _ := json.Marshal(snap.Lists)
		t.Fatalf("lists in the snapshot: %s", b)
	}
	// unused: delete
	e.adminCall("DELETE", "/api/v1/admin/policies/"+p.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/lists/"+l.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/lists/"+ipl.ID, "", http.StatusNoContent, nil)
}
