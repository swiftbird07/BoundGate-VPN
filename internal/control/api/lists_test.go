package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// a node gets the lists its policies name, not the others
	e.registerSigner()
	hub := e.device("hub1")
	hst := e.enroll(hub, `{}`)
	e.approve(hst.NodeID, `{"kind":"workload","roles":["hub"]}`)
	_, snap := e.snapshot(hub, 0, "1s")
	if len(snap.Lists) != 1 || snap.Lists[0].Name != "allowed-sites" || snap.Lists[0].Kind != "sni" || len(snap.Lists[0].Entries) != 2 {
		b, _ := json.Marshal(snap.Lists)
		t.Fatalf("lists in the snapshot: %s", b)
	}
	// a policy scoped to another node brings its list to that node only
	spoke := e.device("spoke1")
	sst := e.enroll(spoke, `{}`)
	e.approve(sst.NodeID, `{"kind":"workload","roles":["endpoint"]}`)
	var p2 api.PolicyView
	e.adminCall("POST", "/api/v1/admin/policies", `{"name":"p2","scope":["`+sst.NodeID+`"],"cedar":"forbid(principal, action, resource in BoundGate::List::\"blocked\");"}`, http.StatusCreated, &p2)
	_, snap = e.snapshot(hub, 0, "1s")
	if len(snap.Lists) != 1 || snap.Lists[0].Name != "allowed-sites" {
		b, _ := json.Marshal(snap.Lists)
		t.Fatalf("the hub got another node's list: %s", b)
	}
	_, snap = e.snapshot(spoke, 0, "1s")
	if len(snap.Lists) != 2 {
		b, _ := json.Marshal(snap.Lists)
		t.Fatalf("lists in the spoke's snapshot: %s", b)
	}
	// unused: delete
	e.adminCall("DELETE", "/api/v1/admin/policies/"+p2.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/policies/"+p.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/lists/"+l.ID, "", http.StatusNoContent, nil)
	e.adminCall("DELETE", "/api/v1/admin/lists/"+ipl.ID, "", http.StatusNoContent, nil)
}

// Import, export and a source the control plane follows: a list can live in
// a Git repository and come back through the API (docs/ACL.md).
func TestListImportExportAndSource(t *testing.T) {
	e := newEnv(t)
	var l api.ListView
	e.adminCall("POST", "/api/v1/admin/lists", `{"name":"from-git","kind":"ip","entries":["10.0.0.1"]}`, http.StatusCreated, &l)

	// import replaces, ?mode=add keeps what is there
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/import", "# a file\n10.1.0.0/16\n10.2.0.0/16\n", http.StatusOK, &l)
	if len(l.Entries) != 2 || l.Entries[0] != "10.1.0.0/16" {
		t.Fatalf("imported: %v", l.Entries)
	}
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/import?mode=add", `["10.3.0.0/16"]`, http.StatusOK, &l)
	if len(l.Entries) != 3 || l.Entries[2] != "10.3.0.0/16" {
		t.Fatalf("added: %v", l.Entries)
	}
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/import", "not an address\n", http.StatusBadRequest, nil)

	// export is the same file again
	body := e.adminCall("GET", "/api/v1/admin/lists/"+l.ID+"/export", "", http.StatusOK, nil)
	for _, want := range []string{`# BoundGate list "from-git" (ip)`, "10.1.0.0/16\n", "10.3.0.0/16\n"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("export without %q: %s", want, body)
		}
	}

	// a source: the control plane fetches it and never sends the secret back
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Private-Token") != "s3cret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("10.9.0.0/16\n"))
	}))
	defer srv.Close()
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.0.0.1"],"source_url":"`+srv.URL+`","source_interval":300,"source_header":"Private-Token","source_secret":"s3cret"}`, http.StatusOK, &l)
	if l.SourceURL != srv.URL || l.SourceInterval != 300 || !l.SourceSecretSet {
		t.Fatalf("source not stored: %+v", l)
	}
	if strings.Contains(string(e.adminCall("GET", "/api/v1/admin/lists/"+l.ID, "", http.StatusOK, nil)), "s3cret") {
		t.Fatal("the answer carries the source secret")
	}
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/fetch", "", http.StatusOK, &l)
	if len(l.Entries) != 1 || l.Entries[0] != "10.9.0.0/16" || l.SourceStatus != "" || l.SourceFetchedAt == nil {
		t.Fatalf("after the fetch: %+v", l)
	}
	// a PUT without source_secret keeps it; the secret still works
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.0.0.1"],"source_url":"`+srv.URL+`","source_interval":300,"source_header":"Private-Token"}`, http.StatusOK, &l)
	if !l.SourceSecretSet {
		t.Fatal("the secret was dropped by a PUT that did not mention it")
	}
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/fetch", "", http.StatusOK, &l)
	if len(l.Entries) != 1 || l.Entries[0] != "10.9.0.0/16" {
		t.Fatalf("fetch after the PUT: %+v", l.Entries)
	}
	// another query on the same file keeps it too
	var requery api.ListView
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.0.0.1"],"source_url":"`+srv.URL+`/?ref=main","source_interval":300,"source_header":"Private-Token"}`, http.StatusOK, &requery)
	if !requery.SourceSecretSet || requery.SourceHeader != "Private-Token" {
		t.Fatalf("the secret was dropped for another query: %+v", requery)
	}
	// another path or host does not: the secret belongs to the URL it was
	// entered for, and an admin who changes the URL must enter it again
	for _, other := range []string{srv.URL + "/other.txt", "https://example.test/"} {
		e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.0.0.1"],"source_url":"`+srv.URL+`","source_interval":300,"source_header":"Private-Token","source_secret":"s3cret"}`, http.StatusOK, &l)
		var moved api.ListView
		e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.0.0.1"],"source_url":"`+other+`","source_interval":300,"source_header":"Private-Token"}`, http.StatusOK, &moved)
		if moved.SourceURL != other || moved.SourceSecretSet || moved.SourceHeader != "" {
			t.Fatalf("%s: the secret went along to another URL: %+v", other, moved)
		}
	}
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.0.0.1"],"source_url":"`+srv.URL+`","source_interval":300,"source_header":"Private-Token","source_secret":"s3cret"}`, http.StatusOK, &l)
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/fetch", "", http.StatusOK, &l)

	// a source that refuses: the list keeps its entries, the reason is in it
	e.adminCall("PUT", "/api/v1/admin/lists/"+l.ID, `{"name":"from-git","kind":"ip","entries":["10.9.0.0/16"],"source_url":"`+srv.URL+`","source_interval":300,"source_header":"Private-Token","source_secret":""}`, http.StatusOK, &l)
	e.adminCall("POST", "/api/v1/admin/lists/"+l.ID+"/fetch", "", http.StatusBadGateway, nil)
	e.adminCall("GET", "/api/v1/admin/lists/"+l.ID, "", http.StatusOK, &l)
	if len(l.Entries) != 1 || l.Entries[0] != "10.9.0.0/16" || !strings.Contains(l.SourceStatus, "403") {
		t.Fatalf("after a refused fetch: %+v", l)
	}
	// a list without a source cannot be fetched, and a bad url is refused
	var plain api.ListView
	e.adminCall("POST", "/api/v1/admin/lists", `{"name":"plain","kind":"dns","entries":["example.com"]}`, http.StatusCreated, &plain)
	e.adminCall("POST", "/api/v1/admin/lists/"+plain.ID+"/fetch", "", http.StatusBadRequest, nil)
	e.adminCall("PUT", "/api/v1/admin/lists/"+plain.ID, `{"name":"plain","kind":"dns","entries":[],"source_url":"file:///etc/passwd","source_interval":300}`, http.StatusBadRequest, nil)
	e.adminCall("PUT", "/api/v1/admin/lists/"+plain.ID, `{"name":"plain","kind":"dns","entries":[],"source_url":"https://example.test/x","source_interval":5}`, http.StatusBadRequest, nil)
}
