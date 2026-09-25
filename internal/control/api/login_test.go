package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/api"
)

// A user login is phishable if the callback completes it: whoever controls
// an approved node can send its login link to someone else, who signs in
// at the IdP (often without a prompt) and gives the node their identity.
// The callback therefore only asks; the node sees pending until the person
// pressed "Sign in this device" on a page that names the device.
func TestLoginNeedsConfirmation(t *testing.T) {
	e := newEnv(t)
	e.withIdP(t, time.Hour)
	e.registerSigner()
	laptop := e.device("laptop")
	st := e.enroll(laptop, `{"name":"laptop","hostname":"mbp.local","platform":"darwin","roles":["endpoint"]}`)
	nv := e.approve(st.NodeID, `{"roles":["endpoint"]}`)

	start := func() api.LoginStart {
		t.Helper()
		code, b := e.nodeCall(laptop, "POST", "/api/v1/node/login/start", "{}")
		if code != http.StatusOK {
			t.Fatalf("login start: %d %s", code, b)
		}
		var ls api.LoginStart
		_ = json.Unmarshal(b, &ls)
		return ls
	}
	status := func(flow string) api.LoginStatus {
		t.Helper()
		_, b := e.nodeCall(laptop, "GET", "/api/v1/node/login/"+flow+"?wait=0s", "")
		var st api.LoginStatus
		_ = json.Unmarshal(b, &st)
		return st
	}

	ls := start()
	code, page := e.browserUntilConfirm(t, ls.URL)
	if code != http.StatusOK {
		t.Fatalf("callback: %d %s", code, page)
	}
	for _, want := range []string{"Sign in this device?", "martin", "laptop", "mbp.local", "darwin", nv.Fingerprint[:19],
		"Only continue if you started this sign-in on this device yourself. Whoever holds this device gets your access.",
		`action="` + api.OIDCConfirmPath + `"`, `value="confirm"`, `value="cancel"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("confirmation page lacks %q: %s", want, page)
		}
	}
	if strings.Contains(page, "another network") {
		t.Fatal("same address, yet the page warns about another network")
	}
	// nothing is signed in yet
	if st := status(ls.FlowID); st.Status != "pending" || st.Session != nil {
		t.Fatalf("before the confirmation: %+v", st)
	}
	var sessions []api.SessionView
	e.adminCall("GET", "/api/v1/admin/sessions", "", http.StatusOK, &sessions)
	if len(sessions) != 0 {
		t.Fatalf("a session before the confirmation: %+v", sessions)
	}
	// a wrong token, or none, changes nothing
	m := confirmFormRe.FindStringSubmatch(page)
	if code, _ := e.postConfirm(t, m[1], m[2]+"x", "confirm"); code != http.StatusBadRequest {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := e.postConfirm(t, m[1], "", "confirm"); code != http.StatusBadRequest {
		t.Fatalf("no token: %d", code)
	}
	if st := status(ls.FlowID); st.Status != "pending" {
		t.Fatalf("after a wrong token: %+v", st)
	}
	// cancel: the flow fails, the page cannot be used afterwards
	if code, body := e.confirmLogin(t, page, "cancel"); code != http.StatusOK || !strings.Contains(body, "cancelled") {
		t.Fatalf("cancel: %d %s", code, body)
	}
	if st := status(ls.FlowID); st.Status != "failed" || !strings.Contains(st.Error, "cancelled") {
		t.Fatalf("after cancel: %+v", st)
	}
	if code, _ := e.confirmLogin(t, page, "confirm"); code != http.StatusConflict {
		t.Fatalf("confirm after cancel: %d", code)
	}

	// confirm: done, and the token is single-use
	ls = start()
	_, page = e.browserUntilConfirm(t, ls.URL)
	if code, body := e.confirmLogin(t, page, "confirm"); code != http.StatusOK || !strings.Contains(body, "Logged in") {
		t.Fatalf("confirm: %d %s", code, body)
	}
	if st := status(ls.FlowID); st.Status != "done" || st.Session == nil || st.Session.Subject != "u1" {
		t.Fatalf("after confirm: %+v", st)
	}
	if code, _ := e.confirmLogin(t, page, "confirm"); code != http.StatusConflict {
		t.Fatalf("second confirm: %d", code)
	}

	// audit: both the question and the answer
	var evs []struct{ Message string }
	e.adminCall("GET", "/api/v1/admin/logs?stream=user-auth&node="+st.NodeID, "", http.StatusOK, &evs)
	msgs := ""
	for _, ev := range evs {
		msgs += ev.Message + ","
	}
	for _, want := range []string{"login awaiting confirmation", "login cancelled", "login completed"} {
		if !strings.Contains(msgs, want) {
			t.Fatalf("user-auth log lacks %q: %s", want, msgs)
		}
	}
}

// A node keeps at most three login flows open (a fourth fails the oldest)
// and two status requests waiting at once.
func TestLoginFlowBounds(t *testing.T) {
	e := newEnv(t)
	e.withIdP(t, time.Hour)
	e.registerSigner()
	d := e.device("laptop")
	st := e.enroll(d, `{"name":"laptop","roles":["endpoint"]}`)
	e.approve(st.NodeID, `{"roles":["endpoint"]}`)
	var flows []string
	for i := 0; i < 4; i++ {
		_, b := e.nodeCall(d, "POST", "/api/v1/node/login/start", "{}")
		var ls api.LoginStart
		_ = json.Unmarshal(b, &ls)
		flows = append(flows, ls.FlowID)
	}
	for i, f := range flows {
		_, b := e.nodeCall(d, "GET", "/api/v1/node/login/"+f+"?wait=0s", "")
		var ls api.LoginStatus
		_ = json.Unmarshal(b, &ls)
		if want := map[bool]string{true: "failed", false: "pending"}[i == 0]; ls.Status != want {
			t.Fatalf("flow %d: %+v, want %s", i, ls, want)
		}
	}

	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := e.nodeCall(d, "GET", "/api/v1/node/login/"+flows[3]+"?wait=2s", "")
			codes <- code
		}()
	}
	// both are waiting (the flow stays pending); a third is refused
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _ := e.nodeCall(d, "GET", "/api/v1/node/login/"+flows[3]+"?wait=0s", "")
		if code == http.StatusTooManyRequests {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a third waiting status request was not refused: %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusOK {
			t.Fatalf("waiting status request: %d", c)
		}
	}
	if code, _ := e.nodeCall(d, "GET", "/api/v1/node/login/"+flows[3]+"?wait=0s", ""); code != http.StatusOK {
		t.Fatalf("after the waiting requests ended: %d", code)
	}
}
