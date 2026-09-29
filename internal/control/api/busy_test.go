package api_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/devicekey"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// brokenLookup is a registry that cannot answer: the control plane holds a
// single database connection, and a lookup queueing behind a write runs into
// its own deadline.
type brokenLookup struct{}

func (brokenLookup) LookupSPKI(devicekey.SPKIHash) (transport.DeviceInfo, bool, error) {
	return transport.DeviceInfo{}, false, errors.New("context deadline exceeded")
}

// A registry that cannot be asked says nothing about the node asking, and the
// node channel must not pretend otherwise: 503, never 403. A node takes 403
// as "unenrolled", clears its snapshot and reports itself revoked — so one
// busy moment would throw the whole fleet out at once and tell every device
// its key had been revoked, which is both false and, for a key, permanent.
func TestABusyRegistryIsNotARefusal(t *testing.T) {
	e := newEnv(t)
	e.registerSigner()
	laptop := e.device("laptop")
	id := e.enroll(laptop, `{"name":"laptop","roles":["endpoint"]}`).NodeID
	e.approve(id, `{"fingerprint":"`+laptop.spki+`","kind":"workload","roles":["endpoint"]}`)
	if code, b := e.nodeCall(laptop, "GET", "/api/v1/node/snapshot?since=0&wait=1s", ""); code != http.StatusOK {
		t.Fatalf("approved node does not get its snapshot: %d %s", code, b)
	}

	e.handlers.SetLookupForTest(brokenLookup{})
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/v1/node/snapshot?since=0&wait=1s", ""},
		{"POST", "/api/v1/node/heartbeat", `{}`},
		{"POST", "/api/v1/node/logs", `{"events":[]}`},
	} {
		code, b := e.nodeCall(laptop, c.method, c.path, c.body)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s: %d %s, want 503", c.method, c.path, code, b)
		}
		if strings.Contains(string(b), "not approved") {
			t.Fatalf("%s %s tells the node it is not approved: %s", c.method, c.path, b)
		}
	}

	// the enrollment status is the node's other question, and a database that
	// cannot answer it must not read as "this key is unknown here" either
	e.store.Close()
	if code, b := e.nodeCall(laptop, "GET", "/api/v1/node/enroll/status", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("enroll status with a closed database: %d %s, want 503", code, b)
	}
}
