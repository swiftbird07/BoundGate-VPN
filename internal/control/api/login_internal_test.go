package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.net407.com/SBH/BoundGate-VPN/internal/control/db"
)

func TestClientKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                 "192.0.2.7",
		"::ffff:192.0.2.7":          "192.0.2.7",
		"2001:db8:1:2:aaaa::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:bbbb:cccc::9": "2001:db8:1:2::/64",
		"fe80::1%eth0":              "fe80::/64",
		"not an address":            "not an address",
	} {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
	if !sameClientNetwork("2001:db8:1:2::1", "2001:db8:1:2:ffff::2") || sameClientNetwork("2001:db8:1:2::1", "2001:db8:1:3::1") ||
		sameClientNetwork("192.0.2.7", "192.0.2.8") || sameClientNetwork("192.0.2.7", "2001:db8::1") {
		t.Fatal("sameClientNetwork")
	}
	// a /64 is one client for a limit
	l := newRateLimiter(2, time.Minute)
	if !l.allowClient("2001:db8:1:2::1") || !l.allowClient("2001:db8:1:2::2") || l.allowClient("2001:db8:1:2::3") {
		t.Fatal("addresses of one /64 count separately")
	}
	if !l.allowClient("2001:db8:1:3::1") {
		t.Fatal("another /64 is limited")
	}
}

// The confirmation page warns more strongly when the browser comes from
// another network than the node that started the login, and escapes what
// the node chose (its name, hostname, platform).
func TestConfirmPageWarnsAboutAnotherNetwork(t *testing.T) {
	n := db.Node{ID: "n1", Name: `evil<script>`, Hostname: "h", Platform: "linux", ApprovedAt: time.Now()}
	flow := db.LoginFlow{ID: "f1", StartIP: "198.51.100.9", CallbackIP: "192.0.2.7", ConfirmExpiresAt: time.Now().Add(time.Minute),
		Identity: db.LoginIdentity{Subject: "u1", Username: "martin", Email: "m@example.test"}}
	w := httptest.NewRecorder()
	confirmPage(w, n, flow, "tok", true)
	body := w.Body.String()
	for _, want := range []string{"started from another network", "198.51.100.9", "192.0.2.7", "evil&lt;script&gt;", "martin (m@example.test)", `name="token" value="tok"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "<script>") {
		t.Fatal("node name not escaped")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("the confirmation page can be framed: %v", w.Header())
	}
}
