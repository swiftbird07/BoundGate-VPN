package node

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/netcfg"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/node/profile"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/registry"
	"gitlab.net407.com/SBH/BoundGate-VPN/internal/transport"
)

// graceNet records routes and resolvers like an app's platform would.
type graceNet struct {
	netcfg.Configurator
	added, deleted []string
	dns            []netip.Addr
}

func (r *graceNet) AddRoute(_ context.Context, dst netip.Prefix, _ string) error {
	r.added = append(r.added, dst.String())
	return nil
}

func (r *graceNet) DelRoute(_ context.Context, dst netip.Prefix, _ string) error {
	r.deleted = append(r.deleted, dst.String())
	return nil
}

func (r *graceNet) SetDNS(servers []netip.Addr) { r.dns = servers }

func graceManager(t *testing.T, rec *graceNet) (*spokeManager, *hubLink) {
	t.Helper()
	n := &Node{net: rec, log: slog.New(slog.DiscardHandler), cfg: Config{AllowOverlap: true}}
	self := registry.Node{ID: "phone"}
	s := &session{n: n, self: self, pool: netip.MustParsePrefix("10.25.0.0/16"), profile: profile.Full(), ifname: "tunnel"}
	own := ownNetworks(self)
	s.own.Store(&own)
	l := &hubLink{tunnel: &transport.ClientTunnel{}, advertised: []netip.Prefix{
		netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("0.0.0.0/0"),
	}, dns: []netip.Addr{netip.MustParseAddr("10.20.0.1")}}
	m := &spokeManager{s: s, installed: map[netip.Prefix]bool{}, links: map[transport.DeviceID]*hubLink{"hub": l}, order: []transport.DeviceID{"hub"}}
	m.primary = l
	m.mu.Lock()
	m.applyRoutesLocked()
	m.mu.Unlock()
	return m, l
}

// A hub tunnel that was just lost leaves its routes and resolvers standing
// for routeGrace while the link dials again: on a phone every change is a
// new tunnel interface, and two in a row in the middle of a change of
// network were what left it without internet. After the grace, or when the
// hub refused the device, they go as before.
func TestALostHubsRoutesStayForTheGrace(t *testing.T) {
	rec := &graceNet{}
	m, l := graceManager(t, rec)
	if len(rec.added) != 4 || len(rec.dns) != 1 { // two halves, the hub's net, the resolver's host route
		t.Fatalf("to begin with: added %v, dns %v", rec.added, rec.dns)
	}

	// lost a moment ago: everything stays, only the uplink is gone
	m.mu.Lock()
	l.tunnel, l.lostAt = nil, time.Now()
	m.primary = nil
	m.applyRoutesLocked()
	m.mu.Unlock()
	if len(rec.deleted) != 0 {
		t.Errorf("routes withdrawn on a loss: %v", rec.deleted)
	}
	if len(rec.dns) != 1 {
		t.Errorf("the resolver was withdrawn on a loss: %v", rec.dns)
	}

	// back: the same routes, nothing changes
	m.mu.Lock()
	l.tunnel, l.lostAt = &transport.ClientTunnel{}, time.Time{}
	m.primary = l
	m.applyRoutesLocked()
	m.mu.Unlock()
	if len(rec.added) != 4 || len(rec.deleted) != 0 {
		t.Errorf("a return changed the routes: added %v, deleted %v", rec.added, rec.deleted)
	}

	// lost for longer than the grace: withdrawn
	m.mu.Lock()
	l.tunnel, l.lostAt = nil, time.Now().Add(-routeGrace-time.Second)
	m.primary = nil
	m.applyRoutesLocked()
	m.mu.Unlock()
	if !slices.Contains(rec.deleted, "0.0.0.0/1") || !slices.Contains(rec.deleted, "10.20.0.0/16") {
		t.Errorf("routes stayed after the grace: deleted %v", rec.deleted)
	}
	if len(rec.dns) != 0 {
		t.Errorf("the resolver stayed after the grace: %v", rec.dns)
	}
}

func TestARefusalEndsTheGrace(t *testing.T) {
	m, _ := graceManager(t, &graceNet{})
	closed := func(code quic.ApplicationErrorCode) error {
		return &quic.ApplicationError{ErrorCode: code, ErrorMessage: "test"}
	}
	for _, c := range []struct {
		err  error
		keep bool
	}{
		{errors.New("read: connection reset"), true},
		{closed(transport.ErrCodeNoAnswer), true},
		{closed(transport.ErrCodeShutdown), true},
		{closed(transport.ErrCodeTryAgain), true},
		{closed(transport.ErrCodeRevoked), false},
		{closed(transport.ErrCodeSessionExpired), false},
		{closed(transport.ErrCodePolicy), false},
	} {
		if got := m.keepsRoutes(c.err); got != c.keep {
			t.Errorf("%v: routes kept %v, want %v", c.err, got, c.keep)
		}
	}
}
