package netcfg

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchDefaultsOnlyOnChange(t *testing.T) {
	old := watchDelay
	watchDelay = 10 * time.Millisecond
	defer func() { watchDelay = old }()
	var mu sync.Mutex
	state := "via wifi"
	snap := func() (string, error) { mu.Lock(); defer mu.Unlock(); return state, nil }
	var calls atomic.Int32
	events := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { watchDefaults(ctx, events, snap, func() { calls.Add(1) }); close(done) }()

	wait := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for calls.Load() != want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // and no more than that
		if got := calls.Load(); got != want {
			t.Fatalf("changed called %d times, want %d", got, want)
		}
	}
	// the node's own route changes: events, same default routes
	for i := 0; i < 20; i++ {
		notify(events)
	}
	wait(0)
	// another network
	mu.Lock()
	state = "via hotspot"
	mu.Unlock()
	notify(events)
	wait(1)
	notify(events)
	wait(1)
	cancel()
	<-done
}

func TestLinuxDefaults(t *testing.T) {
	route4 := `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0102A8C0	0003	0	0	600	00000000	0	0	0
wlan0	0002A8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
bg0	00000000	00000000	0001	0	0	0	00000080	0	0	0
bg0	00000080	00000000	0001	0	0	0	00000080	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`
	route6 := `00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00450003 wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 wlan0
`
	skip := func(n string) bool { return n == "bg0" }
	got := linuxDefaults(route4, route6, skip)
	want := "4 wlan0 0102A8C0 600\n6 wlan0 fe800000000000000000000000000001 00000400"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// a container starting adds routes but no default: same snapshot
	if linuxDefaults(route4+"veth1\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n", route6, skip) != got {
		t.Fatal("a container's route changed the snapshot")
	}
}

func TestDarwinDefaults(t *testing.T) {
	netstat := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
0/1                utun4              USc                 utun4
127                127.0.0.1          UCS                   lo0
192.168.1.1/32     link#12            UCS                   en0      !

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcg                  en0
default                                 fe80::%utun4                            UGcIg               utun4
`
	got := darwinDefaults(netstat, func(n string) bool { return n == "utun4" })
	if got != "192.168.1.1 en0\nfe80::1%en0 en0" {
		t.Fatalf("got %q", got)
	}
}
