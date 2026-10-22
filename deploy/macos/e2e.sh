#!/bin/sh
# M5 acceptance on the Mac host against the running compose lab:
# enroll -> approve + sign -> up (the policy still closed) -> login -> reach the lab
# target through a hub -> down restores the routing table.
#
# Needs: make compose-up && make build-darwin, sudo (utun, routes), and admin
# API access for the lab scripts (deploy/compose/state/control/api.token once
# an admin passkey exists; see docs/DEV.md).
set -eu
cd "$(dirname "$0")"
D=./dev.sh
S=../compose/setup-dev.sh
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
BRIDGE_BIN=../../bin/darwin_$ARCH/boundgate-udpbridge
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; n=$((n-1)); sleep 1; done; return 1; }
st() { $D ctl -json status | jq -e "$1" >/dev/null; }

echo "== 0. sudo, a backup of the Mac's network state, the daemon"
sudo -v
# This lab's control plane is the one under ../compose/state/control. A Mac
# state older than its certificate pinned a key that no longer exists, and its
# device record went with the old database; enrolling again is the only way
# back, and step 2 does exactly that. So the state goes here -- the compose lab
# drops what has gone stale in its own step 0 for the same reason.
CRT=../compose/state/control/control.crt
if [ -f state/device.key ] && [ -f "$CRT" ] && [ "$CRT" -nt state/device.key ]; then
  echo "   the state is older than this lab's control plane: starting over (new key, approved in step 2)"
  $D clean
fi
# A state from before the admin key list was signed holds a plain list of admin
# keys, and the daemon refuses to start with it. In the lab that pin goes and
# the node pins the signed list on its first contact, as ../compose/e2e.sh does.
if [ -f state/admin_keys ] && [ ! -f state/admin_trust.json ]; then
  echo "   dropping an admin key pin from before that list was signed"
  sudo rm -f state/admin_keys
fi
./netbackup.sh backup
echo "   (if anything looks wrong afterwards: deploy/macos/netbackup.sh diff, then restore -y)"
BEFORE=$(./netbackup.sh routes)
$D run > /tmp/boundgate-mac-node.log 2>&1 &
DAEMON=$!

# every resolver entry a node of ours left in the system configuration
dns_leftovers() { printf 'list State:/Network/Service/boundgate-[^/]+/DNS\nquit\n' | scutil 2>/dev/null | sed -n 's/.*= \(State:.*\)$/\1/p'; }

# What this script must never do is walk away from a Mac that cannot resolve
# a name. While the overlay is up, this host sends every name to the hub's
# resolver through the tunnel, and macOS asks nobody else -- so an entry left
# behind for a device that is gone is a Mac without working names, and
# without internet in everything that judges the network by the system
# configuration (Safari among them). It happened on 2026-10-22, and only a
# reboot helped.
#
# Hence: let the teardown finish *before* the daemon is killed, then undo
# what is left without a daemon, then prove the machine is in order -- and
# fail the run if it was not, so this is caught here and not in a browser.
finish() {
  trap '' EXIT # no recursion if something in here fails
  $D ctl down >/dev/null 2>&1 || true
  $D ctl logout >/dev/null 2>&1 || true
  wait_for 20 st '.state == "down"' || echo "   the daemon did not report the overlay as down" >&2
  sudo pkill -f "darwin_.*/boundgate-node" 2>/dev/null || true
  kill $DAEMON 2>/dev/null || true
  sleep 1
  $D repair || true # journal plus a sweep of the system configuration
  bad=0
  left=$(dns_leftovers)
  if [ -n "$left" ]; then
    echo "LEFTOVER: this Mac is still pointed at the tunnel's resolver:" >&2
    echo "$left" >&2
    for k in $left; do printf 'remove %s\nquit\n' "$k" | sudo scutil >/dev/null 2>&1 || true; done
    echo "   removed by hand -- that the daemon and 'dev.sh repair' did not is a bug" >&2
    bad=1
  fi
  dscacheutil -flushcache 2>/dev/null || true
  if ! dscacheutil -q host -a name apple.com 2>/dev/null | grep -q ip_address; then
    echo "THIS MAC CANNOT RESOLVE NAMES after the run. Way back: deploy/macos/netbackup.sh restore -y" >&2
    bad=1
  fi
  # the journal is the node's own answer to the question: it only keeps what
  # it could not take back
  if sudo test -s state/netstate.json; then
    echo "LEFTOVER: the node's journal still names changes nobody could undo:" >&2
    sudo cat state/netstate.json >&2
    bad=1
  fi
  [ $bad = 0 ] || exit 1
}
trap finish EXIT
wait_for 15 $D ctl -json status || fail "daemon not reachable (see /tmp/boundgate-mac-node.log)"

echo "== 1. the hubs answer over UDP through the bridge"
$BRIDGE_BIN -probe 127.0.0.1:15431 || $BRIDGE_BIN -probe 127.0.0.1:15432 || fail "no hub reachable over UDP"

echo "== 2. enroll, then approve and sign as an interactive endpoint"
$S approve mac
wait_for 20 st '.enrollment == "approved" and .binding == "verified"' || fail "not approved"

echo "== 2b. the lab's policy: a device gets in on its key, an interactive node needs a person"
# Whether a sign-in is required is what a policy says, not the hub
# (docs/OIDC.md) -- and ../compose/e2e.sh leaves the lab on a blanket permit
# when it is done. So this run sets the lab's default policy instead of
# inheriting whatever ran last, which is what made step 3 below fail on
# 2026-10-22.
$S policy lab-allow-all 'permit(principal, action, resource) when { principal.has_session || principal.kind == "workload" };' >/dev/null

echo "== 3. up: the hubs admit the device on its key, and the policy -- not the hub -- keeps the target closed until a person signs in"
# A user session is not a condition of the tunnel (docs/OIDC.md): the device
# gets in on its key, and whether a person is needed is what a policy says
# (step 2b). `login_required` is the older behaviour, a hub refusing the
# tunnel itself, and must stay off -- the same assertion as in
# ../compose/e2e.sh step 3.
$D ctl logout >/dev/null 2>&1 || true   # an aborted earlier run leaves its user session in the control plane
$D ctl up >/dev/null || fail "up refused (an 'overlaps' message means another VPN on this Mac uses the lab's overlay range: disconnect it for the test, see docs/MACOS.md)"
wait_for 20 st '(.login_required | not) and ([.hubs[] | select(.state == "connected")] | length >= 1)' || fail "no hub admitted this Mac without a session"
st '.user == null and .kind == "interactive"' || fail "this Mac has a user before the login"
if curl -sf --max-time 3 http://10.60.0.10 >/dev/null; then fail "target reachable without a session, although the policy asks for one"; fi

echo "== 4. login at the (fake) IdP: the session reaches the snapshot and the policy opens"
$S login mac >/dev/null
wait_for 20 st '.user.username == "martin" and ([.hubs[] | select(.state == "connected")] | length >= 1)' || fail "no session on this Mac after the login"
ifconfig | grep -q 'inet 10\.21\.' || fail "no overlay address on a utun device"
# netstat abbreviates (10.60/24); netbackup.sh prints full prefixes
./netbackup.sh routes | grep -q '^inet 10\.60\.0\.0/24 .* utun[0-9]*$' || fail "no route for the lab network through utun"
st '.profile == "mac-lab"' || fail "the configured profile was not applied"
if ./netbackup.sh routes | grep -q '^inet 192\.168\.178\.0/24 .* utun'; then fail "the home LAN prefix was routed into the overlay"; fi

echo "== 4b. the hub's resolver: this Mac asks it for every name while the overlay is up"
# Without this the Mac resolves in its own network, the hub never sees the
# query, and a dynamic access list cannot match the connection that follows
# (#14, docs/ACL.md). On macOS it is one dictionary in configd's dynamic
# store, with the catch-all match domain; /etc/resolv.conf is not touched.
wait_for 15 st '.dns == ["10.60.0.53"]' || fail "the node does not report the hub's resolver (status .dns)"
wait_for 10 sh -c "scutil --dns | awk '/^resolver #1/,/^\$/' | grep -q 10.60.0.53" || fail "mDNSResponder was not pointed at the hub's resolver (scutil --dns)"
# a name only the lab's resolver knows, resolved by this Mac through the tunnel
wait_for 10 sh -c 'dscacheutil -q host -a name target.lab | grep -q "^ip_address: 10.60.0.10"' || fail "target.lab was not resolved through the tunnel"
# and everything else still resolves: the lab resolver forwards what is not its own
dscacheutil -q host -a name www.apple.com | grep -q "^ip_address:" || fail "other names stopped resolving while the overlay is up"

echo "== 5. reach the target behind the hubs; the flow is decided and logged by a hub"
wait_for 10 sh -c 'curl -sf --max-time 3 http://10.60.0.10 | grep -q "^Name: target"' || fail "target unreachable through the overlay"
# by overlay address: the name in the control plane is the admin's choice, not the local host name
OIP=$($D ctl -json status | jq -r .overlay_ip)
wait_for 20 sh -c "$S flows 'dst=10.60.0.10&decision=allow' | grep -qF '	$OIP:'" || fail "no flow record for the Mac node ($OIP)"

echo "== 6. down: device, routes, resolver and journal are gone; the routing table is what it was"
$D ctl down >/dev/null
wait_for 10 st '.state == "down"' || fail "not down"
wait_for 10 sh -c '! scutil --dns | grep -q 10.60.0.53' || fail "the hub's resolver is still in the system configuration after down"
dscacheutil -q host -a name www.apple.com | grep -q "^ip_address:" || fail "names do not resolve after down"
AFTER=$(./netbackup.sh routes)
[ "$BEFORE" = "$AFTER" ] || { echo "$BEFORE" > /tmp/bg-routes.before; echo "$AFTER" > /tmp/bg-routes.after; fail "routing table differs (diff /tmp/bg-routes.before /tmp/bg-routes.after; repair: deploy/macos/netbackup.sh restore -y)"; }
[ ! -e state/netstate.json ] || fail "journal not empty after down"

echo "== 7. a killed daemon leaves no routes behind after the next start"
$D ctl up >/dev/null; wait_for 20 st '[.hubs[] | select(.state == "connected")] | length >= 1' || fail "second up failed"
sudo pkill -9 -f "darwin_.*/boundgate-node"; sleep 1
$D run >> /tmp/boundgate-mac-node.log 2>&1 &
DAEMON=$!
wait_for 15 $D ctl -json status || fail "daemon did not restart"
grep -q "removed network leftovers" state/logs/system.jsonl /tmp/boundgate-mac-node.log 2>/dev/null || echo "   (nothing to recover: loopback hubs need no bypass routes)"
AFTER=$(./netbackup.sh routes)
[ "$BEFORE" = "$AFTER" ] || fail "routes left behind after a crash (repair: deploy/macos/netbackup.sh restore -y)"

echo "PASS: M5 macOS node"
