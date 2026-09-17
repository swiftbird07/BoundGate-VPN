#!/bin/sh
# M5 acceptance on the Mac host against the running compose lab:
# enroll -> approve + sign -> up (login required) -> login -> reach the lab
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
./netbackup.sh backup
echo "   (if anything looks wrong afterwards: deploy/macos/netbackup.sh diff, then restore -y)"
BEFORE=$(./netbackup.sh routes)
$D run > /tmp/boundgate-mac-node.log 2>&1 &
DAEMON=$!
trap '$D ctl down >/dev/null 2>&1 || true; $D ctl logout >/dev/null 2>&1 || true; sudo pkill -f "darwin_.*/boundgate-node" 2>/dev/null || true; kill $DAEMON 2>/dev/null || true' EXIT
wait_for 15 $D ctl -json status || fail "daemon not reachable (see /tmp/boundgate-mac-node.log)"

echo "== 1. the hubs answer over UDP through the bridge"
$BRIDGE_BIN -probe 127.0.0.1:15431 || $BRIDGE_BIN -probe 127.0.0.1:15432 || fail "no hub reachable over UDP"

echo "== 2. enroll, then approve and sign as an interactive endpoint"
$S approve mac
wait_for 20 st '.enrollment == "approved" and .binding == "verified"' || fail "not approved"

echo "== 3. up: tunnel device and routes, but the hubs want a user login"
$D ctl logout >/dev/null 2>&1 || true   # an aborted earlier run leaves its user session in the control plane
$D ctl up >/dev/null || fail "up refused (an 'overlaps' message means another VPN on this Mac uses the lab's overlay range: disconnect it for the test, see docs/MACOS.md)"
wait_for 20 st '.login_required == true' || fail "hubs did not ask for a login"
if curl -sf --max-time 3 http://10.60.0.10 >/dev/null; then fail "target reachable without login"; fi

echo "== 4. login at the (fake) IdP, hubs admit the node"
$S login mac >/dev/null
wait_for 20 st '[.hubs[] | select(.state == "connected")] | length >= 1' || fail "no hub connected after login"
ifconfig | grep -q 'inet 10\.21\.' || fail "no overlay address on a utun device"
# netstat abbreviates (10.60/24); netbackup.sh prints full prefixes
./netbackup.sh routes | grep -q '^inet 10\.60\.0\.0/24 .* utun[0-9]*$' || fail "no route for the lab network through utun"
st '.profile == "mac-lab"' || fail "the configured profile was not applied"
if ./netbackup.sh routes | grep -q '^inet 192\.168\.178\.0/24 .* utun'; then fail "the home LAN prefix was routed into the overlay"; fi

echo "== 5. reach the target behind the hubs; the flow is decided and logged by a hub"
wait_for 10 sh -c 'curl -sf --max-time 3 http://10.60.0.10 | grep -q "^Name: target"' || fail "target unreachable through the overlay"
# by overlay address: the name in the control plane is the admin's choice, not the local host name
OIP=$($D ctl -json status | jq -r .overlay_ip)
wait_for 20 sh -c "$S flows 'dst=10.60.0.10&decision=allow' | grep -qF '	$OIP:'" || fail "no flow record for the Mac node ($OIP)"

echo "== 6. down: device, routes and journal are gone; the routing table is what it was"
$D ctl down >/dev/null
wait_for 10 st '.state == "down"' || fail "not down"
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
