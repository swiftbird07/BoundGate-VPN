#!/bin/sh
# End-to-end check of milestones M1.5 and M1.6 against the running compose
# environment: node model with hubs, subnet router, HA, revocation,
# re-enrollment, signed bindings, sign tokens, tampering, control-plane pin.
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.yml"
S=./setup-dev.sh
fail() { echo "FAIL: $*" >&2; exit 1; }
x() { svc=$1; shift; $COMPOSE exec -T "$svc" "$@"; }
# wait_for SECONDS CMD...: retry until the command succeeds
wait_for() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; n=$((n-1)); sleep 1; done; return 1; }
reach() { x node-a curl -sf --max-time 3 "http://$1" | grep -q "^Name: $2"; }
status_is() { docker compose -f docker-compose.yml exec -T "$1" boundgatectl -json status | jq -e "$2" >/dev/null; }
sql() { x control sqlite3 -cmd '.timeout 5000' /var/lib/boundgate/control.db "$1"; }

fresh_key() {  # fresh_key SVC: replace the node's key (a revoked key can never come back)
  $COMPOSE stop "$1" >/dev/null
  rm -f "state/$1/device.key" "state/$1/device.crt" "state/$1/admin_keys"
  $COMPOSE start "$1" >/dev/null
  wait_for 15 sh -c "docker compose -f docker-compose.yml exec -T $1 boundgatectl -json status >/dev/null" || fail "$1 did not come back"
}

echo "== 0. a previous run may have left node-a revoked: then start with a fresh key"
if wait_for 15 sh -c 'docker compose -f docker-compose.yml exec -T node-a boundgatectl -json enroll | jq -e ".status == \"revoked\""'; then
  fresh_key node-a
fi

echo "== 1. bootstrap: admin signing key, network, enroll + confirm + sign hub1, hub2, node-r, node-a"
$S all
x node-a boundgatectl -json identity | jq -e '.control_pin != "" and (.admin_keys | length) == 1' >/dev/null || fail "node-a has no control pin / admin keys"

echo "== 2. hubs and the subnet router come up on their own"
wait_for 20 status_is hub1 '.state == "up" and .binding == "verified"' || fail "hub1 not up"
wait_for 20 status_is hub2 '.state == "up"' || fail "hub2 not up"
wait_for 20 status_is node-r '[.hubs[] | select(.state == "connected")] | length == 2' || fail "node-r not connected to both hubs"

echo "== 3. node-a: up, connected to both hubs, routes from the lab profile"
x node-a boundgatectl up >/dev/null
wait_for 15 status_is node-a '[.hubs[] | select(.state == "connected")] | length == 2' || fail "node-a not connected to both hubs"
status_is node-a '.routes | index("10.60.0.0/24") != null and index("192.168.178.0/24") != null' || fail "routes missing"

echo "== 4. reach the target behind the hubs, the LAN behind node-r, and node-r itself"
wait_for 10 reach 10.60.0.10 target || fail "target behind hubs unreachable"
wait_for 10 reach 192.168.178.10 target-lan || fail "LAN target behind node-r unreachable"
R_IP=$(x node-r boundgatectl -json status | jq -r .overlay_ip)
x node-a ping -c 2 -W 2 "$R_IP" >/dev/null || fail "node-r overlay ip $R_IP unreachable"
H2_IP=$(x hub2 boundgatectl -json status | jq -r .overlay_ip)
x node-a ping -c 2 -W 2 "$H2_IP" >/dev/null || fail "hub2 overlay ip $H2_IP unreachable"

echo "== 5. HA: stop hub1, traffic moves to hub2 within 10 s, hub1 comes back"
$COMPOSE stop hub1 >/dev/null
START=$(date +%s)
wait_for 10 reach 10.60.0.10 target || fail "target unreachable after hub1 stopped"
echo "   failover took $(( $(date +%s) - START )) s"
status_is node-a '.hubs[] | select(.name == "hub2") | .primary == true' || fail "hub2 not primary"
$COMPOSE start hub1 >/dev/null
wait_for 30 status_is node-a '[.hubs[] | select(.state == "connected")] | length == 2' || fail "node-a did not reconnect to hub1"

echo "== 6. revoke node-a while up: tunnels close, up fails, key cannot re-enroll"
$S revoke node-a >/dev/null
wait_for 5 status_is node-a '.state == "down"' || fail "node-a not down after revocation"
status_is node-a '.last_close | test("revoked|no longer approved")' || fail "unexpected close reason"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "revoked node came up"; fi
x node-a boundgatectl -json enroll | jq -e '.status == "revoked"' >/dev/null || fail "revoked key got a new status"
status_is hub1 '.tunnels == 1' || fail "hub1 still has node-a's tunnel"

echo "== 7. fresh key: enroll -> pending -> confirm (not enough) -> sign -> approved -> up; token is single use"
fresh_key node-a
wait_for 10 sh -c 'docker compose -f docker-compose.yml exec -T node-a boundgatectl -json enroll | jq -e ".status == \"pending\""' || fail "new key not pending"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "pending node came up"; fi
$S confirm node-a >/dev/null
wait_for 10 sh -c 'docker compose -f docker-compose.yml exec -T node-a boundgatectl -json enroll | jq -e ".status == \"confirmed\""' || fail "node-a not confirmed"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "confirmed but unsigned node came up"; fi
$S api GET /api/v1/admin/snapshot | jq -e '[.peers[] | select(.name == "node-a")] | length == 0' >/dev/null || fail "unsigned node in the snapshot"
# sign by hand so the token can be replayed
ID=$(x node-a boundgatectl -json identity | jq -r .node_id)
FP=$(x node-a boundgatectl -json identity | jq -r .spki)
TOKEN=$($S api POST "/api/v1/admin/nodes/$ID/confirm" "{\"fingerprint\":\"$FP\"}" | jq -r .sign_token)
x control boundgatectl admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt --node "$ID" --fingerprint "$FP" --token "$TOKEN" --key /var/lib/boundgate/admin_signer >/dev/null || fail "sign failed"
if out=$(x control boundgatectl admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt --node "$ID" --fingerprint "$FP" --token "$TOKEN" --key /var/lib/boundgate/admin_signer 2>&1); then
  fail "sign token accepted twice"
fi
echo "$out" | grep -q "HTTP 409" || fail "token reuse is not a 409: $out"
wait_for 10 status_is node-a '.enrollment == "approved" and .snapshot_version > 0 and .binding == "verified"' || fail "node-a not approved"
x node-a boundgatectl up >/dev/null
wait_for 10 reach 10.60.0.10 target || fail "target unreachable after re-enrollment"

echo "== 8. changing a signed field (roles) drops the approval until re-signed"
$S api PATCH "/api/v1/admin/nodes/$ID" '{"roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"10.99.0.0/24","mode":"routed"}]}' | jq -e '.status == "confirmed" and .sign_token != null' >/dev/null || fail "patch did not demote"
wait_for 10 status_is node-a '.state == "down"' || fail "node-a still up after its grant changed"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "demoted node came up"; fi
$S sign node-a >/dev/null
wait_for 10 status_is node-a '.enrollment == "approved" and .binding == "verified"' || fail "node-a not re-approved"
x node-a boundgatectl up >/dev/null
wait_for 10 reach 10.60.0.10 target || fail "target unreachable after re-sign"
status_is node-a '.prefixes[0] | test("10.99.0.0/24")' || fail "new grant not applied"

echo "== 9. a control plane that tampers with a role: every node ignores the node (binding does not verify)"
sql "UPDATE nodes SET roles_json = '[\"endpoint\",\"subnet-router\",\"hub\"]' WHERE name = 'node-r'; UPDATE snapshot_version SET version = version + 1;"
wait_for 45 status_is node-a '.ignored_peers | length == 1 and (.[0] | test("node-r"))' || fail "node-a did not ignore the tampered node-r"
wait_for 45 status_is hub1 '.ignored_peers | length == 1' || fail "hub1 did not ignore the tampered node-r"
wait_for 45 status_is node-r '.binding == "invalid" and .state == "down"' || fail "node-r kept operating with a tampered own binding"
if reach 192.168.178.10 target-lan; then fail "LAN behind the tampered node-r still reachable"; fi
sql "UPDATE nodes SET roles_json = '[\"endpoint\",\"subnet-router\"]' WHERE name = 'node-r'; UPDATE snapshot_version SET version = version + 1;"
wait_for 45 status_is node-a '.ignored_peers | length == 0' || fail "node-a still ignores node-r after the fix"
wait_for 60 status_is node-r '.binding == "verified" and .state == "up" and ([.hubs[] | select(.state == "connected")] | length == 2)' || fail "node-r did not recover"
wait_for 20 reach 192.168.178.10 target-lan || fail "LAN behind node-r unreachable after recovery"

echo "== 10. the control plane changes its node-channel key: nodes refuse it until the pin is reset"
$COMPOSE stop control >/dev/null
mv state/control/nodes.key state/control/nodes.key.orig
mv state/control/nodes.crt state/control/nodes.crt.orig
$COMPOSE start control >/dev/null
wait_for 45 status_is node-a '.control_error | test("pinned key")' || fail "node-a accepted a different control plane key"
x node-a boundgatectl status | grep -q "does not match the pinned key" || fail "status does not explain the refusal"
$COMPOSE stop control >/dev/null
mv state/control/nodes.key.orig state/control/nodes.key
mv state/control/nodes.crt.orig state/control/nodes.crt
$COMPOSE start control >/dev/null
wait_for 90 status_is node-a '.enrollment == "approved" and .control_error == null' || fail "node-a did not recover after the key was restored"
wait_for 10 reach 10.60.0.10 target || fail "target unreachable after control plane restart"
x node-a boundgatectl down >/dev/null

echo "== 11. audit trail in the control plane"
$S api GET '/api/v1/admin/logs?stream=enrollment' | jq -e '[.[].message] | index("node confirmed") != null and index("node approved") != null and index("node revoked") != null and index("binding signature rejected") == null' >/dev/null || fail "enrollment log incomplete"

echo "PASS: M1.5 + M1.6 end-to-end"
