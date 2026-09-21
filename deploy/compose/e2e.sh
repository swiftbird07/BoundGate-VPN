#!/bin/sh
# End-to-end check of milestones M1.5, M1.6, M2, M3 and M4 against the
# running compose environment: node model with hubs, subnet router, HA,
# revocation, re-enrollment, signed bindings, sign tokens, tampering,
# control-plane pin, user login (OIDC) with session revocation, logout and
# expiry enforcement, Cedar ACL with flow logs, SNI resets, dry runs, tunnel
# history, the embedded admin UI and admin authentication (OIDC session
# levels, API tokens, bootstrap restriction), TPM keys, the signed admin key
# list, and paths between spokes (relay, direct, M7). Passkey ceremonies need a
# browser and are covered by the Go tests with a software authenticator.
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.yml"
S=./setup-dev.sh
fail() { echo "FAIL: $*" >&2; exit 1; }
x() { svc=$1; shift; $COMPOSE exec -T "$svc" "$@"; }
# wait_for SECONDS CMD...: retry until the command succeeds
wait_for() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; n=$((n-1)); sleep 1; done; return 1; }
reach() { x node-a curl -sf --max-time 3 "http://$1" | grep -q "^Name: $2"; }
# reach_tls NAME IP: https with SNI=NAME against the echo server
reach_tls() { x node-a curl -sk --max-time 3 --resolve "$1:443:$2" "https://$1/" | grep -q '"hostname"'; }
policy() { $S policy "$@" >/dev/null; }
policy_rm() { $S policy-rm "$1" >/dev/null; }
status_is() { docker compose -f docker-compose.yml exec -T "$1" boundgatectl -json status | jq -e "$2" >/dev/null; }
sql() { x control sqlite3 -cmd '.timeout 5000' /var/lib/boundgate/control.db "$1"; }

fresh_key() {  # fresh_key SVC: replace the node's key (a revoked key can never come back)
  $COMPOSE stop "$1" >/dev/null
  rm -f "state/$1/device.key" "state/$1/device.crt" "state/$1/admin_trust.json"
  $COMPOSE start "$1" >/dev/null
  wait_for 15 sh -c "docker compose -f docker-compose.yml exec -T $1 boundgatectl -json status >/dev/null" || fail "$1 did not come back"
}

echo "== 0. a previous run may have left node-a revoked (then start with a fresh key) or logged in (then log out)"
# a lab from before the admin key list was signed: its nodes hold a plain key
# list and refuse to start until that pin is removed by hand, which for the
# lab is here (they then pin the signed list on first contact)
for n in hub1 hub2 node-r node-a node-t; do
  if [ -f "state/$n/admin_keys" ] && [ ! -f "state/$n/admin_trust.json" ]; then
    rm -f "state/$n/admin_keys"; $COMPOSE up -d "$n" >/dev/null 2>&1
  fi
done
if wait_for 15 sh -c 'docker compose -f docker-compose.yml exec -T node-a boundgatectl -json enroll -accept-new-pin | jq -e ".status == \"revoked\""'; then
  fresh_key node-a
fi
x node-a boundgatectl logout >/dev/null 2>&1 || true
x node-a boundgatectl down >/dev/null 2>&1 || true
x node-t boundgatectl down >/dev/null 2>&1 || true
for sid in $($S api GET /api/v1/admin/sessions | jq -r '.[].id'); do $S api DELETE "/api/v1/admin/sessions/$sid" >/dev/null || true; done
# an aborted run may have left test policies behind
for p in $($S api GET /api/v1/admin/policies | jq -r '.[] | select(.name != "lab-allow-all") | .name'); do policy_rm "$p"; done

echo "== 1. bootstrap: admin signing key, network, enroll + confirm + sign hub1, hub2, node-r, node-a, node-t"
$S all
x node-a boundgatectl -json identity | jq -e '.control_pin != "" and (.admin_keys | length) == 1' >/dev/null || fail "node-a has no control pin / admin keys"

echo "== 2. hubs and the subnet router come up on their own, with the lab policy"
wait_for 20 status_is hub1 '.state == "up" and .binding == "verified" and .policies == 1' || fail "hub1 not up (or without the policy)"
wait_for 20 status_is hub2 '.state == "up"' || fail "hub2 not up"
wait_for 20 status_is node-r '[.hubs[] | select(.state == "connected")] | length == 2' || fail "node-r not connected to both hubs"

echo "== 3. node-a (interactive): up, but every hub refuses it until the user logs in; node-r (workload) needs no login"
x node-a boundgatectl up >/dev/null
wait_for 20 status_is node-a '.login_required == true and ([.hubs[] | select(.state == "login required")] | length == 2)' || fail "hubs did not refuse node-a without a session"
if reach 10.60.0.10 target; then fail "target reachable without login"; fi
status_is node-a '.user == null and .kind == "interactive"' || fail "node-a has a user before login"
status_is node-r '.kind == "workload" and .user == null and ([.hubs[] | select(.state == "connected")] | length == 2)' || fail "workload node-r needs a login?"
echo "== 3b. login: boundgatectl login -> browser at the (fake) IdP -> callback -> session in the snapshot -> hubs admit node-a"
$S login node-a >/dev/null
wait_for 15 status_is node-a '.user.username == "martin" and (.user.groups | index("vpn-users") != null) and ([.hubs[] | select(.state == "connected")] | length == 2)' || fail "node-a not connected to both hubs after login"
$S api GET /api/v1/admin/sessions | jq -e 'length == 1 and .[0].node_name == "node-a" and .[0].username == "martin"' >/dev/null || fail "session not listed"
status_is node-a '.routes | index("10.60.0.0/24") != null and index("192.168.178.0/24") != null' || fail "routes missing"

echo "== 4. reach the target behind the hubs, the LAN behind node-r, and node-r itself"
wait_for 10 reach 10.60.0.10 target || fail "target behind hubs unreachable"
wait_for 10 reach 192.168.178.10 target-lan || fail "LAN target behind node-r unreachable"
R_IP=$(x node-r boundgatectl -json status | jq -r .overlay_ip)
x node-a ping -c 2 -W 2 "$R_IP" >/dev/null || fail "node-r overlay ip $R_IP unreachable"
H2_IP=$(x hub2 boundgatectl -json status | jq -r .overlay_ip)
x node-a ping -c 2 -W 2 "$H2_IP" >/dev/null || fail "hub2 overlay ip $H2_IP unreachable"

echo "== 4b. ACL: a forbid for the LAN prefix takes effect on hub and router within seconds; removing it restores"
wait_for 10 reach_tls public.lab 10.60.0.11 || fail "TLS target unreachable"
policy no-lan 'forbid(principal, action, resource) when { resource.ip.isInRange(ip("192.168.178.0/24")) };'
wait_for 10 sh -c '! docker compose -f docker-compose.yml exec -T node-a curl -sf --max-time 2 http://192.168.178.10 >/dev/null 2>&1' || fail "LAN still reachable with a forbid policy"
reach 10.60.0.10 target || fail "target behind the hubs affected by the LAN forbid"
wait_for 20 sh -c "$S flows 'decision=deny&dst=192.168.178.10' | grep -q 'node-a.*deny.*no-lan'" || fail "denied flow not in the shipped flow log"
# whoever admits the traffic decides: a hub, or node-r itself once node-a and node-r have a path of their own (step 15)
denied_at() { x "$1" boundgatectl -json flows | jq -e '[.[]? | select(.decision == "deny" and .principal_name == "node-a")] | length >= 1' >/dev/null; }
denied_at hub1 || denied_at hub2 || denied_at node-r || fail "no enforcing node shows the denied flow"
policy_rm no-lan
wait_for 15 reach 192.168.178.10 target-lan || fail "LAN unreachable after the forbid was removed"

echo "== 4c. ACL: SNI forbid resets the TLS handshake; other names pass; DNS names reach the policy"
policy no-secrets 'forbid(principal, action, resource) when { resource has sni && resource.sni like "secret.*" };'
wait_for 10 status_is hub1 '.policies == 2' || fail "hub1 did not get the SNI policy"
START=$(date +%s)
if reach_tls secret.lab 10.60.0.11; then fail "secret.lab reachable despite the SNI forbid"; fi
[ $(( $(date +%s) - START )) -lt 3 ] || fail "SNI forbid did not reset quickly (curl waited for a timeout)"
reach_tls public.lab 10.60.0.11 || fail "public.lab blocked by the SNI forbid"
wait_for 20 sh -c "$S api GET '/api/v1/admin/flows?decision=deny&sni=secret.lab&limit=1' | jq -e '.[0].attrs.reset == true and .[0].attrs.principal_name == \"node-a\" and .[0].attrs.username == \"martin\" and (.[0].ts > \"$(date -u +%Y-%m-%dT%H:%M)\")'" || fail "SNI denial (with reset) not in the shipped flow log"
policy_rm no-secrets
wait_for 10 reach_tls secret.lab 10.60.0.11 || fail "secret.lab unreachable after the forbid was removed"

echo "== 4d. ACL: group-based permits instead of allow-all; workloads by kind; dry run agrees with the hubs"
policy lab-allow-all 'permit(principal, action, resource) when { principal.kind == "workload" };'
policy vpn-users 'permit(principal in BoundGate::Group::"vpn-users", action, resource in BoundGate::Network::"10.60.0.0/24");'
wait_for 10 status_is hub1 '.policies == 2' || fail "hub1 did not get the group policies"
wait_for 10 reach 10.60.0.10 target || fail "group member cannot reach the target"
wait_for 10 sh -c '! docker compose -f docker-compose.yml exec -T node-a curl -sf --max-time 2 http://192.168.178.10 >/dev/null 2>&1' || fail "LAN reachable without a permit"
$S eval node-a 10.60.0.10 80 | jq -e '.allow == true and .user != null and (.policies | index("vpn-users") != null) and .owner_name == "hub1"' >/dev/null || fail "dry run disagrees (target)"
$S eval node-a 192.168.178.10 80 | jq -e '.allow == false and .owner_name == "node-r"' >/dev/null || fail "dry run disagrees (LAN)"
$S eval node-r 10.60.0.10 22 | jq -e '.allow == true and .user == null' >/dev/null || fail "dry run disagrees (workload)"
policy lab-allow-all 'permit(principal, action, resource);'
policy_rm vpn-users
wait_for 15 reach 192.168.178.10 target-lan || fail "LAN unreachable after restoring allow-all"

echo "== 4e. tunnel history: every spoke-hub tunnel is reported by its hub (paths between spokes, reported by the accepting spoke, are step 15)"
wait_for 40 sh -c "$S api GET '/api/v1/admin/tunnels?active=1' | jq -e '([.[] | select(.hub_name == \"hub1\" and .peer_name == \"node-a\")] | length) == 1 and ([.[] | select(.peer_name == \"node-r\" and (.hub_name | startswith(\"hub\")))] | length) == 2'" || fail "active tunnels not reported"
wait_for 45 sh -c "$S api GET '/api/v1/admin/tunnels?active=1' | jq -e '[.[] | select(.bytes_in > 0)] | length >= 2'" || fail "tunnel counters stay at zero (hubs report every 30 s)"

echo "== 5. HA: stop hub1, traffic moves to hub2 within 10 s, hub1 comes back"
$COMPOSE stop hub1 >/dev/null
START=$(date +%s)
wait_for 10 reach 10.60.0.10 target || fail "target unreachable after hub1 stopped"
echo "   failover took $(( $(date +%s) - START )) s"
status_is node-a '.hubs[] | select(.name == "hub2") | .primary == true' || fail "hub2 not primary"
$COMPOSE start hub1 >/dev/null
wait_for 30 status_is node-a '[.hubs[] | select(.state == "connected")] | length == 2' || fail "node-a did not reconnect to hub1"

echo "== 5b. session revoked by an admin: hubs close node-a's tunnels within seconds; login again restores; logout drops"
SESSION=$($S api GET /api/v1/admin/sessions | jq -r '.[0].id')
$S api DELETE "/api/v1/admin/sessions/$SESSION"
wait_for 10 status_is node-a '.user == null and ([.hubs[] | select(.state == "connected")] | length == 0)' || fail "tunnels survived the session revocation"
if reach 10.60.0.10 target; then fail "target reachable after session revocation"; fi
$S login node-a >/dev/null
wait_for 20 reach 10.60.0.10 target || fail "target unreachable after re-login"
x node-a boundgatectl logout >/dev/null
wait_for 10 status_is node-a '.user == null and ([.hubs[] | select(.state == "connected")] | length == 0)' || fail "tunnels survived the logout"
$S login node-a >/dev/null
wait_for 20 reach 10.60.0.10 target || fail "target unreachable after login"

echo "== 6. revoke node-a while up: tunnels close, up fails, key cannot re-enroll"
OLD_ID=$(x node-a boundgatectl -json identity | jq -r .node_id)
$S revoke node-a >/dev/null
wait_for 5 status_is node-a '.state == "down"' || fail "node-a not down after revocation"
status_is node-a '.last_close | test("revoked|no longer approved")' || fail "unexpected close reason"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "revoked node came up"; fi
x node-a boundgatectl -json enroll -accept-new-pin | jq -e '.status == "revoked"' >/dev/null || fail "revoked key got a new status"
status_is hub1 '.tunnels == 1' || fail "hub1 still has node-a's tunnel"
wait_for 20 sh -c "$S api GET '/api/v1/admin/tunnels?node=$OLD_ID' | jq -e '[.[] | select(.closed_at != null and (.close_reason | test(\"revoked\")))] | length >= 1'" || fail "revoked node's tunnels not closed in the history"

echo "== 7. fresh key: enroll -> pending -> confirm (not enough) -> sign -> approved -> up; token is single use"
fresh_key node-a
wait_for 10 sh -c 'docker compose -f docker-compose.yml exec -T node-a boundgatectl -json enroll -accept-new-pin | jq -e ".status == \"pending\""' || fail "new key not pending"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "pending node came up"; fi
$S confirm node-a >/dev/null
wait_for 10 sh -c 'docker compose -f docker-compose.yml exec -T node-a boundgatectl -json enroll -accept-new-pin | jq -e ".status == \"confirmed\""' || fail "node-a not confirmed"
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
$S login node-a >/dev/null
wait_for 15 reach 10.60.0.10 target || fail "target unreachable after re-enrollment"

echo "== 8. changing a signed field (roles) drops the approval until re-signed"
$S api PATCH "/api/v1/admin/nodes/$ID" '{"roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"10.99.0.0/24","mode":"routed"}]}' | jq -e '.status == "confirmed" and .sign_token != null' >/dev/null || fail "patch did not demote"
wait_for 10 status_is node-a '.state == "down"' || fail "node-a still up after its grant changed"
if x node-a boundgatectl up >/dev/null 2>&1; then fail "demoted node came up"; fi
$S sign node-a >/dev/null
wait_for 10 status_is node-a '.enrollment == "approved" and .binding == "verified"' || fail "node-a not re-approved"
x node-a boundgatectl up >/dev/null
wait_for 15 reach 10.60.0.10 target || fail "target unreachable after re-sign (the session survived the re-sign)"
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
$S api GET '/api/v1/admin/logs?stream=user-auth' | jq -e '[.[].message] | index("login started") != null and index("login completed") != null and index("session revoked") != null and index("logout") != null' >/dev/null || fail "user-auth log incomplete"
$S api GET '/api/v1/admin/logs?stream=audit' | jq -e '[.[].message] | index("policy created") != null and index("policy updated") != null and index("policy deleted") != null' >/dev/null || fail "policy audit incomplete"
$S api GET '/api/v1/admin/flows?event=close&limit=5' | jq -e 'length >= 1 and .[0].attrs.duration_ms != null' >/dev/null || fail "no closed flows shipped"

echo "== 12. admin UI and admin auth: SPA served, status, API token, OIDC admin session stays oidc_only without a passkey"
ADMIN=https://localhost:18443
CA=state/control/control.crt
curl -sf --cacert $CA "$ADMIN/" | grep -q '<title>BoundGate</title>' || fail "SPA not served at /"
curl -sf --cacert $CA "$ADMIN/policies/new" | grep -q '<title>BoundGate</title>' || fail "SPA history fallback missing"
curl -s --cacert $CA -o /dev/null -w '%{http_code}' "$ADMIN/api/v1/admin/nodes" | grep -q '^401$' || fail "admin API reachable without auth"
curl -sf --cacert $CA "$ADMIN/api/v1/admin/auth/status" | jq -e '.level == "none" and .bootstrap_active == (.total_passkeys == 0) and .oidc_configured == true and .passkeys_enabled == true and .rp_id == "localhost"' >/dev/null || fail "auth status wrong"
TOK=$($S api POST /api/v1/admin/tokens '{"name":"e2e","expires_in":"1h"}' | jq -r .token)
echo "$TOK" | grep -q '^bgapi_' || fail "no api token minted"
curl -sf --cacert $CA -H "Authorization: Bearer $TOK" "$ADMIN/api/v1/admin/overview" | jq -e '.nodes.approved >= 3 and .policies >= 1' >/dev/null || fail "overview via api token failed"
TID=$($S api GET /api/v1/admin/tokens | jq -r '.[] | select(.name == "e2e" and .revoked_at == null) | .id')
$S api DELETE "/api/v1/admin/tokens/$TID" >/dev/null
curl -s --cacert $CA -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$ADMIN/api/v1/admin/overview" | grep -q '^401$' || fail "revoked api token still works"
# draft evaluation for the policy editor's sanity check: the draft flips the decision without being stored
$S api POST /api/v1/admin/acl/evaluate '{"node":"node-a","dst":"192.168.178.10","port":80,"draft":{"id":"d","name":"draft-forbid","cedar":"forbid(principal, action, resource) when { resource.port == 80 };"}}' | jq -e '.allow == false and (.policies | index("draft-forbid") != null)' >/dev/null || fail "draft evaluation ignored the draft"
$S api POST /api/v1/admin/acl/evaluate '{"node":"node-a","dst":"192.168.178.10","port":80}' | jq -e '.allow == true' >/dev/null || fail "draft leaked into stored policies"
# every Cedar text the policy builder can generate is accepted by the real parser
(cd ../.. && box sh -c 'cd web && npm test --silent') > /tmp/bg-builder.$$ || fail "policy builder self-test"
while IFS= read -r line; do
  $S api POST /api/v1/admin/policies/validate "$line" | jq -e '.ok == true' >/dev/null || fail "builder generated invalid Cedar: $line"
done < /tmp/bg-builder.$$
rm -f /tmp/bg-builder.$$
# the admin OIDC login in a "browser" (cookie jar): the session exists but stays oidc_only
ADMIN=http://localhost:18080   # the browser's way in: the devproxy (same control plane, plain HTTP on localhost)
curl -sf "$ADMIN/" | grep -q '<title>BoundGate</title>' || fail "SPA not served through the devproxy"
JAR=$(mktemp)
LOC=$(curl -s --cacert $CA -c "$JAR" -o /dev/null -w '%{redirect_url}' "$ADMIN/api/v1/admin/auth/login?next=/nodes")
echo "$LOC" | grep -q '^http://idp.localhost:19000/' || fail "admin login did not redirect to the IdP: $LOC"
CB=$(curl -s -o /dev/null -w '%{redirect_url}' "$LOC")
curl -s --cacert $CA -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code} %{redirect_url}' "$CB" | grep -q '^302 .*/nodes$' || fail "admin callback did not create a session"
curl -sf --cacert $CA -b "$JAR" "$ADMIN/api/v1/admin/auth/status" | jq -e '.level == "oidc_only" and .subject != "" and .via == "session"' >/dev/null || fail "admin session missing"
curl -s --cacert $CA -b "$JAR" -o /dev/null -w '%{http_code}' "$ADMIN/api/v1/admin/nodes" | grep -q '^403$' || fail "oidc_only session reached the admin API"
curl -s --cacert $CA -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$ADMIN/api/v1/admin/auth/logout" | grep -q '^403$' || fail "CSRF header not enforced"
curl -s --cacert $CA -b "$JAR" -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: BoundGate' "$ADMIN/api/v1/admin/auth/logout" | grep -q '^204$' || fail "logout failed"
curl -sf --cacert $CA -b "$JAR" "$ADMIN/api/v1/admin/auth/status" | jq -e '.level == "none"' >/dev/null || fail "session survived logout"
rm -f "$JAR"
$S api GET '/api/v1/admin/logs?stream=admin-auth' | jq -e '[.[].message] | index("admin login (oidc)") != null and index("admin logout") != null and index("api token created") != null and index("api token revoked") != null' >/dev/null || fail "admin-auth audit incomplete"

echo "== 13. TPM: node-t keeps its key in a (software) TPM; hardware_bound is granted, signed and usable in policies"
x node-t boundgatectl -json identity | jq -e '.key_kind == "tpm2" and .hardware_bound == true' >/dev/null || fail "node-t does not use a TPM key"
[ -s state/node-t/device.tpm ] && [ ! -e state/node-t/device.key ] || fail "node-t: expected a wrapped TPM blob and no software key"
$S api GET /api/v1/admin/nodes | jq -e '[.[] | select(.status == "approved")] | (map(select(.hardware_bound)) | map(.name)) == ["node-t"] and (map(select(.hardware_claimed)) | length) == 1' >/dev/null || fail "hardware_bound granted to the wrong set of nodes"
$S api GET "/api/v1/admin/snapshot?node=$($S api GET /api/v1/admin/nodes | jq -r '.[] | select(.name == "hub1" and .status == "approved") | .id')" | jq -e '.peers[] | select(.name == "node-t") | .hardware_bound == true and (.binding | contains("\"hardware_bound\":true"))' >/dev/null || fail "hub1's snapshot does not carry the signed hardware_bound"
x node-t boundgatectl up >/dev/null
reach_t() { x node-t curl -sf --max-time 3 http://10.60.0.10 | grep -q '^Name: target'; }
reach_r() { x node-r curl -sf --max-time 3 http://10.60.0.10 | grep -q '^Name: target'; }
wait_for 20 reach_t || fail "node-t cannot reach the target (TLS client auth with the TPM key)"
wait_for 10 reach_r || fail "node-r cannot reach the target before the policy change"
policy lab-allow-all 'permit(principal, action, resource) when { principal.hardware_bound };'
wait_for 15 sh -c '! docker compose -f docker-compose.yml exec -T node-r curl -sf --max-time 2 http://10.60.0.10 >/dev/null 2>&1' || fail "software-key node still admitted by a hardware_bound policy"
reach_t || fail "hardware-bound node refused by a hardware_bound policy"
$S eval node-t 10.60.0.10 80 | jq -e '.allow == true' >/dev/null || fail "dry run disagrees (node-t)"
$S eval node-r 10.60.0.10 80 | jq -e '.allow == false' >/dev/null || fail "dry run disagrees (node-r)"
# a control plane that declares a software-key node hardware-bound: the signature no longer covers the record
sql "UPDATE nodes SET hardware_bound = 1 WHERE name = 'node-r' AND status = 'approved'; UPDATE snapshot_version SET version = version + 1;"
wait_for 45 status_is hub1 '.ignored_peers | length == 1 and (.[0] | test("node-r"))' || fail "hub1 accepted a forged hardware_bound"
wait_for 45 status_is node-r '.binding == "invalid"' || fail "node-r accepted a forged hardware_bound for itself"
sql "UPDATE nodes SET hardware_bound = 0 WHERE name = 'node-r' AND status = 'approved'; UPDATE snapshot_version SET version = version + 1;"
wait_for 60 status_is node-r '.binding == "verified" and .state == "up"' || fail "node-r did not recover"
policy lab-allow-all 'permit(principal, action, resource);'
wait_for 20 reach_r || fail "node-r cannot reach the target after restoring allow-all"
x node-t boundgatectl down >/dev/null

echo "== 14. admin key list: a second key joins with the first key's signature, nodes follow without re-enrolling; nothing else moves the list"
SS="boundgatectl -json admin sign-signers --control https://localhost:443 --cacert /var/lib/boundgate/control.crt --yes --pin-dir /var/lib/boundgate/signer-pins"
K1=/var/lib/boundgate/admin_signer; K2=/var/lib/boundgate/admin_signer2
x control sh -c "rm -f $K2 $K2.pub; ssh-keygen -q -t ed25519 -N '' -C second-admin -f $K2"
# relative to where the list stands: a lab that ran this before is further along
V0=$(x hub1 boundgatectl -json status | jq -r .admin_set_version); V1=$((V0 + 1)); V2=$((V0 + 2))
[ "$V0" -ge 1 ] || fail "hub1 has not pinned a signed admin key list"
for n in hub1 hub2 node-r node-a; do
  status_is $n ".admin_set_version == $V0 and (.admin_keys | length == 1)" || fail "$n has not pinned the signed list (version $V0)"
done
STOK=$($S api POST /api/v1/admin/signers "$(jq -cn --arg k "$(x control cat $K2.pub)" '{name:"second-admin",public_key:$k}')" | jq -r .sign_token)
$S api GET /api/v1/admin/signers | jq -e '[.[] | select(.active)] | length == 1' >/dev/null || fail "a proposed key is already active"
if x control $SS --token "$STOK" --key $K2 >/dev/null 2>&1; then fail "the key being added signed itself into the list"; fi
x control $SS --token "$STOK" --key $K1 | jq -e ".version == $V1" >/dev/null || fail "first admin could not add the second key"
if x control $SS --token "$STOK" --key $K1 >/dev/null 2>&1; then fail "signer change token accepted twice"; fi
for n in hub1 hub2 node-r node-a; do
  wait_for 45 status_is $n ".admin_set_version == $V1 and (.admin_keys | length == 2) and .admin_trust_error == null and .binding == \"verified\"" || fail "$n did not follow the list to version $V1"
done
# the new key approves a node, and every peer accepts that signature
ID=$(x node-a boundgatectl -json identity | jq -r .node_id); FP=$(x node-a boundgatectl -json identity | jq -r .spki)
TOKEN=$($S api PATCH "/api/v1/admin/nodes/$ID" '{"roles":["endpoint"],"prefixes":[]}' | jq -r .sign_token)
x control boundgatectl admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt --node "$ID" --fingerprint "$FP" --token "$TOKEN" --key $K2 >/dev/null || fail "second admin key could not sign a node"
wait_for 15 status_is node-a '.enrollment == "approved" and .binding == "verified"' || fail "node-a does not verify a binding signed by the new key"
x node-a boundgatectl up >/dev/null
wait_for 20 reach 10.60.0.10 target || fail "hubs refuse a node signed by the new admin key"
# a control plane that writes its own list: forged link, signed by a key the nodes never trusted
x control sh -c "rm -f /tmp/evil /tmp/evil.pub; ssh-keygen -q -t ed25519 -N '' -f /tmp/evil"
HEAD=$(sql "SELECT hash FROM signer_sets WHERE version = $V1;")
EVIL=$(x control awk '{print $1" "$2}' /tmp/evil.pub)
FORGED=$(jq -cnj --arg prev "$HEAD" --arg k "$EVIL" --argjson v "$V2" '{type:"boundgate-signer-set",version:$v,prev:$prev,keys:[$k]}')
x control sh -c "printf '%s' '$FORGED' > /tmp/forged && ssh-keygen -q -Y sign -n boundgate-signers -f /tmp/evil /tmp/forged"
FSIG=$(x control cat /tmp/forged.sig)
sql "INSERT INTO signer_sets (version, set_json, signature, hash, signed_by, admin, created_at) VALUES ($V2, '$FORGED', '$FSIG', 'forged', 'evil', 'root', '2026-01-01T00:00:00.000000000Z'); UPDATE snapshot_version SET version = version + 1;"
for n in hub1 node-a; do
  wait_for 45 status_is $n ".admin_trust_error != null and .admin_set_version == $V1 and (.admin_keys | length == 2)" || fail "$n did not refuse a forged admin key list"
done
reach 10.60.0.10 target || fail "traffic stopped although the pinned list is still valid"
sql "DELETE FROM signer_sets WHERE version = $V2; UPDATE snapshot_version SET version = version + 1;"
wait_for 45 status_is node-a '.admin_trust_error == null' || fail "node-a did not recover after the forged link was removed"
# the first admin removes the second key again: node-a, signed by it, loses its approval until re-signed
RID=$($S api GET /api/v1/admin/signers | jq -r '.[] | select(.name == "second-admin" and .active) | .id')
STOK=$($S api DELETE "/api/v1/admin/signers/$RID" | jq -r .sign_token)
if x control $SS --token "$STOK" --key /tmp/evil >/dev/null 2>&1; then fail "a stranger removed an admin key"; fi
x control $SS --token "$STOK" --key $K1 | jq -e ".version == $V2 and (.demoted_nodes | length == 1)" >/dev/null || fail "removing the second key"
wait_for 20 status_is node-a '.state == "down"' || fail "node-a, signed by the removed key, is still up"
wait_for 45 status_is hub1 ".admin_set_version == $V2 and (.admin_keys | length == 1)" || fail "hub1 did not follow the list to version $V2"
TOKEN=$($S api POST "/api/v1/admin/nodes/$ID/confirm" "{\"fingerprint\":\"$FP\"}" | jq -r .sign_token)
if x control boundgatectl admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt --node "$ID" --fingerprint "$FP" --token "$TOKEN" --key $K2 >/dev/null 2>&1; then fail "a removed admin key approved a node"; fi
x control boundgatectl admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt --node "$ID" --fingerprint "$FP" --token "$TOKEN" --key $K1 >/dev/null || fail "re-sign with the remaining key"
wait_for 15 status_is node-a ".enrollment == \"approved\" and .binding == \"verified\" and .admin_set_version == $V2" || fail "node-a not re-approved"
x node-a boundgatectl up >/dev/null
wait_for 20 reach 10.60.0.10 target || fail "target unreachable after the key rotation"

echo "== 15. paths between spokes: through a hub's relay, direct where a peer announces an address; the receiving node decides; the relaying hub may go away"
path_of() { x "$1" boundgatectl -json status | jq -r "[.paths[]? | select(.peer == \"$2\")][0].$3 // empty"; }
x node-t boundgatectl up >/dev/null 2>&1 || true
TID=$(x node-t boundgatectl -json identity | jq -r .node_id)
$S api PATCH "/api/v1/admin/nodes/$TID" '{"public_addr":"172.30.0.40:4443"}' | jq -e '.status == "approved"' >/dev/null || fail "announcing an address must not cost node-t its approval"
wait_for 20 status_is node-t '.state == "up"' || fail "node-t is not up"
T_IP=$(x node-t boundgatectl -json status | jq -r .overlay_ip)
# relay: neither node-a nor node-r has an address; the first packets go over the hub and start the path
wait_for 20 x node-a ping -c 1 -W 2 "$R_IP" || fail "node-r unreachable"
wait_for 20 sh -c "[ -n \"\$(docker compose -f docker-compose.yml exec -T node-a boundgatectl -json status | jq -r '[.paths[]? | select(.peer == \"node-r\" and (.via | startswith(\"relay \")))][0].via // empty')\" ]" || fail "no relayed path between node-a and node-r"
VIA=$(path_of node-a node-r via); RHUB=${VIA#relay }
SIDES="$(path_of node-a node-r side) $(path_of node-r node-a side)"
[ "$SIDES" = "dialed accepted" ] || [ "$SIDES" = "accepted dialed" ] || fail "exactly one of the two dials: $SIDES"
[ "$(x node-a boundgatectl -json status | jq '[.paths[]? | select(.peer == "node-r")] | length')" = 1 ] || fail "more than one path between node-a and node-r"
B0=$(path_of node-a node-r bytes_in)
x node-a curl -sf --max-time 10 -o /dev/null 'http://192.168.178.10/data?size=300&unit=kb' || fail "download from the LAN behind node-r"
B1=$(path_of node-a node-r bytes_in)
[ $((B1 - B0)) -ge 300000 ] || fail "the download did not take the path ($B0 -> $B1); packets larger than the relayed path must be answered with the size that fits"
status_is "$RHUB" '.relay.dialers >= 1 and .relay.packets > 100' || fail "$RHUB does not count what it relays"
# the hub only sees ciphertext, so the receiving node is the one that decides
policy no-lan 'forbid(principal, action, resource) when { resource.ip.isInRange(ip("192.168.178.0/24")) };'
wait_for 10 sh -c '! docker compose -f docker-compose.yml exec -T node-a curl -sf --max-time 2 http://192.168.178.10 >/dev/null 2>&1' || fail "LAN still reachable over the path with a forbid policy"
x node-r boundgatectl -json flows | jq -e '[.[]? | select(.decision == "deny" and .principal_name == "node-a" and (.policies | index("no-lan")))] | length >= 1' >/dev/null || fail "node-r did not decide the flow that reached it over the path"
policy_rm no-lan
wait_for 15 reach 192.168.178.10 target-lan || fail "LAN unreachable after the forbid was removed"
# direct: node-t announces an address, so node-a dials it without a hub in between
wait_for 20 x node-a ping -c 1 -W 2 "$T_IP" || fail "node-t unreachable"
wait_for 20 status_is node-a '[.paths[]? | select(.peer == "node-t" and .via == "direct" and .side == "dialed")] | length == 1' || fail "node-a did not dial node-t directly"
status_is node-t '[.paths[]? | select(.peer == "node-a" and .via == "direct" and .side == "accepted")] | length == 1' || fail "node-t does not show the accepted path"
wait_for 40 sh -c "$S api GET '/api/v1/admin/tunnels?active=1' | jq -e '([.[] | select(.transport == \"relay\" and ([.hub_name, .peer_name] | sort) == [\"node-a\", \"node-r\"])] | length) == 1 and ([.[] | select(.hub_name == \"node-t\" and .peer_name == \"node-a\" and .transport == \"quic\")] | length) == 1'" || fail "paths are missing from the tunnel history (the accepting node reports them)"
# a relay pairs approved nodes only: a node without its user session is refused like at a hub, and loses the paths it had
SESSION=$($S api GET /api/v1/admin/sessions | jq -r '.[] | select(.node_name == "node-a") | .id' | head -1)
$S api DELETE "/api/v1/admin/sessions/$SESSION"
wait_for 15 status_is node-t '[.paths[]? | select(.peer == "node-a")] | length == 0' || fail "node-t kept the path of a node whose user session was revoked"
wait_for 15 status_is node-r '[.paths[]? | select(.peer == "node-a")] | length == 0' || fail "node-r kept the path of a node whose user session was revoked"
$S login node-a >/dev/null
wait_for 20 reach 192.168.178.10 target-lan || fail "LAN unreachable after re-login"
wait_for 60 sh -c "docker compose -f docker-compose.yml exec -T node-a ping -c 1 -W 1 $R_IP >/dev/null; [ -n \"\$(docker compose -f docker-compose.yml exec -T node-a boundgatectl -json status | jq -r '[.paths[]? | select(.peer == \"node-r\")][0].via // empty')\" ]" || fail "the path to node-r did not come back after the login"
# the relaying hub stops: traffic is back on the other hub at once, and the path forms again through it
VIA=$(path_of node-a node-r via); RHUB=${VIA#relay }; [ "$RHUB" = hub1 ] && OTHER=hub2 || OTHER=hub1
$COMPOSE stop "$RHUB" >/dev/null
START=$(date +%s)
wait_for 5 reach 192.168.178.10 target-lan || fail "LAN unreachable after the relaying hub $RHUB stopped"
echo "   back on the hub path after $(( $(date +%s) - START )) s"
wait_for 60 sh -c "docker compose -f docker-compose.yml exec -T node-a ping -c 1 -W 1 $R_IP >/dev/null; [ \"\$(docker compose -f docker-compose.yml exec -T node-a boundgatectl -json status | jq -r '[.paths[]? | select(.peer == \"node-r\")][0].via // empty')\" = 'relay $OTHER' ]" || fail "the path did not move to the relay of $OTHER"
$COMPOSE start "$RHUB" >/dev/null
wait_for 30 status_is node-a '[.hubs[] | select(.state == "connected")] | length == 2' || fail "node-a did not reconnect to $RHUB"

echo "== 16. the apps' embedded engine (node-m): settings in one piece, the tunnel by descriptor, the key as a signer"
x node-m boundgatectl logout >/dev/null 2>&1 || true
x node-m boundgatectl down >/dev/null 2>&1 || true
status_is node-m '.binding == "verified" and .kind == "interactive"' || fail "node-m is not approved"
x node-m boundgatectl up >/dev/null
wait_for 20 status_is node-m '.login_required == true' || fail "hubs did not ask node-m for a login"
$S login node-m >/dev/null
wait_for 20 status_is node-m '.state == "up" and ([.hubs[] | select(.state == "connected")] | length == 2)' || fail "node-m not connected to both hubs"
# what the platform was handed: address, MTU and the routes, on the device it opened
x node-m sh -c "ip -br addr show bgm0 | grep -q ' $(x node-m boundgatectl -json status | jq -r .overlay_ip)/32' && ip route | grep -q '^10.60.0.0/24 dev bgm0' && [ \$(cat /sys/class/net/bgm0/mtu) = 1230 ]" || fail "node-m's platform did not get the settings"
wait_for 10 sh -c 'docker compose -f docker-compose.yml exec -T node-m curl -sf --max-time 3 http://10.60.0.10 | grep -q "^Name: target"' || fail "target unreachable from node-m"
# down releases the device; up gets a new one from the platform
x node-m boundgatectl down >/dev/null
x node-m sh -c '! ip link show bgm0 2>/dev/null' || fail "the tun device outlived down"
x node-m boundgatectl up >/dev/null
wait_for 20 sh -c 'docker compose -f docker-compose.yml exec -T node-m curl -sf --max-time 3 http://10.60.0.10 | grep -q "^Name: target"' || fail "target unreachable after down and up"
x node-m boundgatectl logout >/dev/null
x node-m boundgatectl down >/dev/null

echo "PASS: M1.5 + M1.6 + M2 + M3 + M4 + M6 + signed admin key list + M7 paths + M8.5 embedded engine end-to-end"
