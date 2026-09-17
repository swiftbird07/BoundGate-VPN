#!/bin/sh
# Rehearsal of the server kit with real binaries in the local Docker VM:
# mux + control plane + hub on ONE address and port 443 (host network of the
# VM), and a client in its own container that enrolls, is approved and
# reaches the hub through the shared port. Nothing on the Mac is touched.
#
#   make -o web server-bundle GOARCH=arm64 && deploy/server/rehearsal.sh
#   deploy/server/rehearsal.sh down
set -eu
cd "$(dirname "$0")/../.."
W=$PWD/dist/rehearsal
P=bgrehearsal
C="docker compose -p $P -f $W/docker-compose.yml"
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; n=$((n-1)); sleep 1; done; return 1; }

if [ "${1:-}" = down ]; then
  docker rm -f $P-client >/dev/null 2>&1 || true
  [ -f "$W/docker-compose.yml" ] && $C down --remove-orphans >/dev/null 2>&1 || true
  echo "rehearsal stopped"; exit 0
fi

[ -d dist/boundgate-server/bin ] || fail "run: make -o web server-bundle GOARCH=$(uname -m | sed 's/x86_64/amd64/')"
"$0" down >/dev/null
rm -rf "$W"; mkdir -p "$W"; cp -R dist/boundgate-server/. "$W/"
GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')

echo "== 0. configuration: one address, port 443 for everything (the VM's host network; clients come in over $GW)"
sed -e 's/bg\.example\.com/bg.test/g' "$W/mux.yaml.example" > "$W/mux.yaml"
sed -e 's/bg\.example\.com/bg.test/g' -e 's/^  enabled: true.*/  enabled: false/' -e '/^oidc:/,/^  session_lifetime: 12h/d' "$W/control.yaml.example" \
  | sed -e 's|^node_cert:|tls_cert: /var/lib/boundgate/control.crt\ntls_key: /var/lib/boundgate/control.key\nnode_cert:|' > "$W/control.yaml"
sed -e 's/addr: bg\.example\.com:443/addr: 127.0.0.1:443/' -e 's/bg\.example\.com/bg.test/g' "$W/hub.yaml.example" > "$W/hub.yaml"
cat > "$W/client.yaml" <<YAML
name: client
state_dir: /var/lib/boundgate
control: {addr: "$GW:443", server_name: nodes.bg.test}
roles: [endpoint]
hub_addrs: {hub1: "$GW:443"}   # the rehearsal has no DNS; a real hub is dialed at its public_addr
socket: /run/boundgate/node.sock
tun_name: bg0
log_stdout: true
YAML

echo "== 1. start mux, control plane, hub"
$C up -d --build >/dev/null 2>&1 || fail "compose up (is port 443 of the VM free?)"
hub() { $C exec -T hub "$@"; }
wait_for 30 test -s "$W/state/control/bootstrap.token" || fail "control plane did not start: $($C logs control | tail -3)"
TOKEN=$(cat "$W/state/control/bootstrap.token")
# every admin call goes through the mux: TCP/443, SNI bg.test, PROXY protocol
api() { m=$1; p=$2; shift 2; hub curl -sS -k --resolve bg.test:443:127.0.0.1 -X "$m" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "https://bg.test$p" "$@"; }
wait_for 30 sh -c "$C exec -T hub curl -sk --resolve bg.test:443:127.0.0.1 https://bg.test/api/v1/admin/auth/status | grep -q passkeys" || fail "admin API not reachable through the mux"
echo "   admin API answers on TCP/443 through the mux"

echo "== 2. signing key, overlay pool, policy"
rm -f "$W/state/hub/signer" "$W/state/hub/signer.pub"; mkdir -p "$W/state/hub"
ssh-keygen -q -t ed25519 -N '' -C rehearsal -f "$W/signer"
hub sh -c 'cat > /var/lib/boundgate/signer; chmod 600 /var/lib/boundgate/signer' < "$W/signer"
hub sh -c 'cat > /var/lib/boundgate/control.crt' < "$W/state/control/control.crt"
hub sh -c 'grep -q bg.test /etc/hosts || echo "127.0.0.1 bg.test" >> /etc/hosts'
api POST /api/v1/admin/signers -d "$(jq -cn --arg k "$(cat "$W/signer.pub")" '{name:"rehearsal",public_key:$k}')" | jq -e .fingerprint >/dev/null || fail "signer"
api PUT /api/v1/admin/settings/network -d '{"pool":"100.96.0.0/16"}' >/dev/null
api POST /api/v1/admin/policies -d '{"name":"allow-all","cedar":"permit(principal, action, resource);","enabled":true,"scope":[]}' | jq -e .id >/dev/null || fail "policy"

approve() {  # approve ENROLL_JSON GRANT
  id=$(printf '%s' "$1" | jq -r .node_id); fp=$(printf '%s' "$1" | jq -r .fingerprint)
  tok=$(api POST "/api/v1/admin/nodes/$id/confirm" -d "{\"fingerprint\":\"$fp\",$2}" | jq -r .sign_token)
  [ -n "$tok" ] && [ "$tok" != null ] || fail "confirm $id"
  hub boundgatectl -json admin sign --control https://bg.test:443 --cacert /var/lib/boundgate/control.crt --node "$id" --fingerprint "$fp" --token "$tok" --key /var/lib/boundgate/signer \
    | jq -r '"   \(.name): \(.status) as \(.roles | join("+")), overlay \(.overlay_ip)"'
}

echo "== 3. the hub enrolls over HTTP/3 on UDP/443 (through the mux) and is approved"
wait_for 30 hub boundgatectl -json enroll || fail "hub cannot enroll: $($C logs hub | tail -3)"
approve "$(hub boundgatectl -json enroll)" '"kind":"workload","roles":["hub"],"public_addr":"bg.test:443"'
wait_for 40 sh -c "$C exec -T hub boundgatectl -json status | jq -e '.state == \"up\"'" || fail "hub did not come up"
if $C logs hub 2>&1 | grep -q 'falling back to TCP'; then fail "the hub fell back to TCP: HTTP/3 through the mux does not work"; fi
HUBIP=$(hub boundgatectl -json status | jq -r .overlay_ip)

echo "== 4. a client in its own network namespace: same address, same port, other server name"
docker run -d --name $P-client --cap-add NET_ADMIN --device /dev/net/tun -v "$W/client.yaml:/etc/boundgate/node.yaml:ro" $P-hub boundgate-node -config /etc/boundgate/node.yaml >/dev/null
cl() { docker exec $P-client "$@"; }
wait_for 30 cl boundgatectl -json enroll || fail "client cannot enroll: $(docker logs $P-client 2>&1 | tail -3)"
approve "$(cl boundgatectl -json enroll)" '"kind":"workload","roles":["endpoint"]'
wait_for 30 cl boundgatectl up || fail "client up: $(cl boundgatectl status | tail -5)"
wait_for 20 sh -c "docker exec $P-client boundgatectl -json status | jq -e '[.hubs[] | select(.state == \"connected\")] | length == 1'" || fail "no tunnel: $(cl boundgatectl status)"
if docker logs $P-client 2>&1 | grep -q 'falling back to TCP'; then fail "the client fell back to TCP"; fi
wait_for 10 cl ping -c 1 -W 2 "$HUBIP" || fail "hub $HUBIP not reachable through the tunnel"
echo "   client reaches the hub ($HUBIP) through a tunnel on the shared UDP/443"

echo "== 5. the hub sees the client's real address, not the mux"
CLIENTIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-client)
wait_for 40 sh -c "$C exec -T hub curl -sS -k --resolve bg.test:443:127.0.0.1 -H 'Authorization: Bearer $TOKEN' 'https://bg.test/api/v1/admin/tunnels?active=1' | jq -e --arg ip '$CLIENTIP' '.[] | select(.peer_addr == \$ip or (.peer_addr | startswith(\$ip + \":\")))'" \
  || fail "tunnel peer address is not $CLIENTIP: $(api GET '/api/v1/admin/tunnels?active=1' | jq -c '[.[].peer_addr]')"
echo "   peer address $CLIENTIP"

echo "== 6. the mux restarts: established tunnels continue (it keeps no connection state)"
SINCE=$(cl boundgatectl -json status | jq -r '.hubs[0].since')
$C restart mux >/dev/null 2>&1
wait_for 15 cl ping -c 1 -W 2 "$HUBIP" || fail "tunnel dead after a mux restart"
[ "$(cl boundgatectl -json status | jq -r '.hubs[0].since')" = "$SINCE" ] || fail "the tunnel was re-established instead of continuing"

"$0" down >/dev/null
echo "PASS: control plane and hub share one address and port 443 (TCP and UDP) behind boundgate-mux"
