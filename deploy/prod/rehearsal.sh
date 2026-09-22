#!/bin/sh
# Rehearsal of the all-in-one kit with the real image in the local Docker VM:
# mux + control plane + hub on ONE address and port 443 (host network of the
# VM), and a client in its own container that enrolls, is approved and
# reaches the hub through the shared port. Nothing on the Mac is touched.
# The compose file is the shipped one; only the image is the locally built
# boundgate:local (make image) instead of the registry's :latest.
#
#   make rehearsal              (= make image && deploy/prod/rehearsal.sh)
#   deploy/prod/rehearsal.sh down
#
# FRONT=nginx puts a stock nginx on TCP/443 instead of the mux (which then
# serves UDP only, no_tcp): SNI passthrough with `ssl_preread`, PROXY protocol
# v1 as nginx sends it. This is the "reverse proxy stays in front" setup of
# docs/DEPLOY.md. NGINX_STREAM_FILE=<file> uses that stream{} block instead of
# the built-in one (e.g. what nginx-waf's render-sites.py wrote for a
# [[boundgate]] entry with control 127.0.0.1:8443, hub 127.0.0.1:8444).
set -eu
cd "$(dirname "$0")/../.."
W=$PWD/dist/rehearsal
P=bgrehearsal
IMAGE=${BOUNDGATE_IMAGE:-boundgate:local}
C="docker compose -p $P -f $W/docker-compose.yml --profile mux"
export BOUNDGATE_IMAGE=$IMAGE
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { n=$1; shift; while [ "$n" -gt 0 ]; do "$@" >/dev/null 2>&1 && return 0; n=$((n-1)); sleep 1; done; return 1; }

if [ "${1:-}" = down ]; then
  docker rm -f $P-client $P-nginx $P-target >/dev/null 2>&1 || true
  docker network rm $P-lan >/dev/null 2>&1 || true
  [ -f "$W/docker-compose.yml" ] && $C down --remove-orphans >/dev/null 2>&1 || true
  echo "rehearsal stopped"; exit 0
fi

docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "no image $IMAGE: run make image"
"$0" down >/dev/null
rm -rf "$W"; mkdir -p "$W"; cp -R deploy/prod/all-in-one/. "$W/"
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
quic_retry: 10s                # step 7: back to QUIC quickly once UDP works again (default 2m)
socket: /run/boundgate/node.sock
tun_name: bg0
log_stdout: true
YAML

if [ "${FRONT:-mux}" = nginx ]; then
  echo "   front: nginx on TCP/443 (SNI passthrough, PROXY v1), mux on UDP/443 only"
  sed -i.bak -e 's/^# no_tcp: true/no_tcp: true/' "$W/mux.yaml" && grep -q '^no_tcp: true' "$W/mux.yaml" || fail "could not switch the mux to no_tcp"
  mkdir -p "$W/nginx"
  if [ -n "${NGINX_STREAM_FILE:-}" ]; then
    cp "$NGINX_STREAM_FILE" "$W/nginx/streams.main"
  else
    cat > "$W/nginx/streams.main" <<'NGX'
stream {
  map $ssl_preread_server_name $bg_backend {
    bg.test        127.0.0.1:8443;
    nodes.bg.test  127.0.0.1:8443;
    hub.boundgate  127.0.0.1:8444;
    default        127.0.0.1:9;
  }
  server {
    listen 443;
    ssl_preread on;
    proxy_protocol on;
    proxy_pass $bg_backend;
  }
}
NGX
  fi
  printf 'events {}\ninclude /etc/nginx/bg/streams.main;\n' > "$W/nginx/nginx.conf"
  docker run -d --name $P-nginx --network host -v "$W/nginx:/etc/nginx/bg:ro" nginx:stable-alpine nginx -g 'daemon off;' -c /etc/nginx/bg/nginx.conf >/dev/null \
    || fail "nginx front"
fi

echo "== 1. start mux, control plane, hub"
$C up -d >/dev/null 2>&1 || fail "compose up (is port 443 of the VM free?): $($C up -d 2>&1 | tail -3)"
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
stok=$(api POST /api/v1/admin/signers -d "$(jq -cn --arg k "$(cat "$W/signer.pub")" '{name:"rehearsal",public_key:$k}')" | jq -r .sign_token)
hub boundgatectl -json admin sign-signers --control https://bg.test:443 --cacert /var/lib/boundgate/control.crt --token "$stok" --key /var/lib/boundgate/signer --yes --pin-dir /var/lib/boundgate/signer-pins | jq -e '.version == 1' >/dev/null || fail "first admin key list"
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
wait_for 30 hub boundgatectl -json enroll -accept-new-pin || fail "hub cannot enroll: $($C logs hub | tail -3)"
# the hub is the exit node too (step 8)
approve "$(hub boundgatectl -json enroll -accept-new-pin)" '"kind":"workload","roles":["hub","exit-node"],"prefixes":[{"prefix":"0.0.0.0/0","mode":"snat"}],"public_addr":"bg.test:443"'
wait_for 40 sh -c "$C exec -T hub boundgatectl -json status | jq -e '.state == \"up\"'" || fail "hub did not come up"
if $C logs hub 2>&1 | grep -q 'falling back to TCP'; then fail "the hub fell back to TCP: HTTP/3 through the mux does not work"; fi
HUBIP=$(hub boundgatectl -json status | jq -r .overlay_ip)

echo "== 4. a client in its own network namespace: same address, same port, other server name"
docker run -d --name $P-client --cap-add NET_ADMIN --device /dev/net/tun -v "$W/client.yaml:/etc/boundgate/node.yaml:ro" "$IMAGE" boundgate-node -config /etc/boundgate/node.yaml >/dev/null
cl() { docker exec $P-client "$@"; }
wait_for 30 cl boundgatectl -json enroll -accept-new-pin || fail "client cannot enroll: $(docker logs $P-client 2>&1 | tail -3)"
approve "$(cl boundgatectl -json enroll -accept-new-pin)" '"kind":"workload","roles":["endpoint"]'
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

echo "== 7. UDP blocked on the client's side: the tunnel falls back to TCP/443 through the mux, then returns to QUIC"
cl nft add table ip blk || fail "nft in the client container"
cl nft add chain ip blk out '{ type filter hook output priority 0; }'
cl nft add rule ip blk out udp dport 443 drop
cl boundgatectl down >/dev/null && wait_for 30 cl boundgatectl up || fail "client up with UDP blocked: $(cl boundgatectl status | tail -5)"
wait_for 60 sh -c "docker exec $P-client boundgatectl -json status | jq -e '[.hubs[] | select(.state == \"connected\" and .transport == \"tcp\")] | length == 1'" || fail "no TCP fallback tunnel: $(cl boundgatectl status | tail -4)"
wait_for 10 cl ping -c 1 -W 2 "$HUBIP" || fail "hub $HUBIP not reachable over the TCP fallback"
echo "   tunnel up over TCP, hub reachable"
wait_for 40 sh -c "$C exec -T hub curl -sS -k --resolve bg.test:443:127.0.0.1 -H 'Authorization: Bearer $TOKEN' 'https://bg.test/api/v1/admin/tunnels?active=1' | jq -e --arg ip '$CLIENTIP' '.[] | select(.transport == \"tcp\" and (.peer_addr == \$ip or (.peer_addr | startswith(\$ip + \":\"))))'" \
  || fail "the hub does not see the client's address on the TCP tunnel (PROXY protocol through the mux)"
echo "   the hub sees the client's real address on TCP too"
cl nft delete table ip blk
wait_for 60 sh -c "docker exec $P-client boundgatectl -json status | jq -e '[.hubs[] | select(.state == \"connected\" and .transport == \"quic\")] | length == 1'" || fail "did not return to QUIC: $(cl boundgatectl status | tail -4)"
wait_for 10 cl ping -c 1 -W 2 "$HUBIP" || fail "hub unreachable after the move back to QUIC"
echo "   back on QUIC, hub reachable"


echo "== 8. exit node on a Docker host: 20 MB through the tunnel, the mux and the host's forwarding (MTU, DOCKER-USER), over QUIC and over TCP"
# The target sits in a Docker network of its own: the client's container
# cannot reach it directly (Docker isolates its bridges), only through the
# hub, which forwards from bg0 into that bridge past Docker's FORWARD policy
# and masquerades, as it does towards the internet. nat-unprotected: Docker
# 28 and later otherwise drop packets for a container address that arrive on
# another interface (raw PREROUTING, before DOCKER-USER; docs/DEPLOY.md).
docker network create -o com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected $P-lan >/dev/null || fail "network $P-lan"
docker run -d --name $P-target --network $P-lan nginx:stable-alpine \
  sh -c 'head -c 20000000 /dev/urandom > /usr/share/nginx/html/big && exec nginx -g "daemon off;"' >/dev/null || fail "target"
TARGET=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $P-target)
wait_for 30 sh -c "docker exec $P-target sh -c 'test \$(wc -c < /usr/share/nginx/html/big) -eq 20000000'" || fail "target file"
WANT=$(docker exec $P-target sha256sum /usr/share/nginx/html/big | cut -d' ' -f1)
cl ip route get "$TARGET" | grep -q 'dev bg0' || fail "the client does not route $TARGET into the tunnel: $(cl ip route get "$TARGET")"
download() {  # download WHAT
  got=$(cl sh -c "curl -sS --max-time 90 -w '%{stderr}%{speed_download}' http://$TARGET/big 2>/tmp/speed | sha256sum" | cut -d' ' -f1)
  [ "$got" = "$WANT" ] || fail "20 MB $1 did not arrive intact (sha256 $got, want $WANT): $(cl boundgatectl status | tail -4)"
  echo "   20 MB $1, intact, $(cl cat /tmp/speed | awk '{printf "%.1f MB/s", $1/1000000}')"
}
download "over QUIC"
cl nft add table ip blk && cl nft add chain ip blk out '{ type filter hook output priority 0; }' && cl nft add rule ip blk out udp dport 443 drop || fail "nft"
cl boundgatectl down >/dev/null && wait_for 30 cl boundgatectl up || fail "client up with UDP blocked"
wait_for 60 sh -c "docker exec $P-client boundgatectl -json status | jq -e '[.hubs[] | select(.state == \"connected\" and .transport == \"tcp\")] | length == 1'" || fail "no TCP fallback tunnel for step 8"
download "over the TCP fallback"
cl nft delete table ip blk

"$0" down >/dev/null
echo "PASS: control plane and hub share one address and port 443 (TCP and UDP) behind boundgate-mux; UDP-blocked clients tunnel over TCP; 20 MB through the exit node over both"
