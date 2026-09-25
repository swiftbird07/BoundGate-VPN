#!/bin/sh
# deploy/prod/setup.sh with answers from a file, the kit from this checkout
# (file://) and stand-ins for docker and uname, so it runs on the developer's
# Mac too. The YAML it writes is parsed by the real programs in the rehearsal;
# here: that every answer lands where it belongs and nothing else is touched.
set -eu
cd "$(dirname "$0")/../.."
SRC=$PWD
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$T/bin" "$T/kit"
cp -R deploy/prod/all-in-one deploy/prod/node deploy/prod/release_keys "$T/kit/"
# update.sh's own test is update_test.sh; here only: is it called, and how
printf '#!/bin/sh\necho "update.sh $*" >> "%s/log"\necho "BOUNDGATE_IMAGE=pinned@sha256:abc" >> .env\n' "$T" > "$T/kit/update.sh"
printf '#!/bin/sh\n[ "$*" = "compose version" ] || echo "docker $*" >> "%s/log"\n' "$T" > "$T/bin/docker"
printf '#!/bin/sh\n[ "$1" = -s ] && echo Linux || /usr/bin/uname "$@"\n' > "$T/bin/uname"
chmod +x "$T/bin/docker" "$T/bin/uname"
run() { # run ANSWERS...: one per line
  printf '%s\n' "$@" > "$T/answers"
  PATH="$T/bin:$PATH" BOUNDGATE_REF=vtest BOUNDGATE_KIT_URL="file://$T/kit" BOUNDGATE_SETUP_INPUT="$T/answers" sh "$SRC/deploy/prod/setup.sh" > "$T/out" 2>&1
}

echo "== 1. control plane and hub, signed updates, started"
D=$T/cp; : > "$T/log"
run 1 "$D" vpn.example.org ops@example.org https://id.example.org/application/o/bg/ bgclient 's3cret&|\value' "vpn admins" edge1 1 y || { cat "$T/out"; fail "setup failed"; }
grep -q '^server_name: vpn.example.org ' "$D/control.yaml" && grep -q '^  email: "ops@example.org"$' "$D/control.yaml" \
  && grep -q '^  issuer: https://id.example.org/application/o/bg/$' "$D/control.yaml" && grep -q '^  client_id: bgclient$' "$D/control.yaml" \
  && grep -q '^  redirect_url: https://vpn.example.org/api/v1/oidc/callback$' "$D/control.yaml" && grep -q '^  group: "vpn admins"$' "$D/control.yaml" || fail "control.yaml: $(cat "$D/control.yaml")"
grep -q '^name: edge1$' "$D/hub.yaml" && grep -q '^  addr: vpn.example.org:443$' "$D/hub.yaml" && grep -q '^public_addr: "vpn.example.org:443"' "$D/hub.yaml" && grep -q '^key_kind: softkey$' "$D/hub.yaml" || fail "hub.yaml"
grep -q 'sni: \[vpn.example.org, nodes.vpn.example.org\]' "$D/mux.yaml" && grep -q 'sni: \[hub.boundgate\]' "$D/mux.yaml" || fail "mux.yaml"
! grep -rq 'bg\.example\.com' "$D"/*.yaml || fail "a placeholder name is left: $(grep -rn 'bg\.example\.com' "$D"/*.yaml)"
[ "$(cat "$D/state/control/oidc.secret")" = 's3cret&|\value' ] || fail "the secret was changed on the way: $(cat "$D/state/control/oidc.secret")"
[ "$(stat -f %Lp "$D/state/control/oidc.secret" 2>/dev/null || stat -c %a "$D/state/control/oidc.secret")" = 600 ] || fail "oidc.secret is not 0600"
! grep -q 's3cret' "$T/out" "$D"/*.yaml "$D/.env" || fail "the secret shows up outside its file"
grep -q '^COMPOSE_PROFILES=mux$' "$D/.env" && grep -q '^BOUNDGATE_IMAGE=pinned@' "$D/.env" || fail ".env: $(cat "$D/.env")"
grep -q '^update.sh pin$' "$T/log" && grep -q '^docker compose up -d$' "$T/log" && ! grep -q 'compose pull' "$T/log" || fail "calls: $(cat "$T/log")"
# the directories go to the users the containers run as (not root: through the pinned image), before the start
grep -q "^docker run .*-v $D:/kit .*--entrypoint chown pinned@sha256:abc -R 65532:65532 state/control state/certs logs/control\$" "$T/log" \
  && grep -q "^docker run .*--entrypoint chown pinned@sha256:abc -R 0:0 state/hub logs/hub\$" "$T/log" \
  && [ "$(grep -n 'compose up' "$T/log" | cut -d: -f1)" -gt "$(grep -n 'chown.*0:0' "$T/log" | cut -d: -f1)" ] || fail "ownership: $(cat "$T/log")"
grep -q 'docker compose exec control cat /var/lib/boundgate/bootstrap.token' "$T/out" || fail "bootstrap token hint: $(cat "$T/out")"
! grep -q 'the OIDC client secret: one line' "$T/out" || fail "asked for a secret that was given"
[ -x "$D/update.sh" ] && cmp -s "$D/release_keys" deploy/prod/release_keys || fail "update.sh / release_keys"
grep -q 'bootstrap.token' "$T/out" || fail "no next steps: $(cat "$T/out")"

echo "== 2. again over the same directory: asks, keeps every file"
echo '# mine' >> "$D/control.yaml"; : > "$T/log"
run 1 "$D" n || { cat "$T/out"; fail "second run"; }
grep -q '^# mine$' "$D/control.yaml" && [ ! -s "$T/log" ] || fail "a declined second run changed something"
run 1 "$D" y other.example.org "" https://x.example.org/ c "" g h 2 n || { cat "$T/out"; fail "second run, continued"; }
grep -q '^# mine$' "$D/control.yaml" && grep -q 'vpn.example.org' "$D/hub.yaml" && grep -q 'kept ' "$T/out" || fail "existing files were not kept"

echo "== 3. a subnet router following the tag latest, not started"
D=$T/router; : > "$T/log"
run 2 "$D" router7 vpn.example.org 1 10.20.30.0/24 routed 2 n || { cat "$T/out"; fail "node setup failed"; }
grep -q '^name: router7$' "$D/node.yaml" && grep -q '^  server_name: nodes.vpn.example.org$' "$D/node.yaml" && grep -q '^roles: \[subnet-router\]$' "$D/node.yaml" \
  && grep -q '^  - {prefix: 10.20.30.0/24, mode: routed}$' "$D/node.yaml" || fail "node.yaml: $(cat "$D/node.yaml")"
grep -q '^BOUNDGATE_IMAGE=ghcr.io/swiftbird07/boundgate:latest$' "$D/.env" && ! grep -q 'COMPOSE_PROFILES' "$D/.env" || fail ".env: $(cat "$D/.env")"
[ "$(cat "$T/log")" = "docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_READ_SEARCH -v $D:/kit -w /kit --entrypoint chown ghcr.io/swiftbird07/boundgate:latest -R 0:0 state logs" ] \
  || fail "something other than the ownership was done: $(cat "$T/log")"
grep -q 'docker compose pull && docker compose up -d' "$T/out" || fail "next steps"

echo "== 4. the other roles; answers that make no sense are asked again"
D=$T/hub2; run 2 "$D" 'bad name!' hub2 'not a host' vpn.example.org 9 3 hub2.example.org 2 n || { cat "$T/out"; fail "hub"; }
grep -q '^name: hub2$' "$D/node.yaml" && grep -q '^roles: \[hub\]$' "$D/node.yaml" && grep -q '^listen: ":443"$' "$D/node.yaml" && grep -q '^public_addr: "hub2.example.org:443"$' "$D/node.yaml" || fail "hub node.yaml"
D=$T/exit; run 2 "$D" exit1 vpn.example.org 2 2 n; grep -q '^roles: \[exit-node\]$' "$D/node.yaml" && grep -q 'prefix: 0.0.0.0/0, mode: snat' "$D/node.yaml" || fail "exit node"
D=$T/wl; run 2 "$D" db1 vpn.example.org 4 2 n; grep -q '^roles: \[endpoint\]$' "$D/node.yaml" && ! grep -q '^prefixes' "$D/node.yaml" || fail "endpoint"

echo "== 5. stops before writing anything: a download that fails, answers that run out"
rm "$T/kit/node/docker-compose.yml"; D=$T/broken
if run 2 "$D" n1 vpn.example.org 4 2 n; then fail "went on without the compose file"; fi
[ ! -e "$D/node.yaml" ] && [ ! -e "$D/docker-compose.yml" ] || fail "a failed download left files"
if run 1 "$T/short" vpn.example.org; then fail "went on without answers"; fi
echo "PASS: setup.sh"
