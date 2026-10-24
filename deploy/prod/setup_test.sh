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
run 2 "$D" router7 vpn.example.org 1 10.20.30.0/24 routed 1 1 2 n || { cat "$T/out"; fail "node setup failed"; }
grep -q '^name: router7$' "$D/node.yaml" && grep -q '^  server_name: nodes.vpn.example.org$' "$D/node.yaml" && grep -q '^roles: \[subnet-router\]$' "$D/node.yaml" \
  && grep -q '^  - {prefix: 10.20.30.0/24, mode: routed}$' "$D/node.yaml" || fail "node.yaml: $(cat "$D/node.yaml")"
# a server does not take an exit node's default route unless it is asked for
grep -q '^profile: lan-only ' "$D/node.yaml" && ! grep -q '^profiles_dir' "$D/node.yaml" || fail "routing: $(grep -n 'profile' "$D/node.yaml")"
! grep -q '^      - ./profiles:' "$D/docker-compose.yml" || fail "the profiles mount was enabled without a profile of its own"
# names through the hub: the option and the system bus the node asks resolved over
grep -q '^resolver: hub ' "$D/node.yaml" || fail "resolver: $(grep -n resolver "$D/node.yaml")"
! grep -q 'dbus' "$D/docker-compose.yml" || fail "the host's system bus is still in the kit (#18): $(grep -n dbus "$D/docker-compose.yml")"
grep -q '^BOUNDGATE_IMAGE=ghcr.io/swiftbird07/boundgate:latest$' "$D/.env" && ! grep -q 'COMPOSE_PROFILES' "$D/.env" || fail ".env: $(cat "$D/.env")"
[ "$(cat "$T/log")" = "docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_READ_SEARCH -v $D:/kit -w /kit --entrypoint chown ghcr.io/swiftbird07/boundgate:latest -R 0:0 state logs" ] \
  || fail "something other than the ownership was done: $(cat "$T/log")"
grep -q 'docker compose pull && docker compose up -d' "$T/out" || fail "next steps"

echo "== 4. the other roles; answers that make no sense are asked again"
D=$T/hub2; run 2 "$D" 'bad name!' hub2 'not a host' vpn.example.org 9 3 hub2.example.org 1 1 2 n || { cat "$T/out"; fail "hub"; }
grep -q '^name: hub2$' "$D/node.yaml" && grep -q '^roles: \[hub\]$' "$D/node.yaml" && grep -q '^listen: ":443"$' "$D/node.yaml" && grep -q '^public_addr: "hub2.example.org:443"$' "$D/node.yaml" || fail "hub node.yaml"
D=$T/exit; run 2 "$D" exit1 vpn.example.org 2 2 1 2 n; grep -q '^roles: \[exit-node\]$' "$D/node.yaml" && grep -q 'prefix: 0.0.0.0/0, mode: snat' "$D/node.yaml" || fail "exit node"
grep -q '^profile: full ' "$D/node.yaml" || fail "the profile that was asked for: $(grep -n 'profile' "$D/node.yaml")"
grep -q 'reply_via_arrival' "$T/out" || fail "full without the note about the default route: $(cat "$T/out")"
D=$T/wl; run 2 "$D" db1 vpn.example.org 4 4 10.20.0.0/16 192.168.5.0/24 '' 2 2 n; grep -q '^roles: \[endpoint\]$' "$D/node.yaml" && ! grep -q '^prefixes' "$D/node.yaml" || fail "endpoint"
# a profile of one's own: the file, the path inside the container, the mount
grep -q '^profile: site ' "$D/node.yaml" && grep -q '^profiles_dir: /etc/boundgate/profiles' "$D/node.yaml" || fail "routing: $(grep -n 'profile' "$D/node.yaml")"
grep -q '^      - ./profiles:/etc/boundgate/profiles:ro$' "$D/docker-compose.yml" || fail "the profiles mount is not enabled: $(grep -n profiles "$D/docker-compose.yml")"
printf 'name: site\nrouting:\n  mode: include\n  networks:\n    - 10.20.0.0/16\n    - 192.168.5.0/24\n' | cmp -s - "$D/profiles/site.yaml" || fail "the profile written: $(cat "$D/profiles/site.yaml")"
# this one keeps its own resolver, and the script says what it costs
grep -q '^resolver: system ' "$D/node.yaml" || fail "resolver: $(grep -n resolver "$D/node.yaml")"
grep -q 'cannot match this node by name' "$T/out" || fail "no note about what a own resolver costs: $(cat "$T/out")"

echo "== 4b. a node that is set up again may give up its identity, through the daemon, never with rm"
D=$T/again; run 2 "$D" db2 vpn.example.org 4 1 1 2 n
mkdir -p "$D/state"; : > "$D/state/device.key"; : > "$T/log"
# declined: nothing is asked of the daemon and the key stays
run 2 "$D" y n db2 vpn.example.org 4 1 1 2 n || { cat "$T/out"; fail "second run over a node"; }
grep -q 'This node already has an identity: a software key' "$T/out" || fail "the identity question did not come: $(cat "$T/out")"
! grep -q 'boundgatectl' "$T/log" || fail "a declined reset still asked the daemon: $(cat "$T/log")"
[ -e "$D/state/device.key" ] || fail "a declined reset deleted the key"
# accepted: down, then reset -new-identity; the script never removes files itself
: > "$T/log"; run 2 "$D" y y db2 vpn.example.org 4 1 1 2 n || { cat "$T/out"; fail "second run with a new identity" ; }
grep -q 'docker compose exec -T node boundgatectl down' "$T/log" || fail "no down before the reset: $(cat "$T/log")"
grep -q 'docker compose exec -T node boundgatectl reset -new-identity' "$T/log" || fail "no reset: $(cat "$T/log")"
grep -q 'revoke the old node in the admin UI' "$T/out" || fail "the next steps do not mention the old node: $(cat "$T/out")"
[ -e "$D/state/device.key" ] || fail "setup.sh deleted a key file itself"

echo "== 4c. the uids the containers run as can get a name on the host"
mkdir -p "$T/root"
printf '#!/bin/sh\n[ "$1" = -u ] && [ $# = 1 ] && { echo 0; exit 0; }\nexit 1\n' > "$T/root/id"
printf '#!/bin/sh\necho "useradd $*" >> "%s/log"\n' "$T" > "$T/root/useradd"
# as root the script chowns directly; here it only has to be recorded
printf '#!/bin/sh\necho "chown $*" >> "%s/log"\n' "$T" > "$T/root/chown"
chmod +x "$T/root/id" "$T/root/useradd" "$T/root/chown"
D=$T/named; : > "$T/log"
printf '%s\n' 2 "$D" db3 vpn.example.org 4 1 1 2 y n > "$T/answers"
PATH="$T/root:$T/bin:$PATH" BOUNDGATE_REF=vtest BOUNDGATE_KIT_URL="file://$T/kit" BOUNDGATE_SETUP_INPUT="$T/answers" sh "$SRC/deploy/prod/setup.sh" > "$T/out" 2>&1 \
  || { cat "$T/out"; fail "node setup as root"; }
grep -q 'useradd --system --no-create-home --shell /usr/sbin/nologin --uid 65531 boundgate-node' "$T/log" || fail "no system user for the worker: $(cat "$T/log")"
! grep -q 'useradd .* 65532' "$T/log" || fail "a node got the control plane's user: $(cat "$T/log")"
# declined, and the numbers stay
: > "$T/log"; printf '%s\n' 2 "$T/numbers" db4 vpn.example.org 4 1 1 2 n n > "$T/answers"
PATH="$T/root:$T/bin:$PATH" BOUNDGATE_REF=vtest BOUNDGATE_KIT_URL="file://$T/kit" BOUNDGATE_SETUP_INPUT="$T/answers" sh "$SRC/deploy/prod/setup.sh" > "$T/out" 2>&1 \
  || { cat "$T/out"; fail "node setup as root, users declined" ; }
! grep -q useradd "$T/log" || fail "a declined question still created a user: $(cat "$T/log")"

echo "== 5. stops before writing anything: a download that fails, answers that run out"
rm "$T/kit/node/docker-compose.yml"; D=$T/broken
if run 2 "$D" n1 vpn.example.org 4 1 1 2 n; then fail "went on without the compose file"; fi
[ ! -e "$D/node.yaml" ] && [ ! -e "$D/docker-compose.yml" ] || fail "a failed download left files"
if run 1 "$T/short" vpn.example.org; then fail "went on without answers"; fi
echo "PASS: setup.sh"
