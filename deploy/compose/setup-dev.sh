#!/bin/sh
# Dev bootstrap against the control plane's admin API (bootstrap token).
#
#   setup-dev.sh                 signer key, network settings, enroll + confirm + sign hub1, hub2, node-r, node-a
#   setup-dev.sh signer          create (if needed) and register the dev admin signing key
#   setup-dev.sh approve SVC     enroll SVC (idempotent), confirm it with the dev grant and sign the binding
#   setup-dev.sh confirm SVC     enroll + confirm only (prints the sign command; the node stays "confirmed")
#   setup-dev.sh sign SVC        sign a confirmed node (new token, then signature)
#   setup-dev.sh revoke SVC      revoke SVC (closes its tunnels everywhere)
#   setup-dev.sh login SVC       log the lab user in on SVC through the fake IdP (what a browser would do)
#   setup-dev.sh policy NAME 'CEDAR' [NODE...]   create or replace a policy (optionally scoped to nodes by service name)
#   setup-dev.sh policy-rm NAME  delete a policy
#   setup-dev.sh policies        list policies
#   setup-dev.sh eval SVC DST [PORT] [PROTO] [SNI]   dry-run the ACL for a flow
#   setup-dev.sh flows [QUERY]   shipped flow records (e.g. 'decision=deny&limit=20')
#   setup-dev.sh tunnels [QUERY] tunnel history (e.g. 'active=1')
#   setup-dev.sh api GET /api/v1/admin/nodes      raw admin API call
#
# The dev admin key is a software ed25519 key created inside the control
# container (state/control/admin_signer). With a real YubiKey you would
# register its sk-ssh-ed25519 public key and run the printed sign command on
# the machine where the key is plugged in.
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.yml"
ADMIN=${BOUNDGATE_ADMIN_URL:-https://127.0.0.1:18443}
# The bearer for the admin API: the bootstrap token while no admin passkey
# exists; afterwards an API token (Admins -> API tokens in the UI) saved as
# state/control/api.token.
TOKEN_FILE=state/control/bootstrap.token
[ -s state/control/api.token ] && TOKEN_FILE=state/control/api.token
CACERT=state/control/control.crt
SIGNER_KEY=/var/lib/boundgate/admin_signer     # inside the control container = state/control/admin_signer

wait_for_token() {
  for _ in $(seq 1 30); do
    [ -s "$TOKEN_FILE" ] && [ -s "$CACERT" ] && return 0
    sleep 1
  done
  echo "bootstrap token not found at $TOKEN_FILE; is the control plane running?" >&2
  exit 1
}

api() {  # api METHOD PATH [JSON]
  wait_for_token
  tok=$(tr -d '[:space:]' < "$TOKEN_FILE")
  if [ $# -ge 3 ]; then
    curl -sS -f --cacert "$CACERT" -X "$1" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d "$3" "$ADMIN$2"
  else
    curl -sS -f --cacert "$CACERT" -X "$1" -H "Authorization: Bearer $tok" "$ADMIN$2"
  fi
}

ensure_signer() {
  wait_for_token
  if [ ! -s state/control/admin_signer.pub ]; then
    $COMPOSE exec -T control ssh-keygen -q -t ed25519 -N '' -C dev-admin -f "$SIGNER_KEY"
    echo "signer: created dev admin key state/control/admin_signer (software ed25519; use a YubiKey sk-key for real)"
  fi
  pub=$(cat state/control/admin_signer.pub)
  fp=$($COMPOSE exec -T control ssh-keygen -lf "$SIGNER_KEY.pub" | awk '{print $2}')
  if api GET /api/v1/admin/signers | jq -e --arg fp "$fp" '.[] | select(.fingerprint == $fp and .active)' >/dev/null; then
    echo "signer: $fp is in the signed admin key list"
  else
    # registering a key only proposes the next list; a key of the current
    # list (for the first list: the key itself) has to sign it
    if api GET /api/v1/admin/signers | jq -e --arg fp "$fp" '.[] | select(.fingerprint == $fp and .revoked_at == null)' >/dev/null; then
      # registered by a lab from before lists were signed: sign the registered keys as the first list
      tok=$(api POST /api/v1/admin/signers/change '{}' | jq -r .sign_token)
    else
      tok=$(api POST /api/v1/admin/signers "$(jq -cn --arg k "$pub" '{name:"dev-admin",public_key:$k}')" | jq -r .sign_token)
    fi
    $COMPOSE exec -T control boundgatectl -json admin sign-signers --control https://localhost:443 --cacert /var/lib/boundgate/control.crt \
      --token "$tok" --key "$SIGNER_KEY" --yes --pin-dir /var/lib/boundgate/signer-pins \
      | jq -r '"signer: admin key list is now version \(.version), signed by \(.signed_by)"'
  fi
}

set_network() {
  api PUT /api/v1/admin/settings/network '{"pool":"10.21.0.0/16"}' >/dev/null
  echo "network: overlay pool 10.21.0.0/16"
}

node_id_of() {  # node_id_of SVC -> node id (approved or confirmed)
  spki=$(nodectl "$1" -json identity | jq -r .spki)
  api GET /api/v1/admin/nodes | jq -r --arg s "$spki" '.[] | select(.spki == $s and .status != "revoked") | .id'
}

# set_policy NAME CEDAR [SVC...]: create or replace; scope = node ids of the services
set_policy() {
  name=$1; cedar=$2; shift 2
  scope='[]'
  for svc in "$@"; do
    scope=$(printf '%s' "$scope" | jq -c --arg id "$(node_id_of "$svc")" '. + [$id]')
  done
  body=$(jq -cn --arg n "$name" --arg c "$cedar" --argjson s "$scope" '{name:$n, cedar:$c, scope:$s}')
  id=$(api GET /api/v1/admin/policies | jq -r --arg n "$name" '.[] | select(.name == $n) | .id')
  if [ -n "$id" ]; then
    api PUT "/api/v1/admin/policies/$id" "$body" | jq -r '"policy: replaced \(.name) (scope \(.scope | length) nodes)"'
  else
    api POST /api/v1/admin/policies "$body" | jq -r '"policy: created \(.name) (scope \(.scope | length) nodes)"'
  fi
}

rm_policy() {
  id=$(api GET /api/v1/admin/policies | jq -r --arg n "$1" '.[] | select(.name == $n) | .id')
  [ -n "$id" ] || { echo "policy: $1 does not exist"; return 0; }
  api DELETE "/api/v1/admin/policies/$id"
  echo "policy: deleted $1"
}

# The lab starts permissive; the e2e adds forbid policies on top and
# switches to group-based permits. Without any policy nothing is reachable.
default_policies() {
  set_policy lab-allow-all 'permit(principal, action, resource);'
}

eval_acl() {  # eval SVC DST [PORT] [PROTO] [SNI]
  body=$(jq -cn --arg n "$1" --arg d "$2" --argjson p "${3:-80}" --arg pr "${4:-tcp}" --arg s "${5:-}" '{node:$n, dst:$d, port:$p, proto:$pr, sni:$s}')
  api POST /api/v1/admin/acl/evaluate "$body" | jq .
}

# The dev grant mirrors what each node requested. A real admin decides this
# per node in the UI after comparing the fingerprint.
# nodectl SVC ARGS...: boundgatectl of a compose node, or of the node on the
# Mac host ("mac", see deploy/macos/dev.sh and docs/MACOS.md)
nodectl() {
  svc=$1; shift
  if [ "$svc" = mac ]; then ../macos/dev.sh ctl "$@"; else $COMPOSE exec -T "$svc" boundgatectl "$@"; fi
}
grant_for() {
  case "$1" in
    hub1)   echo '"kind":"workload","roles":["hub","subnet-router"],"prefixes":[{"prefix":"10.60.0.0/24","mode":"snat"}],"public_addr":"hub1:443"' ;;
    hub2)   echo '"kind":"workload","roles":["hub","subnet-router"],"prefixes":[{"prefix":"10.60.0.0/24","mode":"snat"}],"public_addr":"hub2:443"' ;;
    node-r) echo '"kind":"workload","roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}]' ;;
    node-a|node-m|mac) echo '"kind":"interactive","roles":["endpoint"]' ;;
    node-t) echo '"kind":"workload","roles":["endpoint"]' ;;   # TPM key: hardware_bound follows the node's claim
    *) echo "unknown service $1" >&2; exit 2 ;;
  esac
}

enroll_node() {  # prints the enroll status JSON
  st=""
  for _ in $(seq 1 15); do
    st=$(nodectl "$1" -json enroll -accept-new-pin 2>/dev/null) && break
    sleep 1
  done
  [ -n "$st" ] || { echo "$1: node daemon not reachable" >&2; exit 1; }
  printf '%s' "$st"
}

# sign_node SVC ID FP TOKEN: the admin-side step, run where the signing key is
sign_node() {
  $COMPOSE exec -T control boundgatectl -json admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt \
    --node "$2" --fingerprint "$3" --token "$4" --key "$SIGNER_KEY" \
    | jq -r '"\(.name): approved as \(.kind) \(.roles | join("+")) with overlay ip \(.overlay_ip), signed by \(.signed_by)"'
}

confirm_node() {  # confirm_node SVC [sign]
  svc=$1
  st=$(enroll_node "$svc")
  status=$(printf '%s' "$st" | jq -r .status)
  id=$(printf '%s' "$st" | jq -r .node_id)
  fp=$(printf '%s' "$st" | jq -r .fingerprint)
  echo "$svc: enrollment $status (node $id)"
  echo "$svc: fingerprint $fp"
  case "$status" in
    pending|confirmed)
      # An admin would compare the fingerprint shown in the UI with the one
      # the user reports. Here both come from the same place, so we send it
      # along as the confirmation the API expects.
      body="{\"fingerprint\":\"$fp\",$(grant_for "$svc")}"
      [ "$status" = confirmed ] && [ "${2:-}" = sign ] && body="{\"fingerprint\":\"$fp\"}"
      cr=$(api POST "/api/v1/admin/nodes/$id/confirm" "$body")
      token=$(printf '%s' "$cr" | jq -r .sign_token)
      echo "$svc: confirmed; sign command: $(printf '%s' "$cr" | jq -r .sign_command)"
      if [ "${2:-}" = sign ]; then
        sign_node "$svc" "$id" "$fp" "$token"
      fi ;;
    approved) echo "$svc: already approved" ;;
    *) echo "$svc: cannot approve a $status node" >&2; exit 1 ;;
  esac
}

# login SVC: drive the fake IdP for a node (what a browser would do)
login_node() {
  st=$(nodectl "$1" -json login -no-wait)
  flow=$(printf '%s' "$st" | jq -r .flow_id)
  url=$(printf '%s' "$st" | jq -r .url)
  # the "browser" on the Mac: follow the IdP redirect (published on loopback), then hit the callback (devproxy)
  cb=$(curl -sS -o /dev/null -w '%{redirect_url}' "$url")
  curl -sS -f --cacert "$CACERT" -o /dev/null "$cb"
  nodectl "$1" -json status | jq -r '"\(.node_name): logged in as \(.user.username // "?") \(.user.groups // [])"' 2>/dev/null || true
  echo "$1: login flow $flow completed"
}

revoke_node() {
  spki=$($COMPOSE exec -T "$1" boundgatectl -json identity | jq -r .spki)
  id=$(api GET '/api/v1/admin/nodes?state=approved' | jq -r --arg s "$spki" '.[] | select(.spki == $s) | .id')
  [ -n "$id" ] || { echo "$1 is not approved"; exit 1; }
  api DELETE "/api/v1/admin/nodes/$id"
  echo "revoked $1 ($id)"
}

case "${1:-all}" in
  all)     ensure_signer; set_network; default_policies; for s in hub1 hub2 node-r node-a node-t node-m; do confirm_node "$s" sign; done ;;
  policy)  shift; set_policy "$@" ;;
  policy-rm) rm_policy "$2" ;;
  policies) api GET /api/v1/admin/policies | jq -r '.[] | "\(.name)\t\(if .enabled then "enabled" else "disabled" end)\tscope=\(.scope | length)\t\(.cedar | gsub("\n"; " "))"' ;;
  eval)    shift; eval_acl "$@" ;;
  flows)   api GET "/api/v1/admin/flows?${2:-limit=50}" | jq -r '.[] | "\(.ts)\t\(.attrs.node_name)\t\(.message)\t\(.attrs.principal_name // "local")\t\(.attrs.user // "-")\t\(.attrs.src):\(.attrs.sport) -> \(.attrs.dst):\(.attrs.dport)/\(.attrs.proto)\t\(.attrs.sni // .attrs.dns_name // "")\t\(.attrs.decision)\t\(.attrs.policies // [] | join(","))\t\(.attrs.bytes_in)/\(.attrs.bytes_out)"' ;;
  tunnels) api GET "/api/v1/admin/tunnels?${2:-}" | jq -r '.[] | "\(.opened_at)\t\(.hub_name) <- \(.peer_name)\t\(if .closed_at then "closed \(.closed_at) (\(.close_reason))" else "open" end)\t\(.bytes_in)/\(.bytes_out)"' ;;
  signer)  ensure_signer ;;
  approve) ensure_signer; confirm_node "$2" sign ;;
  confirm) ensure_signer; confirm_node "$2" ;;
  sign)    confirm_node "$2" sign ;;
  revoke)  revoke_node "$2" ;;
  login)   login_node "$2" ;;
  api)     shift; api "$@"; echo ;;
  *)       echo "usage: $0 [all|signer|approve SVC|confirm SVC|sign SVC|revoke SVC|login SVC|policy NAME CEDAR [SVC...]|policy-rm NAME|policies|eval SVC DST [PORT] [PROTO] [SNI]|flows [QUERY]|tunnels [QUERY]|api METHOD PATH [JSON]]" >&2; exit 2 ;;
esac
