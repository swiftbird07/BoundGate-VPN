#!/bin/sh
# Dev bootstrap against the control plane's admin API (bootstrap token).
#
#   setup-dev.sh                 signer key, network settings, enroll + confirm + sign hub1, hub2, node-r, node-a
#   setup-dev.sh signer          create (if needed) and register the dev admin signing key
#   setup-dev.sh approve SVC     enroll SVC (idempotent), confirm it with the dev grant and sign the binding
#   setup-dev.sh confirm SVC     enroll + confirm only (prints the sign command; the node stays "confirmed")
#   setup-dev.sh sign SVC        sign a confirmed node (new token, then signature)
#   setup-dev.sh revoke SVC      revoke SVC (closes its tunnels everywhere)
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
TOKEN_FILE=state/control/bootstrap.token
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
  if api GET /api/v1/admin/signers | jq -e --arg fp "$fp" '.[] | select(.fingerprint == $fp and .revoked_at == null)' >/dev/null; then
    echo "signer: $fp already registered"
  else
    api POST /api/v1/admin/signers "$(jq -cn --arg k "$pub" '{name:"dev-admin",public_key:$k}')" \
      | jq -r '"signer: registered \(.name) \(.fingerprint) (\(.key_type), hardware: \(.hardware))"'
  fi
}

set_network() {
  api PUT /api/v1/admin/settings/network '{"pool":"10.21.0.0/16"}' >/dev/null
  echo "network: overlay pool 10.21.0.0/16"
}

# The dev grant mirrors what each node requested. A real admin decides this
# per node in the UI after comparing the fingerprint.
grant_for() {
  case "$1" in
    hub1)   echo '"roles":["hub","subnet-router"],"prefixes":[{"prefix":"10.60.0.0/24","mode":"snat"}],"public_addr":"hub1:443"' ;;
    hub2)   echo '"roles":["hub","subnet-router"],"prefixes":[{"prefix":"10.60.0.0/24","mode":"snat"}],"public_addr":"hub2:443"' ;;
    node-r) echo '"roles":["endpoint","subnet-router"],"prefixes":[{"prefix":"192.168.178.0/24","mode":"snat"}]' ;;
    node-a) echo '"roles":["endpoint"]' ;;
    *) echo "unknown service $1" >&2; exit 2 ;;
  esac
}

enroll_node() {  # prints the enroll status JSON
  st=""
  for _ in $(seq 1 15); do
    st=$($COMPOSE exec -T "$1" boundgatectl -json enroll 2>/dev/null) && break
    sleep 1
  done
  [ -n "$st" ] || { echo "$1: node daemon not reachable" >&2; exit 1; }
  printf '%s' "$st"
}

# sign_node SVC ID FP TOKEN: the admin-side step, run where the signing key is
sign_node() {
  $COMPOSE exec -T control boundgatectl -json admin sign --control https://localhost:443 --cacert /var/lib/boundgate/control.crt \
    --node "$2" --fingerprint "$3" --token "$4" --key "$SIGNER_KEY" \
    | jq -r '"\(.name): approved as \(.roles | join("+")) with overlay ip \(.overlay_ip), signed by \(.signed_by)"'
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

revoke_node() {
  spki=$($COMPOSE exec -T "$1" boundgatectl -json identity | jq -r .spki)
  id=$(api GET '/api/v1/admin/nodes?state=approved' | jq -r --arg s "$spki" '.[] | select(.spki == $s) | .id')
  [ -n "$id" ] || { echo "$1 is not approved"; exit 1; }
  api DELETE "/api/v1/admin/nodes/$id"
  echo "revoked $1 ($id)"
}

case "${1:-all}" in
  all)     ensure_signer; set_network; for s in hub1 hub2 node-r node-a; do confirm_node "$s" sign; done ;;
  signer)  ensure_signer ;;
  approve) ensure_signer; confirm_node "$2" sign ;;
  confirm) ensure_signer; confirm_node "$2" ;;
  sign)    confirm_node "$2" sign ;;
  revoke)  revoke_node "$2" ;;
  api)     shift; api "$@"; echo ;;
  *)       echo "usage: $0 [all|signer|approve SVC|confirm SVC|sign SVC|revoke SVC|api METHOD PATH [JSON]]" >&2; exit 2 ;;
esac
