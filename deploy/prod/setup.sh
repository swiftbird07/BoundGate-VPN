#!/bin/sh
# Sets up BoundGate on a Linux server with Docker: asks a few questions, writes
# the compose kit and its configuration into a directory, and starts it.
#
#   curl -fsSL https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/prod/setup.sh | sh
#
# or, to read it first:
#
#   curl -fsSLO https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/prod/setup.sh
#   less setup.sh && sh setup.sh
#
# Two kinds of setup (docs/DEPLOY.md):
#   1  control plane and a hub on one server, sharing port 443 (the first server)
#   2  one node: a subnet router, an exit node, another hub, or a workload endpoint
#
# It writes files in the directory you name and, if you say so, a cron file. It
# changes nothing else on the host, keeps every file that already exists, and
# can be run again. What it cannot do for you: the DNS record, the firewall
# (TCP and UDP 443), the OIDC application at your identity provider.
#
# Settings for unusual cases: BOUNDGATE_REF (a tag or branch instead of the
# latest release), BOUNDGATE_REPO (owner/name on GitHub), BOUNDGATE_KIT_URL
# (where deploy/prod is served from), BOUNDGATE_SETUP_INPUT (answers from a
# file, one per line, instead of the terminal).
set -eu

REPO=${BOUNDGATE_REPO:-swiftbird07/BoundGate-VPN}
PUBLIC_IMAGE=ghcr.io/swiftbird07/boundgate

say() { printf '%s\n' "$*" >&2; }
die() { printf 'setup: %s\n' "$*" >&2; exit 1; }

# ---- questions: from the terminal, also when the script itself arrives on stdin ----
open_input() {
  if [ -n "${BOUNDGATE_SETUP_INPUT:-}" ]; then exec 3<"$BOUNDGATE_SETUP_INPUT"
  elif [ -t 0 ]; then exec 3<&0
  elif (exec 3</dev/tty) 2>/dev/null; then exec 3</dev/tty
  else die "there is no terminal to ask questions on; download the script and run it: sh setup.sh"
  fi
}
# ask VAR QUESTION DEFAULT PATTERN [HINT]: repeats until the answer matches PATTERN (an ERE)
ask() {
  while :; do
    if [ -n "$3" ]; then printf '%s [%s]: ' "$2" "$3" >&2; else printf '%s: ' "$2" >&2; fi
    IFS= read -r _a <&3 || die "no more answers (asked: $2)"
    [ -n "$_a" ] || _a=$3
    if printf '%s\n' "$_a" | grep -Eq "$4"; then eval "$1=\$_a"; return; fi
    say "   ${5:-that does not look right}"
  done
}
confirm() { # confirm QUESTION DEFAULT(y|n)
  ask _yn "$1 (y/n)" "$2" '^[YyNn]$' "y or n"
  case "$_yn" in [Yy]) return 0 ;; *) return 1 ;; esac
}
secret() { # secret VAR QUESTION: not echoed; may stay empty
  printf '%s: ' "$2" >&2
  if [ -t 3 ]; then stty -echo <&3; trap 'stty echo <&3; rm -rf "$TMPD"' EXIT INT TERM; fi
  IFS= read -r _s <&3 || _s=
  if [ -t 3 ]; then stty echo <&3; trap 'rm -rf "$TMPD"' EXIT; trap - INT TERM; say ""; fi
  eval "$1=\$_s"
}

HOSTNAME_RE='^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
NAME_RE='^[A-Za-z0-9][A-Za-z0-9._-]*$'
URL_RE='^https://[A-Za-z0-9._~:/%-]+$'
CIDR_RE='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'

# keep FILE if it exists; otherwise write stdin to it
write_new() {
  if [ -e "$1" ]; then say "   kept    $1"; cat >/dev/null; else cat > "$1"; say "   wrote   $1"; fi
}
# the user the control plane (and lego) run as in the all-in-one kit; nodes and
# the hub run as root, but without CAP_DAC_OVERRIDE, so root must own their files
CONTROL_UID=65532
# own UID DIR...: hands directories (relative to the kit directory) to UID. As
# root with chown; otherwise with the kit's image, since whoever may use docker
# may do that anyway
own() {
  u=$1; shift
  if [ "$(id -u)" = 0 ]; then chown -R "$u:$u" "$@" || die "cannot hand $* to user $u"; return; fi
  img=$(sed -n 's/^BOUNDGATE_IMAGE=//p' .env | tail -1)
  [ -n "$img" ] || die "no BOUNDGATE_IMAGE in $DIR/.env"
  docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_READ_SEARCH -v "$DIR:/kit" -w /kit --entrypoint chown "$img" -R "$u:$u" "$@" \
    || die "cannot hand $* to user $u (run this as root, or: sudo chown -R $u:$u $*)"
}
# kit PATH-IN-deploy/prod: downloads to $GOT. Not in a pipeline: a failed download must stop everything
kit() {
  GOT=$TMPD/$(basename "$1")
  curl -fsSL --proto '=https,file' -o "$GOT" "$KIT/$1" && [ -s "$GOT" ] || die "cannot download $KIT/$1"
}

main() {
  [ "$(uname -s)" = Linux ] || die "this sets up a Linux server; for a Mac there is the app (docs/MACOS-APP.md)"
  for t in curl grep sed; do command -v $t >/dev/null 2>&1 || die "$t is needed"; done
  docker compose version >/dev/null 2>&1 || die "docker with the compose plugin is needed (https://docs.docker.com/engine/install/), and this user must be allowed to use it"
  [ -e /dev/net/tun ] || say "note: /dev/net/tun is missing; a node cannot make its tunnel device without it (modprobe tun)"
  open_input
  TMPD=$(mktemp -d); trap 'rm -rf "$TMPD"' EXIT

  # ---- which files: those of the latest release, so that they fit the image ----
  REF=${BOUNDGATE_REF:-}
  if [ -z "$REF" ]; then
    loc=$(curl -fsS -o /dev/null -w '%{redirect_url}' "https://github.com/$REPO/releases/latest") || die "cannot reach https://github.com/$REPO"
    case "$loc" in */releases/tag/v[0-9]*) REF=${loc##*/releases/tag/} ;; *) die "https://github.com/$REPO has no release yet" ;; esac
    printf '%s' "$REF" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "the latest release is not a version: $REF"
  fi
  KIT=${BOUNDGATE_KIT_URL:-https://raw.githubusercontent.com/$REPO/$REF/deploy/prod}

  say ""
  say "BoundGate setup ($REF)"
  say ""
  say "  1  control plane and hub on this server (the first server of an installation)"
  say "  2  a node on this server: subnet router, exit node, another hub, or workload endpoint"
  ask KIND "What do you want to set up?" 1 '^[12]$' "1 or 2"
  ask DIR "Directory for the configuration and state" /opt/boundgate '^/[A-Za-z0-9._/-]+$' "an absolute path without spaces"
  mkdir -p "$DIR" || die "cannot create $DIR"
  cd "$DIR"
  if [ -e docker-compose.yml ]; then
    confirm "There is a setup in $DIR already. Existing files are kept, missing ones written. Continue?" n || exit 0
  fi
  TPM=softkey
  if [ -e /dev/tpmrm0 ] && confirm "This machine has a TPM. Keep the node's device key in it? (the key then cannot be copied off this machine)" y; then TPM=tpm2; fi
  tpm_device() { if [ $TPM = tpm2 ]; then sed 's|^      # - /dev/tpmrm0:/dev/tpmrm0|      - /dev/tpmrm0:/dev/tpmrm0|'; else cat; fi; }

  if [ "$KIND" = 1 ]; then setup_control; else setup_node; fi

  # ---- how this server gets new versions ----
  say ""
  say "Updates:"
  say "  1  signed releases: update.sh checks the release signature on this server and pins the image"
  say "     by its digest; a nightly cron job, or you, run it (recommended)"
  say "  2  the image tag 'latest': docker compose pull, Dockhand, Watchtower. Simple; this server then"
  say "     runs whatever the tag points at: it trusts the registry and whoever can push to it, and"
  say "     checks no signature (docs/SECURITY.md R99). Only if you have a reason"
  ask UPD "How should this server be updated?" 1 '^[12]$' "1 or 2"
  if [ "$UPD" = 1 ]; then
    for t in jq ssh-keygen; do command -v $t >/dev/null 2>&1 || die "update.sh needs $t (packages jq and openssh-client): install it and run this again, or choose 2"; done
  fi
  kit update.sh; write_new update.sh < "$GOT"; chmod +x update.sh
  kit release_keys; write_new release_keys < "$GOT"
  touch .env; chmod 600 .env
  if [ "$UPD" = 2 ]; then
    grep -q '^BOUNDGATE_IMAGE=' .env || echo "BOUNDGATE_IMAGE=$PUBLIC_IMAGE:latest" >> .env
  else
    say "== checking the latest release and pulling its image"
    ./update.sh pin || die "update.sh could not verify or pull the release (its message is above); nothing was started"
    if [ -d /etc/cron.d ] && [ -w /etc/cron.d ] && [ ! -e /etc/cron.d/boundgate-update ] && confirm "Install a nightly update check (/etc/cron.d/boundgate-update)?" y; then
      printf '# BoundGate: signed updates (%s/update.sh). Output is mailed by cron only when something was updated or failed.\n%d 3 * * * root cd %s && ./update.sh -q\n' "$DIR" "$(( $(date +%s) % 60 ))" "$DIR" > /etc/cron.d/boundgate-update
      say "   wrote   /etc/cron.d/boundgate-update"
    fi
  fi

  # the containers do not run with root's privileges over files (docker-compose.yml):
  # their directories must belong to the user each one runs as
  HAVE_SECRET=; [ ! -s state/control/oidc.secret ] || HAVE_SECRET=1
  if [ "$KIND" = 1 ]; then
    own "$CONTROL_UID" state/control state/certs logs/control
    own 0 state/hub logs/hub
  else
    own 0 state logs
  fi

  say ""
  if confirm "Start it now?" y; then
    [ "$UPD" = 1 ] || docker compose pull
    docker compose up -d
    STARTED=1
  else STARTED=; fi
  next_steps
}

setup_control() {
  say ""
  say "The control plane needs a DNS name that points at this server; admins open it in the browser,"
  say "and it gets a Let's Encrypt certificate through port 443."
  ask NAME "DNS name of this server" "" "$HOSTNAME_RE" "a name like bg.example.com"
  ask EMAIL "E-mail address for certificate expiry warnings from Let's Encrypt (empty: none)" "" '^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)?$' "an e-mail address, or nothing"
  say ""
  say "Users and admins sign in through your OIDC provider (Authentik: docs/OIDC.md). Create an"
  say "application there with the redirect URL  https://$NAME/api/v1/oidc/callback"
  ask ISSUER "OIDC issuer URL" "" "$URL_RE" "an https URL, e.g. https://auth.example.com/application/o/boundgate/"
  ask CLIENT "OIDC client ID" boundgate "$NAME_RE" "letters, digits, . _ -"
  secret OIDC_SECRET "OIDC client secret (not shown; empty: put it into $DIR/state/control/oidc.secret later)"
  ask GROUP "OIDC group whose members are administrators" admins '^[A-Za-z0-9][A-Za-z0-9 ._-]*$' "letters, digits, space . _ -"
  ask HUB "Name of the hub on this server" hub1 "$NAME_RE" "letters, digits, . _ -"

  say ""
  kit all-in-one/docker-compose.yml; tpm_device < "$GOT" | write_new docker-compose.yml
  kit all-in-one/control.yaml.example; sed -e "s/bg\.example\.com/$NAME/g" -e "s|^  email: \"\".*|  email: \"$EMAIL\"|" \
    -e "s|^  issuer: .*|  issuer: $ISSUER|" -e "s|^  client_id: .*|  client_id: $CLIENT|" -e "s|^  group: admins.*|  group: \"$GROUP\"|" "$GOT" | write_new control.yaml
  kit all-in-one/hub.yaml.example; sed -e "s/bg\.example\.com/$NAME/g" -e "s|^name: hub1.*|name: $HUB|" -e "s|^key_kind: softkey.*|key_kind: $TPM|" "$GOT" | write_new hub.yaml
  kit all-in-one/mux.yaml.example; sed -e "s/bg\.example\.com/$NAME/g" "$GOT" | write_new mux.yaml
  (umask 077; mkdir -p state/control state/hub state/certs); mkdir -p logs/control logs/hub
  if [ -n "$OIDC_SECRET" ]; then (umask 077; printf '%s\n' "$OIDC_SECRET" | write_new state/control/oidc.secret); fi
  OIDC_SECRET=
  # port 443 is shared by control plane and hub through the mux (other layouts: docs/DEPLOY.md)
  touch .env; grep -q '^COMPOSE_PROFILES=' .env || echo 'COMPOSE_PROFILES=mux' >> .env
}

setup_node() {
  say ""
  ask NODE "Name of this node, as admins will see it" "$(hostname 2>/dev/null | cut -d. -f1)" "$NAME_RE" "letters, digits, . _ -"
  ask NAME "DNS name of the control plane" "" "$HOSTNAME_RE" "a name like bg.example.com"
  say ""
  say "  1  subnet router: a network behind this machine becomes reachable through the overlay"
  say "  2  exit node: clients can send all their traffic out through this machine"
  say "  3  hub: clients connect to this machine (it needs UDP and TCP 443 of a public address)"
  say "  4  workload endpoint: this machine only needs to be reachable itself"
  ask ROLE "What is this node?" 1 '^[1-4]$' "1 to 4"
  EXTRA=
  case "$ROLE" in
    1) ask PREFIX "Network to make reachable (CIDR)" "" "$CIDR_RE" "like 192.168.10.0/24"
       say "   snat: connections appear to come from this machine, the network needs no route back"
       say "   routed: clients keep their overlay address; the network must route the overlay pool to this machine"
       ask MODE "snat or routed" snat '^(snat|routed)$' "snat or routed"
       EXTRA="roles: [subnet-router]
prefixes:
  - {prefix: $PREFIX, mode: $MODE}" ;;
    2) EXTRA="roles: [exit-node]
prefixes:
  - {prefix: 0.0.0.0/0, mode: snat}" ;;
    3) ask PUBLIC "Public DNS name or address of this machine, as clients reach it" "" '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' "a name or an IPv4 address"
       EXTRA="roles: [hub]
listen: \":443\"
public_addr: \"$PUBLIC:443\"" ;;
    4) EXTRA="roles: [endpoint]" ;;
  esac
  say ""
  kit node/docker-compose.yml; tpm_device < "$GOT" | write_new docker-compose.yml
  write_new node.yaml <<EOF
# Written by setup.sh. Every setting: deploy/prod/node/node.yaml.example, docs/DEPLOY.md
name: $NODE
state_dir: /var/lib/boundgate
key_kind: $TPM
control:
  addr: $NAME:443
  server_name: nodes.$NAME
# requested here, granted by the admin at approval
$EXTRA
auto_up: true
profile: full                      # a server should not follow an exit node's default route: docs/PROFILES.md
socket: /run/boundgate/node.sock
tun_name: bg0
log_dir: /var/log/boundgate
log_stdout: true
EOF
  (umask 077; mkdir -p state); mkdir -p logs
}

next_steps() {
  say ""
  say "Done. What is left:"
  [ -n "$STARTED" ] || say "  * start it:  cd $DIR && docker compose up -d"
  if [ "$KIND" = 1 ]; then
    say "  * DNS: $NAME must point at this server. Firewall: TCP 443 and UDP 443 open."
    say "  * identity provider: redirect URL https://$NAME/api/v1/oidc/callback; administrators in the group \"$GROUP\""
    [ -n "$HAVE_SECRET" ] || say "  * the OIDC client secret: one line in $DIR/state/control/oidc.secret (chmod 600, owner $CONTROL_UID), then docker compose restart control"
    say "  * open https://$NAME, sign in, and register the first admin passkey with the token that"
    say "    docker compose exec control cat /var/lib/boundgate/bootstrap.token   prints"
    say "  * Admins > Admin signing keys: add your signing key (a FIDO2 SSH key) and run the command the page shows;"
    say "    Settings > Overlay network: choose the pool before the first node. Then enroll the hub:"
    say "      cd $DIR && docker compose exec hub boundgatectl enroll"
    say "    compare the fingerprint it prints with the admin UI, confirm and sign the hub there."
    say "  * back up $DIR/state/control (database and the key every node pins)."
  else
    say "  * enroll:  cd $DIR && docker compose exec node boundgatectl enroll"
    say "    compare the fingerprint with the admin UI of https://$NAME, confirm the node with its role and sign it."
    say "  * status:  docker compose exec node boundgatectl status"
    say "  * back up $DIR/state: it is this node's identity."
  fi
  if [ "$UPD" = 1 ]; then say "  * updates: cd $DIR && ./update.sh   (check: ./update.sh check)"
  else say "  * updates: cd $DIR && docker compose pull && docker compose up -d"; fi
  say "  * everything else: https://github.com/$REPO/blob/$REF/docs/DEPLOY.md"
}

# the last line: a download that broke off halfway runs nothing
main "$@"
