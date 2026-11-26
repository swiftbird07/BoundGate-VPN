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
# The kinds of setup (docs/DEPLOY.md, docs/REVERSE-PROXY.md), by number or name:
#   1  aio-basic: control plane and a hub on one server, sharing port 443 (the
#      first server)
#   2  node: a subnet router, an exit node, another hub, or a workload endpoint
#   3  reverse-proxy: a node and beside it the reverse proxy module, nginx with
#      ModSecurity in front of this host's web services
#   4  module: the reverse proxy module for the node already set up here
#   5  aio-full: aio-basic and a reverse proxy on the same server, all on port
#      443; nginx owns TCP 443 and passes control plane and hub through, the
#      hub runs in a network of its own (deploy/prod/all-in-one/docker-compose.full.yml)
#
# It writes files in the directory you name and, if you say so, a cron file. It
# changes nothing else on the host, keeps every file that already exists, and
# can be run again. What it cannot do for you: the DNS record, the firewall
# (TCP and UDP 443), the OIDC application at your identity provider.
#
# BOUNDGATE_CHANNEL=stable sets up a server that follows the stable channel
# instead of beta (docs/RELEASES.md): its files, its image, its updates.
#
# Settings for unusual cases: BOUNDGATE_REF (a tag or branch instead of the
# channel's release), BOUNDGATE_REPO (owner/name on GitHub), BOUNDGATE_KIT_URL
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

# DNS names are case-insensitive, the control plane, the mux and the reverse
# proxy compare them in lower case (registry.HostName refuses capitals)
lower() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }
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
# the node's worker under privilege separation (privsep.user in node.yaml)
WORKER_UID=65531
# the reverse proxy module beside a node (module_uid in node.yaml)
MODULE_UID=65533
# own UID DIR...: hands directories (relative to the kit directory) to UID. As
# root with chown; otherwise with the kit's image, since whoever may use docker
# may do that anyway.
# Only a directory that is not UID's yet, on the first run: later, what is in
# it is the containers' doing. A worker of privilege separation may create
# files in its node's state directory, and one under a name of the parent's
# that a second run handed to root would pass for the parent's own. -h: a
# link in the tree is changed itself, never what it points to.
own() {
  u=$1; shift
  todo=
  for d in "$@"; do
    [ "$(ls -nd "$d" 2>/dev/null | awk '{print $3}')" = "$u" ] || todo="$todo $d"
  done
  [ -n "$todo" ] || return 0
  # shellcheck disable=SC2086 # the kit's own directory names, without spaces
  set -- $todo
  if [ "$(id -u)" = 0 ]; then chown -hR "$u:$u" "$@" || die "cannot hand $* to user $u"; return; fi
  img=$(sed -n 's/^BOUNDGATE_IMAGE=//p' .env | tail -1)
  [ -n "$img" ] || die "no BOUNDGATE_IMAGE in $DIR/.env"
  docker run --rm --network none --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add DAC_READ_SEARCH -v "$DIR:/kit" -w /kit --entrypoint chown "$img" -hR "$u:$u" "$@" \
    || die "cannot hand $* to user $u (run this as root, or: sudo chown -hR $u:$u $*)"
}
# identity_question: a node that is set up a second time usually wants one
# thing the questions above do not offer - a new device key. Changing
# key_kind is the common reason (a TPM that was forgotten), a revoked node
# the other. Never by deleting the state directory: under a running daemon
# that leaves the process writing into an unlinked directory.
identity_question() {
  [ "$KIND" != 1 ] || return 0
  svc=node
  kind=
  for f in device.tpm device.sekey device.key; do
    [ -e "state/$f" ] || continue
    case $f in
      device.tpm) kind="in this machine's TPM" ;;
      device.sekey) kind="in the Secure Enclave" ;;
      device.key) kind="a software key in state/device.key" ;;
    esac
    break
  done
  [ -n "$kind" ] || return 0
  say ""
  say "This node already has an identity: $kind."
  say "A new one means enrolling again, an administrator approving it again, and revoking"
  say "the old node in the admin UI. Say no if you only want to change the configuration."
  confirm "Give this node a new identity?" n || return 0
  docker compose up -d "$svc" >/dev/null 2>&1 || true
  if ! docker compose exec -T "$svc" boundgatectl down >/dev/null 2>&1; then
    say "   the node does not answer at its socket. Start it, then:"
    say "     cd $DIR && docker compose exec $svc boundgatectl down && docker compose exec $svc boundgatectl reset -new-identity"
    return 0
  fi
  docker compose exec -T "$svc" boundgatectl reset -new-identity >/dev/null \
    || die "the node did not give up its identity (run the command by hand to see why: docker compose exec $svc boundgatectl reset -new-identity)"
  NEW_IDENTITY=1
  say "   done; the node opens a new key as soon as its service is back"
}

# system_users UID...: offer to give the uids the containers run as a name on
# this host. They exist only as numbers otherwise, which makes `ls -l` in the
# kit unreadable and leaves the uid free for another service later. A user
# that *operates* the stack is deliberately not offered: it would need the
# docker group, which is root on this host anyway (docs/DEPLOY.md).
system_users() {
  [ "$(id -u)" = 0 ] || return 0
  command -v useradd >/dev/null 2>&1 || command -v adduser >/dev/null 2>&1 || return 0
  need=
  for u in "$@"; do
    id -u "$u" >/dev/null 2>&1 || need="$need $u"
  done
  [ -n "$need" ] || return 0
  say ""
  say "The containers run as unprivileged accounts that exist only as numbers here:$need."
  confirm "Create system users for them (no home directory, no login shell)?" y || return 0
  for u in $need; do
    name=boundgate
    [ "$u" = 65531 ] && name=boundgate-node
    [ "$u" = 65532 ] && name=boundgate-control
    [ "$u" = 65533 ] && name=boundgate-proxy
    if id -u "$name" >/dev/null 2>&1; then say "   kept    user $name"; continue; fi
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --no-create-home --shell /usr/sbin/nologin --uid "$u" "$name" 2>/dev/null \
        || { say "   could not create $name (uid $u); the numbers stay"; continue; }
    else
      adduser --system --no-create-home --shell /usr/sbin/nologin --uid "$u" --disabled-login "$name" >/dev/null 2>&1 \
        || { say "   could not create $name (uid $u); the numbers stay"; continue; }
    fi
    say "   wrote   user $name (uid $u)"
  done
}

# networkd_keep_rules: systemd-networkd removes every policy rule and route it
# did not make itself when it starts, and an unattended upgrade restarts it.
# With reply_via_arrival those are the rules that lead into the tunnel: the
# tunnel stands and the host's own traffic misses it (Martins-NAS 2026-11-17,
# pCore 2026-11-22; #38). The node puts them back, the drop-in keeps them.
networkd_keep_rules() {
  command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-networkd 2>/dev/null || return 0
  dir=${BOUNDGATE_NETWORKD_DIR:-/etc/systemd/networkd.conf.d}
  f=$dir/boundgate.conf
  if [ -e "$f" ]; then say "   kept    $f"; return 0; fi
  say ""
  say "systemd-networkd runs here. Every time it starts (a security update restarts it) it removes"
  say "routing rules and routes it did not make itself, the node's among them (docs/ARRIVAL.md)."
  confirm "Write $f so that it leaves them alone?" y || return 0
  if mkdir -p "$dir" 2>/dev/null && printf '[Network]\nManageForeignRoutingPolicyRules=no\nManageForeignRoutes=no\n' > "$f" 2>/dev/null; then
    say "   wrote   $f (takes effect at networkd's next start)"
  else
    say "   could not write $f: write it as root (docs/ARRIVAL.md)"
  fi
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

  # ---- which files: those of the channel's release, so that they fit the image ----
  CHANNEL=${BOUNDGATE_CHANNEL:-beta}
  case "$CHANNEL" in beta|stable) ;; *) die "BOUNDGATE_CHANNEL must be beta or stable, not $CHANNEL" ;; esac
  TAG=latest; [ "$CHANNEL" != stable ] || TAG=stable   # the image tag that follows the channel; latest is beta
  REF=${BOUNDGATE_REF:-}
  if [ -z "$REF" ]; then
    # the pointer only picks the files here: update.sh verifies its signature
    # before anything is pulled, and starts no older than this release
    ptr=$(curl -fsSL "https://github.com/$REPO/releases/download/channel-$CHANNEL/$CHANNEL.json") || die "cannot read channel $CHANNEL from https://github.com/$REPO"
    REF=$(printf '%s\n' "$ptr" | sed -n 's/.*"version": *"\(v[0-9][0-9.]*\)".*/\1/p' | head -1)
    printf '%s' "$REF" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die "channel $CHANNEL names no release"
  fi
  KIT=${BOUNDGATE_KIT_URL:-https://raw.githubusercontent.com/$REPO/$REF/deploy/prod}

  say ""
  say "BoundGate setup ($REF, channel $CHANNEL)"
  say ""
  say "  1  aio-basic: control plane and hub on this server (the first server of an installation)"
  say "  2  node: a node on this server: subnet router, exit node, another hub, or workload endpoint"
  say "  3  reverse-proxy: a new reverse proxy on this server: a node, and beside it the reverse proxy"
  say "     module (nginx with ModSecurity in front of its web services, run from the control plane)"
  say "  4  module: the reverse proxy module for the node already set up on this server (it keeps its identity)"
  say "  5  aio-full: control plane, hub and a reverse proxy on this server, all on port 443; nginx serves"
  say "     the sites and passes the control plane and the hub through"
  ask KIND "What do you want to set up?" 1 '^([1-5]|aio-basic|node|reverse-proxy|module|aio-full)$' "1 to 5, or its name"
  case "$KIND" in aio-basic) KIND=1 ;; node) KIND=2 ;; reverse-proxy) KIND=3 ;; module) KIND=4 ;; aio-full) KIND=5 ;; esac
  # aio-full is aio-basic in the directory, with the hub in a network of its
  # own, and a reverse proxy (3) in its proxy/
  FULL=
  if [ "$KIND" = 5 ]; then FULL=1; KIND=1; full_preflight; fi
  ask DIR "Directory for the configuration and state" /opt/boundgate '^/[A-Za-z0-9._/-]+$' "an absolute path without spaces"
  mkdir -p "$DIR" || die "cannot create $DIR"
  cd "$DIR"
  # what the questions below may set (set -u: next_steps reads them)
  NEW_IDENTITY=; PROFILE=; PROFILES_DIR=; RESOLVER=
  # a reverse proxy kit of v0.2.0 ran the proxy as a node of its own; it is
  # moved by hand, not set up over (docs/REVERSE-PROXY.md)
  if [ -e reverse-proxy.yaml ] && [ ! -e docker-compose.reverse-proxy.yml ]; then
    die "$DIR holds a reverse proxy of v0.2.0, which ran as a node of its own. Move it to the module as docs/REVERSE-PROXY.md (\"From a reverse proxy of v0.2.0\") says; this changes nothing here"
  fi
  # 4, or 3 over a node set up here: the module joins the node, which stays
  # as it is. Inside, both are kind 3 from here on
  ADD_TO_NODE=
  if [ "$KIND" = 4 ]; then
    [ -e node.yaml ] || die "there is no node in $DIR: give the directory of the node, or choose 3 for a new one with the reverse proxy"
    KIND=3; ADD_TO_NODE=1
  elif [ "$KIND" = 3 ] && [ -e node.yaml ]; then
    say "A node is set up in $DIR already: the reverse proxy joins it (as with 4)."
    ADD_TO_NODE=1
  fi
  # aio-full over an aio-basic would keep its hub.yaml, mux.yaml and
  # control.yaml and put the hub into a network of its own: every tunnel
  # cut, and nginx without TCP 443. The move is by hand (docs/DEPLOY.md)
  if [ -n "$FULL" ] && [ -e docker-compose.yml ] && [ ! -e docker-compose.full.yml ]; then
    die "$DIR holds an aio-basic setup; setup.sh does not move it to aio-full (docs/DEPLOY.md, aio-full). Choose another directory, or 1 to run aio-basic again"
  fi
  if [ -n "$ADD_TO_NODE" ]; then
    confirm "The reverse proxy joins the node in $DIR: its node.yaml and .env get one line each, the node restarts. Continue?" y || exit 0
  elif [ -e docker-compose.yml ]; then
    confirm "There is a setup in $DIR already. Existing files are kept, missing ones written. Continue?" n || exit 0
  fi
  TPM=softkey
  tpm_device() { if [ $TPM = tpm2 ]; then sed 's|^      # - /dev/tpmrm0:/dev/tpmrm0|      - /dev/tpmrm0:/dev/tpmrm0|'; else cat; fi; }
  if [ -z "$ADD_TO_NODE" ]; then
    if [ -e /dev/tpmrm0 ] && confirm "This machine has a TPM. Keep the node's device key in it? (the key then cannot be copied off this machine)" y; then TPM=tpm2; fi
    identity_question
  fi

  if [ "$KIND" = 1 ]; then setup_control
  elif [ "$KIND" = 3 ]; then
    if [ -z "$ADD_TO_NODE" ]; then say ""; say "No node here yet: one is set up first, and the reverse proxy joins it."; setup_node; fi
    setup_proxy
  else setup_node; fi

  updates_question
  install_updates boundgate-update 0
  set_owners

  if [ -n "$FULL" ]; then
    # the reverse proxy: kind 3 in a directory of its own, so that its
    # node's kit, state and updates are those of any reverse proxy
    MAIN_DIR=$DIR; DIR=$DIR/proxy
    say ""
    say "== the reverse proxy and its node, in $DIR"
    mkdir -p "$DIR" || die "cannot create $DIR"
    cd "$DIR"
    KIND=3; ADD_TO_NODE=
    identity_question
    if [ -e node.yaml ]; then ADD_TO_NODE=1; else setup_node; fi
    setup_proxy
    install_updates boundgate-update-proxy 30
    set_owners
    KIND=1; DIR=$MAIN_DIR
    cd "$DIR"
  fi

  say ""
  if confirm "Start it now?" y; then
    start_kit "$DIR"
    # the mux has left TCP 443 to nginx by now (mux.yaml: no_tcp)
    [ -z "$FULL" ] || start_kit "$DIR/proxy"
    STARTED=1
  else STARTED=; fi
  next_steps
}

# full_preflight: what aio-full needs beyond aio-basic
full_preflight() {
  # docker-compose.full.yml takes the hub out of the host's network with !reset
  v=$(docker compose version --short 2>/dev/null | sed 's/^v//') || v=
  case "$v" in
    [0-9]*.[0-9]*)
      maj=${v%%.*}; rest=${v#*.}; min=${rest%%.*}
      case "$maj$min" in *[!0-9]*) ;; *)
        if [ "$maj" -lt 2 ] || { [ "$maj" = 2 ] && [ "$min" -lt 24 ]; }; then
          die "aio-full needs Docker Compose 2.24 or later; this is $v"
        fi ;;
      esac ;;
  esac
  # the hub's network; one Docker made for it before is no conflict
  if command -v ip >/dev/null 2>&1 && ip -4 route show 2>/dev/null | overlaps_hub_net && ! docker network inspect boundgate-hub >/dev/null 2>&1; then
    die "172.31.254.0/29, the hub's network in aio-full, is taken on this host (ip -4 route). Free it, or set up aio-basic and change the addresses by hand (deploy/prod/all-in-one/docker-compose.full.yml names the four files)"
  fi
}

# overlaps_hub_net: whether a route of `ip -4 route show` (stdin) shares an
# address with 172.31.254.0/29: one inside it, and one around it
# (172.31.240.0/20, a cloud's private network) alike
overlaps_hub_net() {
  awk 'function ip(a,  p) { split(a, p, "."); return ((p[1] * 256 + p[2]) * 256 + p[3]) * 256 + p[4] }
    BEGIN { hub = ip("172.31.254.0"); found = 1 }
    $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ {
      n = split($1, f, "/"); bits = (n == 2) ? f[2] + 0 : 32; if (bits > 29) bits = 29
      size = 2 ^ (32 - bits)
      if (int(ip(f[1]) / size) == int(hub / size)) found = 0
    }
    END { exit found }'
}

# start_kit DIR: the containers of one kit
start_kit() {
  (cd "$1" && { [ "$UPD" = 1 ] || docker compose pull; } && docker compose up -d) || die "the containers in $1 did not start (the message is above)"
}

# ---- how this server gets new versions ----
updates_question() {
  say ""
  say "Updates:"
  say "  1  signed releases: update.sh checks the release signature on this server and pins the image"
  say "     by its digest; a nightly cron job, or you, run it (recommended)"
  say "  2  the image tag of the channel ('$TAG'): docker compose pull, Dockhand, Watchtower. Simple; this server then"
  say "     runs whatever the tag points at: it trusts the registry and whoever can push to it, and"
  say "     checks no signature (docs/SECURITY.md R99). Only if you have a reason"
  ask UPD "How should this server be updated?" 1 '^[12]$' "1 or 2"
  if [ "$UPD" = 1 ]; then
    for t in jq ssh-keygen; do command -v $t >/dev/null 2>&1 || die "update.sh needs $t (packages jq and openssh-client): install it and run this again, or choose 2"; done
  fi
}

# install_updates CRON MINUTES: update.sh, its settings and the image of the
# kit in this directory; the nightly job as /etc/cron.d/CRON, MINUTES after
# the others (two kits on one server do not pull at the same minute)
install_updates() {
  kit update.sh; write_new update.sh < "$GOT"; chmod +x update.sh
  # the channel, and the release these files came from: update.sh starts no older than that
  grep -qs '^BOUNDGATE_CHANNEL=' update.env || echo "BOUNDGATE_CHANNEL=$CHANNEL" >> update.env
  if printf '%s' "$REF" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' && ! grep -qs '^BOUNDGATE_MIN_RELEASE=' update.env; then
    echo "BOUNDGATE_MIN_RELEASE=$REF" >> update.env
  fi
  kit release_keys; write_new release_keys < "$GOT"
  touch .env; chmod 600 .env
  if [ "$UPD" = 2 ]; then
    IMG=$PUBLIC_IMAGE
    grep -q '^BOUNDGATE_IMAGE=' .env || echo "BOUNDGATE_IMAGE=$IMG:$TAG" >> .env
    # the reverse proxy module has an image of its own
    [ "$KIND" != 3 ] || grep -q '^BOUNDGATE_PROXY_IMAGE=' .env || echo "BOUNDGATE_PROXY_IMAGE=$IMG-reverse-proxy:$TAG" >> .env
  else
    say "== checking channel $CHANNEL's release and pulling its image"
    ./update.sh pin || die "update.sh could not verify or pull the release (its message is above); nothing was started"
    cron=/etc/cron.d/$1
    if [ -d /etc/cron.d ] && [ -w /etc/cron.d ] && [ ! -e "$cron" ] && confirm "Install a nightly update check ($cron)?" y; then
      [ -n "${CRON_MINUTE:-}" ] || CRON_MINUTE=$(( $(date +%s) % 60 ))
      printf '# BoundGate: signed updates (%s/update.sh). Output is mailed by cron only when something was updated or failed.\n%d 3 * * * root cd %s && ./update.sh -q\n' "$DIR" "$(( (CRON_MINUTE + $2) % 60 ))" "$DIR" > "$cron"
      say "   wrote   $cron"
    fi
  fi
}

# set_owners: the containers do not run with root's privileges over files
# (docker-compose.yml): their directories must belong to the user each one
# runs as
set_owners() {
  if [ "$KIND" = 1 ]; then
    HAVE_SECRET=; [ ! -s state/control/oidc.secret ] || HAVE_SECRET=1
    system_users "$CONTROL_UID" "$WORKER_UID"
    own "$CONTROL_UID" state/control state/certs logs/control
    own 0 state/hub logs/hub
  else
    if [ "$KIND" = 3 ]; then system_users "$WORKER_UID" "$MODULE_UID"; else system_users "$WORKER_UID"; fi
    own 0 state logs
    # the reverse proxy module reads the token files itself, as its user
    # (docs/REVERSE-PROXY.md); its state and logs it takes over at start
    [ "$KIND" != 3 ] || own "$MODULE_UID" secrets proxy-state proxy-logs
  fi
}

setup_control() {
  say ""
  say "The control plane needs a DNS name that points at this server; admins open it in the browser,"
  say "and it gets a Let's Encrypt certificate through port 443."
  ask NAME "DNS name of this server" "" "$HOSTNAME_RE" "a name like bg.example.com"
  NAME=$(lower "$NAME")
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
  # everything is downloaded and edited first, and written only when the
  # edits took: the examples are the release's, this script may be newer
  # or older than they are
  kit all-in-one/docker-compose.yml; tpm_device < "$GOT" > "$TMPD/compose.yml"
  [ -z "$FULL" ] || { kit all-in-one/docker-compose.full.yml; cp "$GOT" "$TMPD/compose.full.yml"; }
  kit all-in-one/control.yaml.example; sed -e "s/bg\.example\.com/$NAME/g" -e "s|^  email: \"\".*|  email: \"$EMAIL\"|" \
    -e "s|^  issuer: .*|  issuer: $ISSUER|" -e "s|^  client_id: .*|  client_id: $CLIENT|" -e "s|^  group: admins.*|  group: \"$GROUP\"|" "$GOT" | full_control > "$TMPD/control.yaml"
  kit all-in-one/hub.yaml.example; sed -e "s/bg\.example\.com/$NAME/g" -e "s|^name: hub1.*|name: $HUB|" -e "s|^key_kind: softkey.*|key_kind: $TPM|" "$GOT" | full_hub > "$TMPD/hub.yaml"
  kit all-in-one/mux.yaml.example; sed -e "s/bg\.example\.com/$NAME/g" "$GOT" | full_mux > "$TMPD/mux.yaml"
  [ -z "$FULL" ] || full_check "$TMPD"
  write_new docker-compose.yml < "$TMPD/compose.yml"
  write_new control.yaml < "$TMPD/control.yaml"
  write_new hub.yaml < "$TMPD/hub.yaml"
  write_new mux.yaml < "$TMPD/mux.yaml"
  (umask 077; mkdir -p state/control state/hub state/certs); mkdir -p logs/control logs/hub
  if [ -n "$OIDC_SECRET" ]; then (umask 077; printf '%s\n' "$OIDC_SECRET" | write_new state/control/oidc.secret); fi
  OIDC_SECRET=
  # port 443 is shared by control plane and hub through the mux (other layouts: docs/DEPLOY.md)
  touch .env; grep -q '^COMPOSE_PROFILES=' .env || echo 'COMPOSE_PROFILES=mux' >> .env
  if [ -n "$FULL" ]; then
    # the hub in a network of its own (the file says why)
    write_new docker-compose.full.yml < "$TMPD/compose.full.yml"
    if ! grep -q '^COMPOSE_FILE=' .env; then
      echo "COMPOSE_FILE=docker-compose.yml:docker-compose.full.yml" >> .env
      say "   added   COMPOSE_FILE to .env"
    fi
  fi
}

# aio-full: the hub listens in its own network at 172.31.254.2 and trusts its
# gateway, where the mux and nginx arrive from (docker-compose.full.yml)
full_hub() {
  if [ -z "$FULL" ]; then cat; return; fi
  # the control plane on the host, at the gateway: an answer to the public
  # address would come back from the gateway (the mux answers from any
  # address), and behind a NAT the public address is not the host's
  sed -e 's|^listen: "127.0.0.1:8444" .*|listen: ":8444"                  # in its own network (docker-compose.full.yml), behind the mux (UDP) and nginx (TCP)|' \
    -e 's|^  trusted: \[127.0.0.1\]|  trusted: [172.31.254.1]          # its network'"'"'s gateway: the mux and nginx on the host arrive from it|' \
    -e 's|^  addr: [^ ]*:443$|  addr: 172.31.254.1:443          # the host from the hub'"'"'s network: mux (UDP), nginx (TCP); the name checked is server_name|'
}
# full_check DIR: the aio-full edits are all in the files DIR holds, or
# nothing is written. A missing one would leave the mux on TCP 443 (nginx
# cannot start) or the hub where the mux does not reach it
full_check() {
  bad=
  grep -q '^listen: ":8444"' "$1/hub.yaml" && grep -q '^  trusted: \[172.31.254.1\]' "$1/hub.yaml" && grep -q '^  addr: 172.31.254.1:443 ' "$1/hub.yaml" || bad="$bad hub.yaml"
  grep -q '^no_tcp: true' "$1/mux.yaml" && [ "$(grep -c '^    [ut][dc]p: 172.31.254.2:8444' "$1/mux.yaml")" = 2 ] && ! grep -q '127\.0\.0\.1:8444' "$1/mux.yaml" || bad="$bad mux.yaml"
  sed -n '/^proxy:$/,$p' "$1/control.yaml" | grep -q '^  enabled: true$' || bad="$bad control.yaml"
  [ -z "$bad" ] || die "the examples of $REF do not take the aio-full edits ($bad); nothing was written. Use a release that has aio-full (BOUNDGATE_REF), or aio-basic"
}
# aio-full: the mux serves UDP only (nginx owns TCP 443) and finds the hub at
# its own address; the control plane stays on loopback
full_mux() {
  if [ -z "$FULL" ]; then cat; return; fi
  printf '# aio-full: UDP 443 only; nginx of the reverse proxy (proxy/) owns TCP 443 and\n# passes these names through. The hub is in its own network (docker-compose.full.yml).\n'
  sed -e 's|127\.0\.0\.1:8444|172.31.254.2:8444|g' \
    -e 's|^# no_tcp: true$|no_tcp: true                         # aio-full: TCP 443 is nginx'"'"'s, which passes these names through (proxy/reverse-proxy.yaml)|'
}
# aio-full: the control plane serves the reverse proxy's admin pages and the
# role reverse-proxy
full_control() {
  if [ -z "$FULL" ]; then cat; return; fi
  sed -e 's|^# proxy:$|proxy:|' -e 's|^#   enabled: true$|  enabled: true|' -e 's|^#   crs_updates: |  crs_updates: |'
}

setup_node() {
  say ""
  if [ -n "$FULL" ]; then
    # aio-full: the reverse proxy's node, an endpoint of the control plane
    # set up above
    ask NODE "Name of the reverse proxy's node, as admins will see it" "$(hostname 2>/dev/null | cut -d. -f1)-proxy" "$NAME_RE" "letters, digits, . _ -"
    ROLE=4
    # control plane and hub on this very host, not through its public
    # address (behind a NAT that is not the host's); the names checked are
    # server_name and the hub's pinned identity
    CONTROL_ADDR=127.0.0.1:443
  else
    ask NODE "Name of this node, as admins will see it" "$(hostname 2>/dev/null | cut -d. -f1)" "$NAME_RE" "letters, digits, . _ -"
    ask NAME "DNS name of the control plane" "" "$HOSTNAME_RE" "a name like bg.example.com"
    NAME=$(lower "$NAME")
    say ""
    say "  1  subnet router: a network behind this machine becomes reachable through the overlay"
    say "  2  exit node: clients can send all their traffic out through this machine"
    say "  3  hub: clients connect to this machine (it needs UDP and TCP 443 of a public address)"
    say "  4  workload endpoint: this machine only needs to be reachable itself"
    ask ROLE "What is this node?" 1 '^[1-4]$' "1 to 4"
  fi
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
  [ -z "$FULL" ] || EXTRA="$EXTRA
hub_addrs: {$HUB: \"127.0.0.1:443\"}   # the hub of this host, through the mux and nginx here"
  # Which of the networks the hubs advertise this machine routes. A server
  # that takes an exit node's 0.0.0.0/0 loses its own internet, its other
  # VPNs and everything outside the overlay, and a subnet router must not
  # take a route for the network it announces itself (docs/PROFILES.md).
  say ""
  if [ -n "$FULL" ]; then
    # the control plane's own host gives its default route to no exit node
    say "  1  only the private networks the overlay offers; this machine keeps its own internet"
    say "  4  only the networks you name"
    ask ROUTING "What should the reverse proxy reach through the overlay?" 1 '^[14]$' "1 or 4"
  else
    say "  1  only the private networks the overlay offers; this machine keeps its own internet"
    say "  2  everything the hubs advertise, an exit node's default route included"
    say "  3  only the internet through an exit node, none of the LANs"
    say "  4  only the networks you name"
    ask ROUTING "What should this machine route through the overlay?" 1 '^[1-4]$' "1 to 4"
  fi
  PROFILE=lan-only; PROFILES_DIR=
  case "$ROUTING" in
    2) PROFILE=full
       say "   note: this takes over the machine's default route. A server behind a port forward"
       say "   also needs reply_via_arrival in node.yaml (docs/ARRIVAL.md)"
       networkd_keep_rules ;;
    3) PROFILE=wan-only ;;
    4) PROFILE=site; PROFILES_DIR=/etc/boundgate/profiles
       NETS=
       while :; do
         ask NET "Network to route through the overlay (CIDR; empty when done)" "" "(^\$)|$CIDR_RE" "like 10.20.0.0/16, or nothing to finish"
         [ -n "$NET" ] || break
         NETS="$NETS    - $NET
"
       done
       [ -n "$NETS" ] || die "a profile of your own needs at least one network"
       mkdir -p profiles
       printf 'name: site\nrouting:\n  mode: include\n  networks:\n%s' "$NETS" | write_new profiles/site.yaml ;;
  esac
  profile_mount() { if [ -n "$PROFILES_DIR" ]; then sed 's|^      # - ./profiles:/etc/boundgate/profiles:ro|      - ./profiles:/etc/boundgate/profiles:ro|'; else cat; fi; }

  # Where this machine resolves names while the overlay is up. Through the
  # hub is what the policies need: a hub only learns which address a name
  # stands for when it sees the query, so a node that asks its own network's
  # resolver cannot be matched by name at all (docs/ACL.md). The node
  # redirects the host's DNS queries with nftables; nothing to mount.
  if [ -n "$FULL" ]; then
    # aio-full: the sites must not depend on the overlay. nginx resolves
    # their upstreams with this host's resolver, and so do the control
    # plane and the hub; the redirect would send all of it into the tunnel
    RES=2
  else
    say ""
    say "  1  through the resolvers the hub offers, while the overlay is up (this host's and its containers' queries)"
    say "  2  keep this machine's own resolver"
    ask RES "Where should this machine resolve names?" 1 '^[12]$' "1 or 2"
  fi
  case "$RES" in
    1) RESOLVER=hub ;;
    2) RESOLVER=system
       [ -n "$FULL" ] || say "   note: a dynamic access list cannot match this node by name then, and plain HTTP"
       [ -n "$FULL" ] || say "   reaches the hub as a bare address (docs/ACL.md)" ;;
  esac

  say ""
  kit node/docker-compose.yml; tpm_device < "$GOT" | profile_mount | write_new docker-compose.yml
  write_new node.yaml <<EOF
# Written by setup.sh. Every setting: deploy/prod/node/node.yaml.example, docs/DEPLOY.md
name: $NODE
state_dir: /var/lib/boundgate
key_kind: $TPM
control:
  addr: ${CONTROL_ADDR:-$NAME:443}
  server_name: nodes.$NAME
privsep:                           # the node runs as this user; the key and the host's network stay with a root parent
  user: "65531"                    # (docs/PRIVSEP.md)
# requested here, granted by the admin at approval
$EXTRA
auto_up: true
profile: $PROFILE                  # which of the advertised networks this machine routes: docs/PROFILES.md${PROFILES_DIR:+
profiles_dir: $PROFILES_DIR        # mounted read-only in docker-compose.yml}
resolver: $RESOLVER                # hub: this host's DNS goes to the hub's resolver while the overlay is up (docs/ACL.md); system: keep this machine's resolver
socket: /run/boundgate/node.sock
tun_name: bg0
log_dir: /var/log/boundgate
log_stdout: true
EOF
  (umask 077; mkdir -p state); mkdir -p logs
}

# setup_proxy adds the reverse proxy module to the node of this directory
# (docs/REVERSE-PROXY.md): its compose file, its configuration, its
# directories, and the one line in node.yaml that makes the node serve it.
setup_proxy() {
  say ""
  [ -n "${NAME:-}" ] || NAME=$(sed -n 's/^  server_name: nodes\.//p' node.yaml | head -1)
  ask EMAIL "E-mail address for the Let's Encrypt account (empty: no certificates from ACME)" "${EMAIL:-}" '^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+)?$' "an e-mail address, or nothing"
  say "The proxy obtains certificates with Cloudflare DNS-01 (a token with Zone:DNS:Edit for the zones) and"
  say "gates by country with MaxMind's GeoLite2 (a license key). Both go into $DIR/secrets, one line each, 0600, owner $MODULE_UID."
  kit reverse-proxy/docker-compose.reverse-proxy.yml; write_new docker-compose.reverse-proxy.yml < "$GOT"
  # docker compose reads the module's file next to the node's from now on,
  # update.sh too
  touch .env
  if ! grep -q '^COMPOSE_FILE=' .env; then
    echo "COMPOSE_FILE=docker-compose.yml:docker-compose.reverse-proxy.yml" >> .env
    say "   added   COMPOSE_FILE to .env"
  fi
  # the node serves the module: it asks for the role reverse-proxy and makes
  # the module's socket
  if grep -q '^modules:' node.yaml; then
    grep -q '^modules:.*reverse-proxy' node.yaml || say "   note: node.yaml names other modules; add reverse-proxy to its modules: by hand"
  else
    printf '\n# the reverse proxy module beside this node (docker-compose.reverse-proxy.yml, docs/REVERSE-PROXY.md)\nmodules: [reverse-proxy]\n' >> node.yaml
    say "   added   modules: [reverse-proxy] to node.yaml"
  fi
  ACME_BLOCK="  acme:
    email: $EMAIL
    cloudflare_token_file: /etc/boundgate/secrets/cloudflare.token"
  [ -n "$EMAIL" ] || ACME_BLOCK="  acme:
    disabled: true                 # certificates come from the control plane (internal) only"
  PASS_BLOCK=
  [ -z "$FULL" ] || PASS_BLOCK="  # aio-full: this host's control plane and hub behind port 443. From nginx's first
  # start on, before this proxy is enrolled, and in every revision; the admin UI
  # neither changes nor removes it (docs/DEPLOY.md, aio-full). countries: [DE, AT]
  # gates the names by country (only with the GeoLite2 key in secrets/maxmind.key;
  # without it only private addresses would pass)
  passthroughs:
    - name: boundgate
      port: 443
      control: 127.0.0.1:8443      # control.yaml's listen
      hub: 172.31.254.2:8444       # the hub in its own network (../docker-compose.full.yml)
      node_name: nodes.$NAME
      admin_name: $NAME"
  write_new reverse-proxy.yaml <<YAML
# The reverse proxy module beside the node of this directory (docs/REVERSE-PROXY.md).
# Everything about the overlay is node.yaml's.
module:
  socket: /run/boundgate/module/module.sock
state_dir: /var/lib/boundgate-proxy
log_dir: /var/log/boundgate-proxy
log_stdout: true

proxy:
  listen_http: ":80"
$ACME_BLOCK
  geoip:
    maxmind_license_key_file: /etc/boundgate/secrets/maxmind.key
$PASS_BLOCK
YAML
  (umask 077; mkdir -p secrets proxy-state); mkdir -p proxy-logs modules
}

next_steps() {
  say ""
  say "Done. What is left:"
  [ -n "$STARTED" ] || say "  * start it:  cd $DIR && docker compose up -d${FULL:+, then cd $DIR/proxy && docker compose up -d}"
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
    if [ -n "$FULL" ]; then
      P=$DIR/proxy
      say "  * the reverse proxy in $P: nginx owns TCP 443 and passes $NAME, nodes.$NAME and the hub"
      say "    through (proxy/reverse-proxy.yaml, passthroughs); the mux serves UDP 443 only. Enroll its node:"
      say "      cd $P && docker compose exec node boundgatectl enroll"
      say "    and confirm it in the admin UI with its roles, reverse-proxy among them, and sign it."
      say "  * secrets: $P/secrets/cloudflare.token and $P/secrets/maxmind.key, one line each (chmod 600, owner $MODULE_UID)"
      say "  * sites: Reverse Proxy in the admin UI. They keep being served when control plane, hub or mux stop."
      say "  * status:  cd $P && docker compose exec node boundgatectl status   logs: docker compose logs reverse-proxy"
      say "  * firewall: TCP 80 as well; back up $P/state and $P/proxy-state too."
      if [ "$UPD" = 1 ]; then say "  * updates: cd $P && ./update.sh   (the reverse proxy is a kit of its own)"
      else say "  * updates: cd $P && docker compose pull && docker compose up -d"; fi
    fi
  elif [ "$KIND" = 3 ]; then
    if [ -z "$ADD_TO_NODE" ]; then
      say "  * enroll the node:  cd $DIR && docker compose exec node boundgatectl enroll"
      say "    compare the fingerprint with the admin UI of https://$NAME, confirm the node with its roles, reverse-proxy among them, and sign it."
      [ -z "$NEW_IDENTITY" ] || say "    this node gave up its old identity: revoke the old node in the admin UI."
    else
      say "  * the node asks for the role reverse-proxy now: in the admin UI of https://$NAME confirm and sign it again"
      say "    with reverse-proxy among its roles. Until then the proxy serves its last configuration, if it has one."
    fi
    say "  * the control plane: proxy: {enabled: true} in its control.yaml, or it refuses the role (docs/REVERSE-PROXY.md)"
    say "  * secrets: $DIR/secrets/cloudflare.token and $DIR/secrets/maxmind.key, one line each (chmod 600, owner $MODULE_UID)"
    say "  * sites: Reverse Proxy in the admin UI; an nginx-waf hosts.toml goes in with Settings > Import, dry run first"
    say "  * status:  docker compose exec node boundgatectl status   (the proxy's revision, nginx, certificates under extra)"
    say "    logs:    docker compose logs reverse-proxy"
    say "  * firewall: TCP 80 and the sites' ports (443, 8443, ...) open; back up $DIR/state (the node's identity)"
    say "    and $DIR/proxy-state (ACME account and keys)."
  else
    say "  * enroll:  cd $DIR && docker compose exec node boundgatectl enroll"
    say "    compare the fingerprint with the admin UI of https://$NAME, confirm the node with its role and sign it."
    [ -z "$NEW_IDENTITY" ] || say "    this node gave up its old identity: revoke the old node in the admin UI."
    say "  * status:  docker compose exec node boundgatectl status"
    say "  * routing: profile $PROFILE; see it with   docker compose exec node boundgatectl status   (routes, not routed)"
    [ -z "$PROFILES_DIR" ] || say "    the profile is $DIR/profiles/site.yaml; change it and run: docker compose exec node boundgatectl up -profile site"
    say "  * back up $DIR/state: it is this node's identity."
  fi
  if [ "$UPD" = 1 ]; then say "  * updates: cd $DIR && ./update.sh   (check: ./update.sh check)"
  else say "  * updates: cd $DIR && docker compose pull && docker compose up -d"; fi
  say "  * everything else: https://github.com/$REPO/blob/$REF/docs/DEPLOY.md"
}

# the last line: a download that broke off halfway runs nothing
main "$@"
