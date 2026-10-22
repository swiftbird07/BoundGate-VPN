#!/bin/sh
# Run a BoundGate node on the Mac host against the compose lab without
# installing anything: binaries from bin/darwin_<arch>, state, socket and
# logs under deploy/macos/state (git-ignored).
#
#   make build-darwin
#   deploy/macos/dev.sh run            # the daemon (sudo: utun and routes need root)
#   deploy/macos/dev.sh ctl status     # boundgatectl against that daemon
#   deploy/macos/dev.sh ctl enroll | up | login | down
#   deploy/macos/dev.sh check          # routes and interfaces the node touched
#   deploy/macos/dev.sh repair         # undo what a node left on this Mac (no daemon needed)
#   deploy/macos/dev.sh clean          # forget the device key and state
#
# NOSUDO=1 runs the daemon unprivileged: enroll, status and login work, `up`
# fails at creating the utun device.
# BRIDGE=0 dials the hubs' published UDP ports directly (Colima with
# `portForwarder: grpc`); the default starts boundgate-udpbridge, because
# Colima's default forwarder carries TCP only.
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
BIN=$REPO/bin/darwin_$ARCH
STATE=$REPO/deploy/macos/state
NAME=${BOUNDGATE_NAME:-$(scutil --get LocalHostName 2>/dev/null || hostname -s)}
SUDO=sudo
[ "${NOSUDO:-0}" = 1 ] && SUDO=

if [ "${BRIDGE:-1}" = 1 ]; then HUB1=15431; HUB2=15432; HUBNOTE="UDP-over-TCP bridge"; else HUB1=14431; HUB2=14432; HUBNOTE="published UDP ports"; fi
# The state belongs to whoever runs the daemon: root, unless NOSUDO=1. So
# the configuration is written with the same rights, or the next run fails
# on a directory it may not write.
config() {
  $SUDO mkdir -p "$STATE/logs"
  sed -e "s#@HUB1@#$HUB1#g" -e "s#@HUB2@#$HUB2#g" -e "s#@HUBNOTE@#$HUBNOTE#g" -e "s#@NAME@#$NAME#g" -e "s#@STATE@#$STATE#g" -e "s#@REPO@#$REPO#g" "$REPO/deploy/macos/node.yaml.in" \
    | $SUDO tee "$STATE/node.yaml" >/dev/null
}
need() { [ -x "$BIN/$1" ] || { echo "missing $BIN/$1: run 'make build-darwin' first" >&2; exit 1; }; }

# The daemon needs root (utun, routes, the resolver), and a device key is only
# read when it belongs to whoever reads it (safefile). A state directory left
# behind by a run without root therefore stops the next one with a message in
# the log and nothing else; say it here instead.
own_state() {
  [ -n "$SUDO" ] || return 0
  for f in "$STATE/device.key" "$STATE/device.sekey" "$STATE/device.tpm"; do
    [ -e "$f" ] || continue
    [ "$(stat -f %u "$f")" = 0 ] && continue
    echo "$f belongs to uid $(stat -f %u "$f"), but the daemon runs as root." >&2
    echo "Keep this node's identity:  sudo chown -R root:wheel $STATE" >&2
    echo "Or start over (new key, needs approval again):  $0 clean" >&2
    exit 1
  done
}

case "${1:-}" in
  run)
    need boundgate-node; own_state; config
    if [ "${BRIDGE:-1}" = 1 ]; then
      need boundgate-udpbridge
      # the bridge is an unprivileged loopback shim, but the log directory
      # belongs to the daemon's user: hand it a file it may write
      $SUDO touch "$STATE/logs/udpbridge.log"
      $SUDO chown "$(id -u)" "$STATE/logs/udpbridge.log"
      "$BIN/boundgate-udpbridge" -client "127.0.0.1:15431=127.0.0.1:24431,127.0.0.1:15432=127.0.0.1:24432" > "$STATE/logs/udpbridge.log" 2>&1 &
      BRIDGE_PID=$!
      trap 'kill $BRIDGE_PID 2>/dev/null || true' EXIT INT TERM
      $SUDO "$BIN/boundgate-node" -config "$STATE/node.yaml"
      exit $?
    fi
    exec $SUDO "$BIN/boundgate-node" -config "$STATE/node.yaml" ;;
  ctl)
    need boundgatectl; shift
    S=
    # the socket belongs to whoever runs the daemon (root under sudo). An if,
    # not a chain of tests: under `set -e` a chain whose last test is false
    # ends the script, so `ctl down` would silently do nothing exactly when
    # the socket is already gone.
    if [ -S "$STATE/node.sock" ] && [ ! -w "$STATE/node.sock" ]; then S=sudo; fi
    exec $S env BOUNDGATE_SOCKET="$STATE/node.sock" "$BIN/boundgatectl" "$@" ;;
  repair)
    # Undo what a node left on this Mac when there is no daemon left to do
    # it: the host's resolver first -- a Mac still pointed at a resolver
    # inside a tunnel that is gone resolves no name at all, not even through
    # its own resolver -- then routes, host routes and NAT.
    need boundgate-node
    [ -f "$STATE/node.yaml" ] || config
    exec $SUDO "$BIN/boundgate-node" -config "$STATE/node.yaml" -repair ;;
  check)
    echo "== utun interfaces with an overlay address"; ifconfig | awk '/^utun/{i=$1} /inet 10\.21\./{print i, $0}'
    echo "== routes through utun or pinned hosts"; netstat -rn -f inet | awk 'NR<4 || /utun/ || /UGHS/ || /UHS/'
    echo "== journal"; cat "$STATE/netstate.json" 2>/dev/null || echo "(none: clean)" ;;
  clean)
    $SUDO rm -rf "$STATE" ;;
  *) sed -n '2,14p' "$0"; exit 2 ;;
esac
