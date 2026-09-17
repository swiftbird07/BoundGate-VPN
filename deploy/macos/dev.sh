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
config() {
  mkdir -p "$STATE/logs"
  sed -e "s#@HUB1@#$HUB1#g" -e "s#@HUB2@#$HUB2#g" -e "s#@HUBNOTE@#$HUBNOTE#g" -e "s#@NAME@#$NAME#g" -e "s#@STATE@#$STATE#g" -e "s#@REPO@#$REPO#g" "$REPO/deploy/macos/node.yaml.in" > "$STATE/node.yaml"
}
need() { [ -x "$BIN/$1" ] || { echo "missing $BIN/$1: run 'make build-darwin' first" >&2; exit 1; }; }

case "${1:-}" in
  run)
    need boundgate-node; config
    if [ "${BRIDGE:-1}" = 1 ]; then
      need boundgate-udpbridge
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
    # the socket belongs to whoever runs the daemon (root under sudo)
    [ -S "$STATE/node.sock" ] && [ ! -w "$STATE/node.sock" ] && S=sudo
    exec $S env BOUNDGATE_SOCKET="$STATE/node.sock" "$BIN/boundgatectl" "$@" ;;
  check)
    echo "== utun interfaces with an overlay address"; ifconfig | awk '/^utun/{i=$1} /inet 10\.21\./{print i, $0}'
    echo "== routes through utun or pinned hosts"; netstat -rn -f inet | awk 'NR<4 || /utun/ || /UGHS/ || /UHS/'
    echo "== journal"; cat "$STATE/netstate.json" 2>/dev/null || echo "(none: clean)" ;;
  clean)
    $SUDO rm -rf "$STATE" ;;
  *) sed -n '2,14p' "$0"; exit 2 ;;
esac
