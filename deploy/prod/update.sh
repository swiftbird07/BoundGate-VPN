#!/bin/sh
# Unattended updates for a BoundGate host (the kits in this directory, or plain
# binaries). Meant for cron:
#
#   17 3 * * *  /opt/boundgate/update.sh -q            # in the kit directory
#
#   update.sh [-q] [check|apply]      default: apply; -q: silent unless something
#                                     was updated or went wrong
#
# What it does: asks the Gitea release API for the latest release, downloads
# manifest.json and manifest.json.sig, verifies the signature against the
# release keys next to this script (ssh-keygen -Y verify, namespace
# boundgate-release) and refuses anything else. Then, only if that release is
# newer than what runs here:
#   MODE=compose (default)  pulls the image BY THE DIGEST the signed manifest
#       names - not a tag somebody could move -, writes BOUNDGATE_IMAGE and
#       BOUNDGATE_RELEASE to .env, `docker compose up -d`, and goes back to the
#       previous image if the containers do not stay up.
#   MODE=binaries  downloads boundgate-<v>-linux-<arch>.tar.gz, checks size and
#       SHA-256 against the manifest, installs into INSTALL_DIR and runs
#       RESTART_CMD.
# The server is trusted with nothing but being reachable.
#
# Settings: environment, or a file update.env next to the compose file:
#   BOUNDGATE_UPDATE_URL         Gitea instance      (https://gitlab.net407.com)
#   BOUNDGATE_UPDATE_REPO        owner/name          (SBH/BoundGate-VPN)
#   BOUNDGATE_UPDATE_TOKEN_FILE  read token, if the instance wants a login
#   RELEASE_KEYS                 public keys         (release_keys next to this script)
#   COMPOSE_DIR                  the kit directory   (the current directory)
#   MODE, INSTALL_DIR (/usr/local/bin), RESTART_CMD (systemctl restart boundgate-node)
# Needs curl, jq, ssh-keygen; docker for MODE=compose. Exit: 0 done or nothing
# to do, 1 failed (cron mails the output).
set -eu
QUIET=; [ "${1:-}" != "-q" ] || { QUIET=1; shift; }
ACTION=${1:-apply}
HERE=$(cd "$(dirname "$0")" && pwd)
COMPOSE_DIR=${COMPOSE_DIR:-$PWD}
[ ! -f "$COMPOSE_DIR/update.env" ] || . "$COMPOSE_DIR/update.env"
URL=${BOUNDGATE_UPDATE_URL:-https://gitlab.net407.com}; URL=${URL%/}
REPO=${BOUNDGATE_UPDATE_REPO:-SBH/BoundGate-VPN}
TOKEN_FILE=${BOUNDGATE_UPDATE_TOKEN_FILE:-}
RELEASE_KEYS=${RELEASE_KEYS:-$HERE/release_keys}
MODE=${MODE:-compose}
INSTALL_DIR=${INSTALL_DIR:-/usr/local/bin}
RESTART_CMD=${RESTART_CMD:-systemctl restart boundgate-node}
DOCKER=${DOCKER:-docker}

say() { [ -n "$QUIET" ] || echo "$*"; }
die() { echo "update: $*" >&2; exit 1; }
for t in curl jq ssh-keygen; do command -v $t >/dev/null 2>&1 || die "$t is needed"; done
case "$URL" in https://*|http://127.0.0.1*|http://localhost*) ;; *) die "BOUNDGATE_UPDATE_URL must be https" ;; esac
case "$ACTION" in check|apply) ;; *) die "usage: update.sh [-q] [check|apply]" ;; esac

WORK=$(mktemp -d); LOCK="$COMPOSE_DIR/.update.lock"
mkdir "$LOCK" 2>/dev/null || die "another update is running ($LOCK)"
trap 'rm -rf "$WORK" "$LOCK"' EXIT INT TERM

# the token goes to the configured instance only, never to where an asset link points
fetch() { # fetch URL FILE
  case "$1" in
    "$URL"/*) if [ -n "$TOKEN_FILE" ]; then
        curl -fsSL --proto '=https,http' --max-time 300 -H "Authorization: token $(tr -d '\n' < "$TOKEN_FILE")" -o "$2" "$1"; return
      fi ;;
  esac
  curl -fsSL --proto '=https,http' --max-time 300 -o "$2" "$1"
}
fetch "$URL/api/v1/repos/$REPO/releases/latest" "$WORK/release.json" || die "cannot read the latest release from $URL (does it want a login? BOUNDGATE_UPDATE_TOKEN_FILE)"
TAG=$(jq -r '.tag_name // empty' "$WORK/release.json")
asset_url() { jq -r --arg n "$1" '.assets[]? | select(.name == $n) | .browser_download_url' "$WORK/release.json" | head -1; }
MURL=$(asset_url manifest.json); SURL=$(asset_url manifest.json.sig)
[ -n "$TAG" ] && [ -n "$MURL" ] && [ -n "$SURL" ] || die "release ${TAG:-?} has no signed manifest"
fetch "$MURL" "$WORK/manifest.json"; fetch "$SURL" "$WORK/manifest.json.sig"

# -- the one place where trust comes from
[ -s "$RELEASE_KEYS" ] || die "no release keys at $RELEASE_KEYS"
grep -v '^[[:space:]]*#' "$RELEASE_KEYS" | grep . | sed 's/^/boundgate-release /' > "$WORK/allowed"
[ -s "$WORK/allowed" ] || die "$RELEASE_KEYS names no key"
ssh-keygen -Y verify -f "$WORK/allowed" -I boundgate-release -n boundgate-release -s "$WORK/manifest.json.sig" < "$WORK/manifest.json" >/dev/null 2>&1 \
  || die "the manifest of $TAG is not signed by a release key: refusing"
M="$WORK/manifest.json"
VERSION=$(jq -r 'select(.type == "boundgate-release") | .version // empty' "$M")
echo "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || die "the signed manifest has no usable version"
[ "$VERSION" = "$TAG" ] || die "release $TAG carries the signed manifest of $VERSION: refusing"

newer() { # newer CURRENT CANDIDATE
  [ -n "$1" ] || return 0
  a=${1#v}; b=${2#v}
  for i in 1 2 3; do
    x=$(echo "$a" | cut -d. -f$i); y=$(echo "$b" | cut -d. -f$i)
    case "$x$y" in *[!0-9]*|'') return 1 ;; esac
    [ "$y" -gt "$x" ] && return 0; [ "$y" -lt "$x" ] && return 1
  done
  return 1
}
ENVFILE="$COMPOSE_DIR/.env"
current() { [ -f "$1" ] && sed -n 's/^BOUNDGATE_RELEASE=//p' "$1" | tail -1 || true; }
if [ "$MODE" = binaries ]; then CUR=$(cat "$INSTALL_DIR/.boundgate-release" 2>/dev/null || true); else CUR=$(current "$ENVFILE"); fi
if ! newer "$CUR" "$VERSION"; then say "up to date: ${CUR:-?} (latest release $VERSION)"; exit 0; fi
if [ "$ACTION" = check ]; then echo "update available: ${CUR:-unknown} -> $VERSION"; exit 0; fi

if [ "$MODE" = binaries ]; then
  ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
  NAME=$(jq -r --arg a "$ARCH" '.assets[] | select(.kind == "binaries" and .os == "linux" and .arch == $a) | .name' "$M" | head -1)
  [ -n "$NAME" ] || die "release $VERSION has no binaries for linux/$ARCH"
  case "$NAME" in */*|.*) die "bad asset name" ;; esac
  AURL=$(asset_url "$NAME"); [ -n "$AURL" ] || die "the release does not offer $NAME"
  fetch "$AURL" "$WORK/$NAME"
  WANT=$(jq -r --arg n "$NAME" '.assets[] | select(.name == $n) | "\(.size) \(.sha256)"' "$M")
  if command -v sha256sum >/dev/null 2>&1; then SUM=$(sha256sum "$WORK/$NAME" | cut -d' ' -f1); else SUM=$(openssl dgst -sha256 -r "$WORK/$NAME" | cut -d' ' -f1); fi
  [ "$(wc -c < "$WORK/$NAME" | tr -d ' ') $SUM" = "$WANT" ] || die "$NAME does not match the signed manifest: refusing"
  mkdir "$WORK/x" && tar -xzf "$WORK/$NAME" -C "$WORK/x"
  for b in "$WORK"/x/boundgate*; do
    [ -f "$INSTALL_DIR/$(basename "$b")" ] || continue      # only what is installed here
    install -m 755 "$b" "$INSTALL_DIR/.$(basename "$b").new" && mv "$INSTALL_DIR/.$(basename "$b").new" "$INSTALL_DIR/$(basename "$b")"
  done
  echo "$VERSION" > "$INSTALL_DIR/.boundgate-release"
  $RESTART_CMD || die "installed $VERSION, but the restart failed: $RESTART_CMD"
  echo "updated ${CUR:-unknown} -> $VERSION"
  exit 0
fi

REF=$(jq -r '.image.ref // empty' "$M"); DIGEST=$(jq -r '.image.digest // empty' "$M")
echo "$DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$' && [ -n "$REF" ] || die "the signed manifest names no image"
case "$REF" in *[!A-Za-z0-9./:_-]*) die "bad image reference" ;; esac
[ -f "$COMPOSE_DIR/docker-compose.yml" ] || die "no docker-compose.yml in $COMPOSE_DIR (COMPOSE_DIR, or MODE=binaries)"
IMAGE="$REF@$DIGEST"
$DOCKER pull -q "$IMAGE" >/dev/null || die "cannot pull $IMAGE"
touch "$ENVFILE"; cp "$ENVFILE" "$ENVFILE.before-update"
{ grep -v '^BOUNDGATE_IMAGE=\|^BOUNDGATE_RELEASE=' "$ENVFILE.before-update" || true; echo "BOUNDGATE_IMAGE=$IMAGE"; echo "BOUNDGATE_RELEASE=$VERSION"; } > "$ENVFILE"
up() { (cd "$COMPOSE_DIR" && $DOCKER compose up -d --remove-orphans >/dev/null 2>&1); }
healthy() { # every container of the project running, none restarting
  sleep "${SETTLE:-20}"
  (cd "$COMPOSE_DIR" && $DOCKER compose ps --format json 2>/dev/null) | jq -es 'flatten | length > 0 and all(.[]; .State == "running")' >/dev/null
}
if up && healthy; then
  rm -f "$ENVFILE.before-update"
  echo "updated ${CUR:-unknown} -> $VERSION ($IMAGE)"
else
  echo "update: $VERSION did not stay up; going back to ${CUR:-the previous image}" >&2
  mv "$ENVFILE.before-update" "$ENVFILE"; up || true
  exit 1
fi
