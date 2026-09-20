#!/bin/sh
# Points the image tag `latest` at a release, for people and tools that follow
# a tag (`docker compose pull`, Dockhand, Watchtower) instead of running
# deploy/prod/update.sh:
#
#   tag-latest.sh MANIFEST SIG [REPOSITORY]
#
# MANIFEST and SIG are a release's manifest.json and manifest.json.sig. The
# tag only ever moves to the digest a release key signed: the signature is
# checked first, and the bytes the registry holds under that digest are
# hashed before they are put under the new tag. REPOSITORY defaults to the
# image the manifest names (ghcr.io/...).
#
# No docker: two requests to the registry API (get the image index by digest,
# put the same bytes as `latest`). Runs in CI when a release is published
# (.gitea/workflows/latest.yml) and by hand.
#
# What this does not give: a host that follows `latest` trusts the registry
# and whoever can push to it; only update.sh checks the signature on the host
# (docs/RELEASES.md, R99).
#
# Environment:
#   REGISTRY_USER, REGISTRY_TOKEN   a login that may push (ghcr.io: a classic
#                                   token with write:packages)
#   TAG            the tag to move (latest)
#   RELEASE_KEYS   public keys (deploy/prod/release_keys)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
M=${1:-}; SIG=${2:-}
[ -s "$M" ] && [ -s "$SIG" ] || { echo "usage: tag-latest.sh manifest.json manifest.json.sig [repository]" >&2; exit 2; }
TAG=${TAG:-latest}
RELEASE_KEYS=${RELEASE_KEYS:-$HERE/../prod/release_keys}
die() { echo "tag-latest: $*" >&2; exit 1; }
for t in curl jq ssh-keygen openssl; do command -v $t >/dev/null || die "$t is missing"; done
TMP=$(umask 077; mktemp -d); trap 'rm -rf "$TMP"' EXIT

# ---- the signed manifest says which digest ----
grep -v '^[[:space:]]*#' "$RELEASE_KEYS" | grep . | sed 's/^/boundgate-release /' > "$TMP/allowed"
ssh-keygen -Y verify -f "$TMP/allowed" -I boundgate-release -n boundgate-release -s "$SIG" < "$M" >/dev/null 2>&1 || die "$M is not signed by a release key"
V=$(jq -r 'select(.type == "boundgate-release") | .version // empty' "$M")
DIGEST=$(jq -r '.image.digest // empty' "$M")
REPO=${3:-$(jq -r '.image.ref // empty' "$M")}
echo "$DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$' && [ -n "$V" ] || die "the manifest names no image"
case "$REPO" in ''|*[!A-Za-z0-9./:_-]*) die "bad repository: $REPO" ;; esac
case "$TAG" in ''|*[!A-Za-z0-9._-]*) die "bad tag: $TAG" ;; esac
HOST=${REPO%%/*}; NAME=${REPO#*/}
case "$HOST" in localhost:*|127.0.0.1:*) BASE=http://$HOST ;; *) BASE=https://$HOST ;; esac

# ---- a token for this repository, the way every registry client gets one ----
: > "$TMP/auth"
challenge=$(curl -sS -o /dev/null -D - "$BASE/v2/" | tr -d '\r' | sed -n 's/^[Ww][Ww][Ww]-[Aa]uthenticate: *[Bb]earer *//p' | head -1)
if [ -n "$challenge" ]; then
  realm=$(echo "$challenge" | sed -n 's/.*realm="\([^"]*\)".*/\1/p'); service=$(echo "$challenge" | sed -n 's/.*service="\([^"]*\)".*/\1/p')
  case "$realm" in https://*) ;; *) die "$HOST wants a token from $realm: not https" ;; esac
  [ -n "${REGISTRY_USER:-}" ] && [ -n "${REGISTRY_TOKEN:-}" ] || die "REGISTRY_USER and REGISTRY_TOKEN are needed to push to $HOST"
  printf 'user = "%s:%s"\n' "$REGISTRY_USER" "$REGISTRY_TOKEN" > "$TMP/login"   # off the command line
  token=$(curl -fsS -K "$TMP/login" -G --data-urlencode "service=$service" --data-urlencode "scope=repository:$NAME:pull,push" "$realm" | jq -r '.token // .access_token // empty')
  [ -n "$token" ] || die "$HOST gave no token for $NAME (does the login have write access to the package?)"
  printf 'header = "Authorization: Bearer %s"\n' "$token" > "$TMP/auth"
fi

# ---- the same bytes under another name ----
ACCEPT='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
curl -fsS -K "$TMP/auth" -H "$ACCEPT" -D "$TMP/headers" -o "$TMP/index" "$BASE/v2/$NAME/manifests/$DIGEST" || die "$REPO does not hold $DIGEST (the image of $V was pushed elsewhere?)"
[ "sha256:$(openssl dgst -sha256 -r "$TMP/index" | cut -d' ' -f1)" = "$DIGEST" ] || die "$HOST answered $DIGEST with other bytes"
TYPE=$(tr -d '\r' < "$TMP/headers" | sed -n 's/^[Cc]ontent-[Tt]ype: *//p' | tail -1)
[ -n "$TYPE" ] || TYPE=$(jq -r '.mediaType // empty' "$TMP/index")
[ -n "$TYPE" ] || die "$HOST did not say what kind of manifest $DIGEST is"
curl -fsS -K "$TMP/auth" -X PUT -H "Content-Type: $TYPE" --data-binary "@$TMP/index" -o /dev/null "$BASE/v2/$NAME/manifests/$TAG" || die "could not put $REPO:$TAG"
# and read it back
got=$(curl -fsS -K "$TMP/auth" -H "$ACCEPT" -I "$BASE/v2/$NAME/manifests/$TAG" | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p' | tail -1)
[ "$got" = "$DIGEST" ] || die "$REPO:$TAG is $got after the push, expected $DIGEST"
echo "$REPO:$TAG -> $V ($DIGEST)"
