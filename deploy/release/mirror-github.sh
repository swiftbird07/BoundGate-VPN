#!/bin/sh
# Puts a release that was made and signed here (deploy/release/release.sh) on
# GitHub as well, where anyone can read it: the same files, byte for byte, with
# the same signed manifest. `make release` runs this as its last step;
#
#   make release-mirror VERSION=v1.4.0
#
# repeats it, or mirrors a release from before there was a mirror. GitHub only
# stores files: nothing is built there, and no signing key is anywhere near it.
# Clients install what the signed manifest names, so whoever controls the
# GitHub repository can withhold a release, not change one (docs/RELEASES.md).
#
#   mirror-github.sh --check      only checks that the token can write to the repository
#
# The code gets to GitHub by Gitea's push mirror, tags included; this script
# waits for the tag and refuses one that is not the tag made here.
#
# Environment:
#   GITHUB_TOKEN / GITHUB_TOKEN_FILE  fine-grained token for that one repository,
#                                     "Contents: read and write" (default file:
#                                     private/github_token, one line, 0600)
#   GITHUB_REPO   owner/name (swiftbird07/BoundGate-VPN)
#   WAIT_MINUTES (10), POLL (15): how long to wait for the tag
set -eu
cd "$(dirname "$0")/../.."

GITHUB_REPO=${GITHUB_REPO:-swiftbird07/BoundGate-VPN}
GITHUB_URL=${GITHUB_URL:-https://github.com}
GITHUB_API=${GITHUB_API:-https://api.github.com}
GITHUB_UPLOADS=${GITHUB_UPLOADS:-https://uploads.github.com}
KEYS=internal/update/release_keys
NS=boundgate-release
WAIT_MINUTES=${WAIT_MINUTES:-10}
POLL=${POLL:-15}

say() { echo "== $*"; }
die() { echo "mirror: $*" >&2; exit 1; }
sha() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
keygen() { if [ -x /opt/homebrew/bin/ssh-keygen ]; then /opt/homebrew/bin/ssh-keygen "$@"; else ssh-keygen "$@"; fi; }

for t in git curl jq openssl ssh-keygen; do command -v $t >/dev/null || die "$t is missing"; done
TOKEN=${GITHUB_TOKEN:-}
if [ -z "$TOKEN" ]; then
  f=${GITHUB_TOKEN_FILE:-private/github_token}
  [ -r "$f" ] || die "no GitHub token: put a fine-grained one for $GITHUB_REPO (Contents: read and write) into $f (one line, chmod 600) or set GITHUB_TOKEN; NO_GITHUB=1 releases without the mirror"
  TOKEN=$(tr -d '\r\n' < "$f")
fi
# the token stays off every command line, and goes to GitHub's API and upload hosts only
TMP=$(umask 077; mktemp -d); trap 'rm -rf "$TMP"' EXIT
printf 'header = "Authorization: Bearer %s"\nheader = "Accept: application/vnd.github+json"\nheader = "X-GitHub-Api-Version: 2022-11-28"\n' "$TOKEN" > "$TMP/auth"
API=$GITHUB_API/repos/$GITHUB_REPO
ghapi() { # ghapi METHOD PATH [curl args]: JSON on stdout
  m=$1; p=$2; shift 2
  curl -fsS -K "$TMP/auth" -X "$m" "$@" "$API$p"
}

[ "$(ghapi GET "" | jq -r '.permissions.push')" = true ] || die "the GitHub token does not get write access to $GITHUB_REPO (curl's message above: 401 = wrong or expired token, 404 = the token does not cover this repository)"
[ "${1:-}" != "--check" ] || exit 0

V=${1:-${VERSION:-}}
echo "$V" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || die "usage: mirror-github.sh vMAJOR.MINOR.PATCH"
OUT=dist/release/$V
M=$OUT/manifest.json

# ---- only what was signed here goes out ----
[ -s "$M" ] && [ -s "$M.sig" ] || die "no signed release in $OUT: this mirrors what \`make release\` left there (on the machine that made the release)"
grep -v '^#' "$KEYS" | grep . | sed "s/^/$NS /" > "$TMP/allowed"
keygen -Y verify -f "$TMP/allowed" -I $NS -n $NS -s "$M.sig" < "$M" >/dev/null 2>&1 || die "$M is not signed by a key in $KEYS"
[ "$(jq -r 'select(.type == "boundgate-release") | .version' "$M")" = "$V" ] || die "$M is not the manifest of $V"
n=2
for name in $(jq -r '.assets[].name' "$M"); do
  case "$name" in */*|.*) die "bad asset name $name" ;; esac
  [ -f "$OUT/$name" ] || die "$name is in the manifest but not in $OUT"
  [ "$(sha "$OUT/$name")" = "$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .sha256' "$M")" ] || die "$OUT/$name is not the file the manifest names"
  n=$((n + 1))
done
[ "$n" = "$(ls "$OUT" | wc -l | tr -d ' ')" ] || die "$OUT holds files the manifest does not name"

# ---- the tag: brought by Gitea's push mirror, and it has to be ours ----
want=$(git rev-parse -q --verify "refs/tags/$V") || die "there is no tag $V in this repository"
say "waiting for tag $V on GitHub (up to $WAIT_MINUTES min)"
deadline=$(( $(date +%s) + WAIT_MINUTES * 60 ))
while :; do
  got=$(ghapi GET "/git/ref/tags/$V" 2>/dev/null | jq -r '.object.sha // empty') || got=
  [ "$got" != "$want" ] || break
  [ -z "$got" ] || die "tag $V on GitHub is $got, here it is $want: not attaching a release to a tag somebody else made"
  [ "$(date +%s)" -lt "$deadline" ] || die "tag $V has not arrived on GitHub: look at the push mirror (Gitea > repository settings > Mirror Settings, \"Synchronize now\"), then run: make release-mirror VERSION=$V"
  sleep "$POLL"
done

# ---- draft, files, publish ----
visible() { [ "$(curl -fsS -o /dev/null -w '%{redirect_url}' "$GITHUB_URL/$GITHUB_REPO/releases/latest")" = "$GITHUB_URL/$GITHUB_REPO/releases/tag/$V" ]; }
REL=$(ghapi GET "/releases?per_page=100" | jq -c --arg v "$V" '[.[] | select(.tag_name == $v)][0] // empty')
if [ -n "$REL" ] && [ "$(echo "$REL" | jq -r .draft)" = false ]; then
  say "$V is on GitHub already: $GITHUB_URL/$GITHUB_REPO/releases/tag/$V"
  exit 0
fi
NOTE="Verify before use: manifest.json is signed (ssh-keygen -Y verify, namespace $NS, keys in internal/update/release_keys) and names every file here and the image by digest. docs/RELEASES.md"
[ -n "$REL" ] || REL=$(jq -n --arg t "$V" --arg b "$NOTE" '{tag_name:$t, name:$t, body:$b, draft:true}' | ghapi POST /releases -d @-)
RID=$(echo "$REL" | jq -r .id)
UP=$(echo "$REL" | jq -r '.upload_url // empty' | sed 's/{.*//')
case "$UP" in "$GITHUB_UPLOADS"/*) ;; *) die "GitHub names $UP for uploads: the token only goes to $GITHUB_API and $GITHUB_UPLOADS" ;; esac
for f in "$OUT"/*; do
  name=$(basename "$f")
  for id in $(echo "$REL" | jq -r --arg n "$name" '.assets[]? | select(.name == $n) | .id'); do ghapi DELETE "/releases/assets/$id" >/dev/null; done # of an earlier attempt
  curl -fsS -K "$TMP/auth" -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$f" "$UP?name=$name" >/dev/null
  echo "   uploaded $name"
done
# an older release mirrored after the fact must not become "latest"
LATEST=true; [ "$(git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1)" = "$V" ] || LATEST=false
jq -n --arg l $LATEST '{draft:false, make_latest:$l}' | ghapi PATCH "/releases/$RID" -d @- >/dev/null
# what every updater does, without a token
[ $LATEST = false ] || visible || die "published, but $GITHUB_URL/$GITHUB_REPO/releases/latest does not lead visitors to $V: is the repository public?"
say "mirrored $V: $GITHUB_URL/$GITHUB_REPO/releases/tag/$V"
