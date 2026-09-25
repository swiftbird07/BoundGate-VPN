#!/bin/sh
# Makes a release, from the maintainer's Mac:
#
#   make release                    # next patch version after the highest tag (first: v0.1.0)
#   make release BUMP=minor         # or major
#   make release VERSION=v1.4.0     # a version of your choice; also resumes that release
#
#   1. tags the commit and pushes the tag; CI (.gitea/workflows/release.yml)
#      builds the Linux binaries and the image and parks them in a draft release
#   2. meanwhile builds, signs and notarizes the Mac app here (your Developer ID
#      and notary credentials stay in your keychain)
#   3. downloads what CI built, writes the manifest over all of it and signs it
#      with the release key, which exists only here (docs/RELEASES.md)
#   4. uploads Mac app, manifest and signature, and publishes the draft
#   5. puts the same files on GitHub, the public mirror that updaters read
#      (deploy/release/mirror-github.sh)
#
# Every step can be repeated: run it again with VERSION=... after a failure.
#
# Needs: git, curl, jq, ssh-keygen, openssl; for the Mac app Xcode and what
# apps/macos/notarize.sh asks for. Environment:
#   GITEA_TOKEN / GITEA_TOKEN_FILE  access token with write:repository (default
#                                   file: private/gitea_token, one line, 0600)
#   RELEASE_KEY   private half of a key in internal/update/release_keys
#                 (default private/release_signing_key; passphrase or a FIDO2
#                 "sk" key are fine: ssh-keygen asks)
#   NO_MAC=1      a release without the Mac app
#   NO_GITHUB=1   do not mirror to GitHub (updaters read GitHub by default: they
#                 will not see this release); otherwise GITHUB_TOKEN(_FILE) and
#                 GITHUB_REPO as in mirror-github.sh
#   NO_GO_VERIFY=1  skip the second signature check (with the updater's Go code, in the box)
#   GITEA_URL, GITEA_REPO, WAIT_MINUTES (40)
set -eu
cd "$(dirname "$0")/../.."

GITEA_URL=${GITEA_URL:-https://gitlab.net407.com}
GITEA_REPO=${GITEA_REPO:-SBH/BoundGate-VPN}
API=$GITEA_URL/api/v1/repos/$GITEA_REPO
RELEASE_KEY=${RELEASE_KEY:-private/release_signing_key}
KEYS=internal/update/release_keys
WAIT_MINUTES=${WAIT_MINUTES:-40}
POLL=${POLL:-20}
NS=boundgate-release

say() { echo "== $*"; }
die() { echo "release: $*" >&2; exit 1; }
sha() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
keygen() { if [ -x /opt/homebrew/bin/ssh-keygen ]; then /opt/homebrew/bin/ssh-keygen "$@"; else ssh-keygen "$@"; fi; } # Apple's cannot use FIDO2 keys

highest() { git tag -l 'v[0-9]*.[0-9]*.[0-9]*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1; }
# next_version BUMP: the highest vX.Y.Z tag, one further
next_version() {
  last=$(highest)
  [ -n "$last" ] || { echo v0.1.0; return; }
  IFS=. read -r ma mi pa <<EOF
${last#v}
EOF
  case "$1" in
    patch) pa=$((pa + 1)) ;;
    minor) mi=$((mi + 1)); pa=0 ;;
    major) ma=$((ma + 1)); mi=0; pa=0 ;;
    *) die "BUMP must be patch, minor or major" ;;
  esac
  echo "v$ma.$mi.$pa"
}
# newer A B: is version A greater than B?
newer() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1.2,1n -k2,2n -k3,3n | tail -1)" = "$1" ]; }

if [ "${1:-}" = "--next" ]; then next_version "${BUMP:-patch}"; exit 0; fi

# ---- before anything leaves this machine ----
for t in git curl jq openssl ssh-keygen; do command -v $t >/dev/null || die "$t is missing"; done
TOKEN=${GITEA_TOKEN:-}
if [ -z "$TOKEN" ]; then
  f=${GITEA_TOKEN_FILE:-private/gitea_token}
  [ -r "$f" ] || die "no access token: put one with write:repository into $f (one line, chmod 600) or set GITEA_TOKEN"
  TOKEN=$(tr -d '\r\n' < "$f")
fi
[ -r "$RELEASE_KEY" ] && [ -r "$RELEASE_KEY.pub" ] || die "no release key at $RELEASE_KEY (make release-key)"
pub=$(awk '{print $1" "$2}' "$RELEASE_KEY.pub")
grep -v '^#' "$KEYS" | awk '{print $1" "$2}' | grep -qxF "$pub" || die "$RELEASE_KEY.pub is not in $KEYS: no build would accept this release. Add and commit it first (make release-key does both files)"
cmp -s "$KEYS" deploy/prod/release_keys || die "$KEYS and deploy/prod/release_keys differ"
[ -z "$(git status --porcelain)" ] || die "uncommitted changes; a release is a commit"
git fetch -q --tags origin
HEAD=$(git rev-parse HEAD)
# every Go binary of a release is built with go.mod's toolchain line (CI records its Go in build.json)
GO_WANT=$(sed -n 's/^toolchain \(go[0-9.]*\)$/\1/p' go.mod)
[ -n "$GO_WANT" ] || die "go.mod has no toolchain line: a release pins its Go"

V=${1:-${VERSION:-}}
[ -n "$V" ] && [ "$V" != dev ] || V=$(next_version "${BUMP:-patch}")
echo "$V" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || die "version must be vMAJOR.MINOR.PATCH, got $V"

# the token stays off every command line (ps shows those): curl reads it from a file only we can read
TMP=$(umask 077; mktemp -d); trap 'rm -rf "$TMP"' EXIT
printf 'header = "Authorization: token %s"\n' "$TOKEN" > "$TMP/auth"
api() { # api METHOD PATH [curl args]: JSON on stdout
  m=$1; p=$2; shift 2
  curl -fsS -K "$TMP/auth" -X "$m" -H 'Content-Type: application/json' "$@" "$API$p"
}

# a pushed tag starts CI and is seen by everyone: find out now what would stop this run later
[ "$(api GET "" | jq -r '.permissions.push')" = true ] || die "the access token does not get write access to $GITEA_REPO at $GITEA_URL (curl's message above: 401 = wrong or expired token, 404 = the token's user does not see the repository)"
[ -n "${NO_GITHUB:-}" ] || deploy/release/mirror-github.sh --check
PLAIN=${V#v}
ZIP=dist/BoundGate-$PLAIN-macos.zip; DMG=dist/BoundGate-$PLAIN.dmg
if [ -n "${NO_MAC:-}" ]; then MAC=none
elif [ -f "$ZIP" ] && [ -f "$DMG" ] && [ "$(cat dist/.release-built 2>/dev/null)" = "$V $HEAD" ]; then MAC=built
else
  MAC=build
  # the daemon and CLI inside the app are built in the box: with the same Go as CI's
  command -v box >/dev/null || die "box is missing: the Mac app's Go binaries are built in it"
  have=$(box go env GOVERSION) || die "cannot ask the box for its Go"
  [ "$have" = "$GO_WANT" ] || die "the box has $have, go.mod pins $GO_WANT: bring them together first"
  case "${SIGN_IDENTITY:-}" in
    "") security find-identity -v -p codesigning | grep -q '"Developer ID Application: ' || die "no \"Developer ID Application\" identity in the keychain (an \"Apple Development\" one cannot be notarized); NO_MAC=1 releases without the Mac app" ;;
    "Developer ID Application: "*) ;;
    *) die "SIGN_IDENTITY=$SIGN_IDENTITY cannot be notarized: a release needs a \"Developer ID Application\" identity" ;;
  esac
  if [ -z "${NOTARY_KEY_FILE:-}" ]; then
    xcrun notarytool history --keychain-profile "${NOTARY_PROFILE:-boundgate-notary}" >/dev/null 2>"$TMP/notary" \
      || die "notarytool cannot use the keychain profile ${NOTARY_PROFILE:-boundgate-notary} (apps/macos/notarize.sh says how to store it): $(tail -1 "$TMP/notary")"
  fi
fi

# ---- 1. tag ----
if git rev-parse -q --verify "refs/tags/$V" >/dev/null; then
  [ "$(git rev-parse "$V^{commit}")" = "$HEAD" ] || die "tag $V exists and is not the commit checked out; check it out to resume, or pick another version"
  say "$V is tagged already: resuming"
else
  top=$(highest)
  [ -z "$top" ] || newer "$V" "$top" || die "$V is not newer than $top: nodes refuse to go back"
  [ "$(git rev-parse origin/main)" = "$HEAD" ] || die "HEAD is not origin/main: push first, releases are built from what is on the server"
  git tag -a "$V" -m "BoundGate $V"
  say "tagged $V at $(git rev-parse --short HEAD)"
fi
if [ -z "$(git ls-remote --tags origin "refs/tags/$V")" ]; then
  git push -q origin "refs/tags/$V"
  say "pushed the tag; CI builds the Linux binaries and the image now"
fi

# ---- 2. Mac app, while CI works ----
if [ $MAC = none ]; then
  say "NO_MAC: this release gets no Mac app"
elif [ $MAC = built ]; then
  say "Mac app of $V is built already"
else
  say "building, signing and notarizing the Mac app"
  RELEASE=$V UNIVERSAL=1 apps/macos/build-app.sh
  apps/macos/notarize.sh
  [ -f "$ZIP" ] && [ -f "$DMG" ] || die "the Mac build did not leave $ZIP and $DMG"
  echo "$V $HEAD" > dist/.release-built
fi

mirror() {
  if [ -n "${NO_GITHUB:-}" ]; then say "NO_GITHUB: not mirrored; updaters that read GitHub do not see $V"; else deploy/release/mirror-github.sh "$V"; fi
}
# a run that got as far as publishing here only has the mirror left to do
if [ "$(api GET "/releases/tags/$V" 2>/dev/null | jq -r '.draft')" = false ]; then
  say "$V is published on $GITEA_URL already"
  mirror
  exit 0
fi

# ---- 3. what CI built ----
say "waiting for CI's draft release of $V (up to $WAIT_MINUTES min)"
deadline=$(( $(date +%s) + WAIT_MINUTES * 60 ))
while :; do
  REL=$(api GET "/releases?draft=true&limit=50" | jq -c --arg v "$V" '[.[] | select(.tag_name == $v)][0] // empty')
  if [ -n "$REL" ]; then
    [ "$(echo "$REL" | jq -r .draft)" = true ] || die "$V is published already"
    echo "$REL" | jq -e '[.assets[].name] | index("build.json")' >/dev/null && break
  fi
  [ "$(date +%s)" -lt "$deadline" ] || die "no complete draft of $V after $WAIT_MINUTES min; look at the release workflow in Gitea, then run: make release VERSION=$V"
  sleep "$POLL"
done
RID=$(echo "$REL" | jq -r .id)
OUT=dist/release/$V
rm -rf "$OUT" "$OUT.build.json"; mkdir -p "$OUT"
echo "$REL" | jq -r '.assets[] | "\(.name)\t\(.browser_download_url)"' | while IFS="$(printf '\t')" read -r name url; do
  case "$name" in
    build.json) dst=$OUT.build.json ;;
    boundgate-*-linux-*.tar.gz|boundgate-*-windows-*.zip) dst=$OUT/$name ;;
    *) continue ;; # leftovers of an earlier attempt: replaced below
  esac
  case "$url" in "$GITEA_URL"/*) ;; *) die "asset $name would be downloaded from $url: the token only goes to $GITEA_URL" ;; esac
  curl -fsS -K "$TMP/auth" -o "$dst" "$url"
done
B=$OUT.build.json
[ -s "$B" ] || die "could not download build.json"
[ "$(jq -r .version "$B")" = "$V" ] || die "CI built $(jq -r .version "$B"), not $V"
[ "$(jq -r .commit "$B")" = "$HEAD" ] || die "CI built commit $(jq -r .commit "$B"), the tag here is $HEAD"
[ "$(jq -r '.go // empty' "$B")" = "$GO_WANT" ] || die "CI built with $(jq -r '.go // "a Go it did not record"' "$B"), go.mod pins $GO_WANT: not signing this"
n=0
for name in $(jq -r '.assets[].name' "$B"); do
  [ -f "$OUT/$name" ] || die "$name is in CI's build record but not in the draft"
  [ "$(sha "$OUT/$name")" = "$(jq -r --arg n "$name" '.assets[] | select(.name == $n) | .sha256' "$B")" ] || die "$name does not have the hash CI recorded: not signing this"
  n=$((n + 1))
done
[ "$n" -ge 1 ] && [ "$n" = "$(ls "$OUT" | wc -l | tr -d ' ')" ] || die "the draft and CI's build record disagree about the files"
IMAGE=$(jq -r '.image.ref // empty' "$B"); DIGEST=$(jq -r '.image.digest // empty' "$B")
[ -n "$IMAGE" ] && [ -n "$DIGEST" ] || die "CI's build record names no image"
[ -n "${NO_MAC:-}" ] || cp "$ZIP" "$DMG" "$OUT/"

# ---- 4. manifest, signed here ----
COMMIT=$HEAD deploy/release/manifest.sh "$V" "$OUT" "$IMAGE" "$DIGEST" > "$OUT/manifest.json"
say "signing the manifest with $RELEASE_KEY"
rm -f "$OUT/manifest.json.sig"
keygen -q -Y sign -n $NS -f "$RELEASE_KEY" "$OUT/manifest.json"
# what every client will do; a signature they would refuse must not go out
grep -v '^#' "$KEYS" | grep . | sed "s/^/$NS /" > "$TMP/allowed"
keygen -Y verify -f "$TMP/allowed" -I $NS -n $NS -s "$OUT/manifest.json.sig" < "$OUT/manifest.json" >/dev/null || die "the signature does not verify against $KEYS"
# and with the code the nodes run (it is stricter than ssh-keygen about key types); Go lives in the box
if [ -z "${NO_GO_VERIFY:-}" ]; then
  command -v box >/dev/null || die "box is missing: cannot check the signature with the updater's own code (NO_GO_VERIFY=1 skips this)"
  box go run ./cmd/boundgatectl verify-release "$OUT/manifest.json" "$OUT/manifest.json.sig" || die "the nodes' verifier refuses this signature: not publishing"
fi

# ---- 5. upload, publish ----
for f in "$OUT"/*; do
  name=$(basename "$f")
  case "$name" in boundgate-*-linux-*.tar.gz|boundgate-*-windows-*.zip) continue ;; esac # CI's, already there
  old=$(echo "$REL" | jq -r --arg n "$name" '.assets[] | select(.name == $n) | .id')
  for id in $old; do api DELETE "/releases/$RID/assets/$id" >/dev/null; done
  curl -fsS -K "$TMP/auth" -X POST -F "attachment=@$f" "$API/releases/$RID/assets?name=$name" >/dev/null
  echo "   uploaded $name"
done
NOTE="Verify before use: manifest.json is signed (ssh-keygen -Y verify, namespace $NS, keys in internal/update/release_keys) and names every file here and the image by digest. docs/RELEASES.md"
[ -z "${NO_MAC:-}" ] || NOTE="$NOTE

This release has no macOS app."
jq -n --arg b "$NOTE" '{draft:false, body:$b}' | api PATCH "/releases/$RID" -d @- >/dev/null
# CI's build record has served its purpose; the manifest replaces it (only now, so that a failure above can be resumed)
for id in $(echo "$REL" | jq -r '.assets[] | select(.name == "build.json") | .id'); do api DELETE "/releases/$RID/assets/$id" >/dev/null || true; done
[ "$(api GET /releases/latest | jq -r .tag_name)" = "$V" ] || die "published, but releases/latest does not answer $V: check the release page"
say "released $V: $GITEA_URL/$GITEA_REPO/releases/tag/$V"
jq -r '.assets[] | "   \(.name)  \(.sha256)"' "$OUT/manifest.json"

# ---- 6. the public mirror ----
mirror
