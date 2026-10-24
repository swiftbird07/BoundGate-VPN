#!/bin/sh
# deploy/release/release.sh against a stand-in for Gitea: a throwaway
# repository with a bare "origin", a throwaway release key, and a `curl` on
# PATH that answers the API calls from files. The Mac build is not part of it
# (it needs your Developer ID): the test puts the two Mac files in place the
# way a finished build leaves them. Needs git, jq, ssh-keygen, openssl.
set -eu
SRC=$(cd "$(dirname "$0")/../.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
sha() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }

# ---- a repository that looks enough like this one ----
git init -q --bare "$T/origin.git"
git init -q -b main "$T/repo"; cd "$T/repo"
git config user.email test@example.net; git config user.name test
mkdir -p deploy/release deploy/prod internal/update private dist
cp "$SRC/deploy/release/release.sh" "$SRC/deploy/release/manifest.sh" "$SRC/deploy/release/mirror-github.sh" \
   "$SRC/deploy/release/sign-apk.sh" deploy/release/
ssh-keygen -q -t ed25519 -N '' -C test-release-key -f private/release_signing_key
{ echo "# test keys"; cat private/release_signing_key.pub; } > internal/update/release_keys
cp internal/update/release_keys deploy/prod/release_keys
mkdir -p apps/android
printf '#!/bin/sh\nset -eu\nmkdir -p dist\necho "apk $VERSION $ANDROID_BUILD" > "dist/BoundGate-$VERSION-unsigned.apk"\n' > apps/android/build.sh
chmod +x apps/android/build.sh
printf 'private/\ndist/\n' > .gitignore
GO_WANT=$(sed -n 's/^toolchain //p' "$SRC/go.mod"); [ -n "$GO_WANT" ] || fail "go.mod has no toolchain line"
printf 'module example.test/r\n\ngo 1.26.0\n\ntoolchain %s\n' "$GO_WANT" > go.mod
printf '#!/bin/sh\nKIT_FLOOR=v0.1.10\n' > deploy/prod/update.sh   # the last release before v0.1.11, as it would be
git add -A; git commit -qm init
git remote add origin "$T/origin.git"; git push -q -u origin main

R="sh deploy/release/release.sh"
# This tree has no Makefile and no Go code: the scan of the real release
# (govulncheck in the box) has nothing to look at here, like the Mac build.
export NO_VULN=1
# ---- version numbers ----
[ "$($R --next)" = v0.1.0 ] || fail "first version: $($R --next)"
for t in v0.1.0 v0.1.9 v0.1.10 v0.2.0-rc1 nightly; do git tag "$t"; done
[ "$($R --next)" = v0.1.11 ] || fail "next patch after v0.1.10 (numeric, not alphabetic; other tags ignored): $($R --next)"
[ "$(BUMP=minor $R --next)" = v0.2.0 ] || fail "minor: $(BUMP=minor $R --next)"
[ "$(BUMP=major $R --next)" = v1.0.0 ] || fail "major"
git push -q origin --tags

# ---- the stand-in for Gitea, and for GitHub (three hosts: website, API, uploads) ----
G=$T/gitea; mkdir -p "$G/assets" "$G/uploaded" "$T/bin"
printf 'v0.1.0\nv0.1.9\nv0.1.10\n' > "$G/published"   # the releases the tags of old stand for
cat > "$T/bin/curl" <<'EOF'
#!/bin/sh
# understands what the release scripts send: -K file, -X METHOD, -o FILE, -w FORMAT,
# -F attachment=@FILE, --data-binary @FILE, -d @-, URL last
method=GET; out=; attach=; auth=
while [ $# -gt 1 ]; do
  case "$1" in
    -X) method=$2; shift ;; -o) out=$2; shift ;; -K) auth=$2; shift ;; -H|-w) shift ;;
    -F) attach=${2#attachment=@}; shift ;; --data-binary) attach=${2#@}; shift ;; -d) cat > "$FAKE/body"; shift ;;
  esac
  shift
done
url=$1
# each token is accepted by its own service only, and the website is read without one
case "$url" in
  http://api.github.test/*|http://uploads.github.test/*) grep -q 'Authorization: Bearer gh-token' "$auth" 2>/dev/null || { echo "curl: 401 (github)" >&2; exit 22; } ;;
  http://github.test/*) [ -z "$auth" ] || { echo "curl: a token went to the GitHub website" >&2; exit 22; } ;;
  *) grep -q 'Authorization: token test-token' "$auth" 2>/dev/null || { echo "curl: 401" >&2; exit 22; } ;;
esac
echo "$method $url" >> "$FAKE/calls"
case "$method $url" in
  "GET http://api.github.test/repos/go/gr") echo "{\"permissions\":{\"push\":${FAKE_GH_PUSH:-true}}}" ;;
  "GET http://api.github.test/repos/go/gr/git/ref/tags/"*) # a push mirror that works: GitHub has the tags this repository has
    sha=${FAKE_GH_TAG:-$(git rev-parse -q --verify "refs/tags/${url##*/}" 2>/dev/null)}; [ -n "$sha" ] || exit 22
    echo "{\"object\":{\"sha\":\"$sha\"}}" ;;
  "GET http://api.github.test/repos/go/gr/releases?per_page=100") cat "$FAKE/gh-releases.json" ;;
  "POST http://api.github.test/repos/go/gr/releases") cp "$FAKE/body" "$FAKE/gh-created"
    echo '{"id":70, "draft":true, "assets":[], "upload_url":"http://uploads.github.test/repos/go/gr/releases/70/assets{?name,label}"}' ;;
  "POST http://uploads.github.test/repos/go/gr/releases/70/assets?name="*) cp "$attach" "$FAKE/gh-uploaded/${url##*name=}"; echo '{}' ;;
  "PATCH http://api.github.test/repos/go/gr/releases/70") cp "$FAKE/body" "$FAKE/gh-patched"; echo '{}' ;;
  "GET http://github.test/go/gr/releases/latest") printf 'http://github.test/go/gr/releases/tag/%s' "$(jq -r .tag_name "$FAKE/gh-created")" ;;
  "GET "*"/releases/tags/"*) # releases of old: $FAKE/published; the current one: a draft until it is patched
    t=${url##*/}; cur=$(jq -r '.[0].tag_name // empty' "$FAKE/releases.json" 2>/dev/null)
    if grep -qx "$t" "$FAKE/published" 2>/dev/null || { [ -f "$FAKE/patched" ] && [ "$t" = "$cur" ]; }; then echo '{"draft":false}'
    elif [ "$t" = "$cur" ]; then echo '{"draft":true}'
    else exit 22; fi ;;
  "GET "*"/repos/o/r") echo "{\"permissions\":{\"push\":${FAKE_PUSH:-true}}}" ;;
  "GET "*"/releases?draft=true"*) cat "$FAKE/releases.json" ;;
  "GET "*"/releases/latest") cat "$FAKE/latest.json" ;;
  "GET "*"/dl/"*) cp "$FAKE/assets/${url##*/}" "$out" ;;
  "POST "*"/assets?name="*) cp "$attach" "$FAKE/uploaded/${url##*name=}"; echo '{}' ;;
  "DELETE "*"/assets/"*) echo "${url##*/}" >> "$FAKE/deleted" ;;
  "PATCH "*"/releases/7") cp "$FAKE/body" "$FAKE/patched"; echo '{}' ;;
  *) echo "fake curl: unexpected $method $url" >&2; exit 22 ;;
esac
EOF
chmod +x "$T/bin/curl"

# The Android app: the build runs in images and the signature needs the SDK,
# so docker and apksigner are stood in for. sign-apk.sh itself is the real
# one, including its certificate pin.
printf '#!/bin/sh\nexit 0\n' > "$T/bin/docker"; chmod +x "$T/bin/docker"
cat > "$T/bin/apksigner" <<'EOF'
#!/bin/sh
# understands "sign --ks K --ks-key-alias A --min-sdk-version N [--ks-pass S]
# --out OUT IN" and "verify ... APK"; FAKE_CERT is the certificate it reports
cmd=$1; shift
case $cmd in
sign)
  out=; ks=; pass=; in=
  while [ $# -gt 0 ]; do
    case "$1" in
      --out) out=$2; shift ;; --ks) ks=$2; shift ;; --ks-pass) pass=$2; shift ;;
      --ks-key-alias|--min-sdk-version|--ks-type|--ks-provider-class|--ks-provider-arg|--lineage|--v4-signing-enabled) shift ;;
      *) in=$1 ;;
    esac
    shift
  done
  [ -n "$ks" ] || { echo "fake apksigner: no --ks" >&2; exit 1; }
  [ -n "$out" ] && [ -f "${in:-}" ] || { echo "fake apksigner: no --out or input" >&2; exit 1; }
  case "$pass" in
    env:*) eval "p=\$${pass#env:}"; [ -n "${p:-}" ] || { echo "fake apksigner: ${pass#env:} is empty" >&2; exit 1; } ;;
    pass:?*|file:?*|stdin) ;;
    *) echo "fake apksigner: no password source" >&2; exit 1 ;;
  esac
  cat "$in" > "$out"; echo "signed by $FAKE_CERT" >> "$out" ;;
verify) echo "Signer #1 certificate SHA-256 digest: $FAKE_CERT" ;;
*) echo "fake apksigner: unexpected $cmd" >&2; exit 1 ;;
esac
EOF
chmod +x "$T/bin/apksigner"
: > "$T/apk.jks"
CERT_A=1111111122222222333333334444444455555555666666667777777788888888
CERT_B=99999999aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff00000000
# the pin outside the repository: a release that writes it must not leave the
# working tree dirty for the next case (in a real repository it is committed)
export APKSIGNER="$T/bin/apksigner" APK_KS="$T/apk.jks" APK_KS_PASS=pass:test FAKE_CERT=$CERT_A APK_CERT_FILE="$T/apk_cert"
# the Go check needs the real tree and the box; ssh-keygen's check stays
export NO_GO_VERIFY=1
export FAKE=$G PATH="$T/bin:$PATH" GITEA_URL=http://gitea.test GITEA_REPO=o/r GITEA_TOKEN=test-token POLL=0 WAIT_MINUTES=0
export GITHUB_URL=http://github.test GITHUB_API=http://api.github.test GITHUB_UPLOADS=http://uploads.github.test GITHUB_REPO=go/gr GITHUB_TOKEN=gh-token

V=v0.1.11; HEAD=$(git rev-parse HEAD)
# what CI leaves in the draft: two tarballs, a Windows zip and its build record
ci_draft() {
  rm -rf "$G/assets" "$G/uploaded" "$G/calls" "$G/deleted" "$G/patched" "$G"/gh-*; mkdir -p "$G/assets" "$G/uploaded" "$G/gh-uploaded"; echo '[]' > "$G/gh-releases.json"
  for a in amd64 arm64; do echo "linux $a $1" > "$G/assets/boundgate-$V-linux-$a.tar.gz"; done
  echo "windows $1" > "$G/assets/boundgate-$V-windows-amd64.zip"
  COMMIT=$HEAD sh deploy/release/manifest.sh $V "$G/assets" registry.test/boundgate sha256:$(printf %064d 7) | jq --arg go "$GO_WANT" '.type = "boundgate-build" | .go = $go' > "$T/build.json"
  cp "$T/build.json" "$G/assets/build.json"
  jq -n --arg v $V '{id:7, tag_name:$v, draft:true, assets:[
    {id:1, name:"boundgate-\($v)-linux-amd64.tar.gz", browser_download_url:"http://gitea.test/dl/boundgate-\($v)-linux-amd64.tar.gz"},
    {id:2, name:"boundgate-\($v)-linux-arm64.tar.gz", browser_download_url:"http://gitea.test/dl/boundgate-\($v)-linux-arm64.tar.gz"},
    {id:4, name:"boundgate-\($v)-windows-amd64.zip", browser_download_url:"http://gitea.test/dl/boundgate-\($v)-windows-amd64.zip"},
    {id:3, name:"build.json", browser_download_url:"http://gitea.test/dl/build.json"}]} | [.]' > "$G/releases.json"
  echo "{\"tag_name\":\"$V\"}" > "$G/latest.json"
}
mac_built() { echo app > dist/BoundGate-0.1.11-macos.zip; echo dmg > dist/BoundGate-0.1.11.dmg; echo "$V $HEAD" > dist/.release-built; }
apk_built() { echo apk > "dist/BoundGate-$V-unsigned.apk"; echo "$V $HEAD" > dist/.release-apk; }

# ---- 1. the whole way, version chosen by the script ----
ci_draft one; mac_built; apk_built
$R > "$T/out" 2>&1 || { cat "$T/out"; fail "release failed"; }
grep -q "released $V" "$T/out" || fail "did not pick $V: $(cat "$T/out")"
[ "$(git ls-remote --tags origin refs/tags/$V | wc -l | tr -d ' ')" = 1 ] || fail "tag not pushed"
for f in manifest.json manifest.json.sig BoundGate-0.1.11-macos.zip BoundGate-0.1.11.dmg BoundGate-0.1.11.apk; do [ -f "$G/uploaded/$f" ] || fail "$f not uploaded"; done
[ ! -e "$G/uploaded/BoundGate-$V-unsigned.apk" ] || fail "the unsigned APK was uploaded"
grep -qx "$CERT_A" "$T/apk_cert" || fail "the first release did not pin the signing certificate: $(cat "$T/apk_cert" 2>&1)"
[ ! -e "$G/uploaded/boundgate-$V-linux-amd64.tar.gz" ] && [ ! -e "$G/uploaded/boundgate-$V-windows-amd64.zip" ] || fail "CI's files were uploaded a second time"
M=$G/uploaded/manifest.json
sed 's/^/boundgate-release /' private/release_signing_key.pub > "$T/allowed"
ssh-keygen -Y verify -f "$T/allowed" -I boundgate-release -n boundgate-release -s "$M.sig" < "$M" >/dev/null 2>&1 || fail "uploaded manifest does not verify"
jq -e --arg v $V --arg c "$HEAD" '.type == "boundgate-release" and .version == $v and .commit == $c and .image.digest == "sha256:'"$(printf %064d 7)"'" and (.assets | length) == 6 and ([.assets[] | select(.os == "windows" and .kind == "binaries")] | length) == 1 and ([.assets[] | select(.kind == "apk" and .os == "android" and .name == "BoundGate-0.1.11.apk")] | length) == 1' "$M" >/dev/null || fail "manifest: $(cat "$M")"
for n in $(jq -r '.assets[].name' "$M"); do
  f=$G/assets/$n; [ -f "$f" ] || f=dist/$n; [ -f "$f" ] || f=dist/release/$V/$n
  [ "$(jq -r --arg n "$n" '.assets[] | select(.name == $n) | .sha256' "$M")" = "$(sha "$f")" ] || fail "hash of $n"
done
jq -e '.draft == false' "$G/patched" >/dev/null || fail "draft not published"
grep -qx 3 "$G/deleted" || fail "CI's build.json was not removed from the published release"
# order: nothing is published before the signature is up
[ "$(grep -n 'PATCH http://gitea.test' "$G/calls" | cut -d: -f1)" -gt "$(grep -n 'gitea.test.*name=manifest.json.sig' "$G/calls" | cut -d: -f1)" ] || fail "published before the signature was uploaded"
# the mirror: the same eight files, the manifest and signature byte for byte, published last, as the latest release
[ "$(ls "$G/gh-uploaded" | wc -l | tr -d ' ')" = 8 ] || fail "GitHub got: $(ls "$G/gh-uploaded")"
for f in manifest.json manifest.json.sig; do cmp -s "$G/uploaded/$f" "$G/gh-uploaded/$f" || fail "GitHub's $f differs from Gitea's"; done
for n in $(jq -r '.assets[].name' "$M"); do [ "$(jq -r --arg n "$n" '.assets[] | select(.name == $n) | .sha256' "$M")" = "$(sha "$G/gh-uploaded/$n")" ] || fail "GitHub's $n is not the file the manifest names"; done
jq -e --arg v $V '.tag_name == $v and .draft == true' "$G/gh-created" >/dev/null && jq -e '.draft == false and .make_latest == "true"' "$G/gh-patched" >/dev/null || fail "GitHub release: $(cat "$G/gh-created" "$G/gh-patched")"
[ "$(grep -n 'PATCH http://api.github.test' "$G/calls" | cut -d: -f1)" -gt "$(grep -n 'uploads.github.test.*name=manifest.json.sig' "$G/calls" | cut -d: -f1)" ] || fail "GitHub: published before the signature was uploaded"
grep -q "mirrored $V" "$T/out" || fail "no mirror: $(cat "$T/out")"

# ---- 2. resume: same version again, tag exists; leftovers of the first attempt are replaced ----
ci_draft one; mac_built; apk_built
jq '.[0].assets += [{id:9, name:"manifest.json", browser_download_url:"http://gitea.test/dl/manifest.json"}]' "$G/releases.json" > "$T/r" && mv "$T/r" "$G/releases.json"
$R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "resume failed"; }
grep -q "resuming" "$T/out" && grep -qx 9 "$G/deleted" || fail "resume did not replace the old manifest"

# ---- 2b. the mirror alone: a tag on GitHub that is not ours gets no release; a second run has only the mirror left ----
ci_draft one; mac_built; apk_built
if FAKE_GH_TAG=0000 $R $V > "$T/out" 2>&1; then fail "attached a release to a foreign tag"; fi
grep -q "somebody else made" "$T/out" && [ -e "$G/patched" ] && [ ! -e "$G/gh-created" ] || fail "foreign tag: $(cat "$T/out")"
: > "$G/calls"
$R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "mirror-only run failed"; }
grep -q "is published on http://gitea.test already" "$T/out" && grep -q "mirrored $V" "$T/out" || fail "mirror-only run: $(cat "$T/out")"
! grep -q 'POST http://gitea.test\|PATCH http://gitea.test' "$G/calls" || fail "the mirror-only run changed the published release"
[ "$(ls "$G/gh-uploaded" | wc -l | tr -d ' ')" = 8 ] || fail "mirror-only run uploaded: $(ls "$G/gh-uploaded")"
# and once it is there, nothing is uploaded again
rm -rf "$G/gh-uploaded"; mkdir "$G/gh-uploaded"; jq -n --arg v $V '[{id:70, tag_name:$v, draft:false}]' > "$G/gh-releases.json"
sh deploy/release/mirror-github.sh $V > "$T/out" 2>&1 && grep -q "on GitHub already" "$T/out" && [ -z "$(ls "$G/gh-uploaded")" ] || fail "mirrored twice: $(cat "$T/out")"
# a file changed after signing does not go out
echo x >> dist/release/$V/boundgate-$V-linux-amd64.tar.gz; echo '[]' > "$G/gh-releases.json"
if sh deploy/release/mirror-github.sh $V > "$T/out" 2>&1; then fail "mirrored a file the manifest does not name"; fi
[ -z "$(ls "$G/gh-uploaded")" ] || fail "something went to GitHub although the check failed"

# ---- 3. a file that is not what CI recorded is not signed ----
ci_draft one; mac_built; apk_built; echo tampered > "$G/assets/boundgate-$V-linux-arm64.tar.gz"
if $R $V > "$T/out" 2>&1; then fail "signed a file that differs from CI's record"; fi
grep -q "does not have the hash CI recorded" "$T/out" || fail "wrong reason: $(cat "$T/out")"
[ ! -e "$G/uploaded/manifest.json" ] && [ ! -e "$G/patched" ] || fail "something went out although the check failed"

# ---- 4. CI built another commit than the one tagged here ----
ci_draft one; mac_built; apk_built; jq '.commit = "0000"' "$G/assets/build.json" > "$T/b" && mv "$T/b" "$G/assets/build.json"
if $R $V > "$T/out" 2>&1; then fail "accepted a build of another commit"; fi

# ---- 4b. CI built with another Go than go.mod's toolchain line, or did not say ----
for go in go1.26.0 ""; do
  ci_draft one; mac_built; apk_built; jq --arg go "$go" 'if $go == "" then del(.go) else .go = $go end' "$G/assets/build.json" > "$T/b" && mv "$T/b" "$G/assets/build.json"
  if $R $V > "$T/out" 2>&1; then fail "accepted a build made with Go '${go:-unrecorded}'"; fi
  grep -q "go.mod pins $GO_WANT" "$T/out" && [ ! -e "$G/patched" ] || fail "Go '${go:-unrecorded}': $(cat "$T/out")"
done

# ---- 5. refusals before anything happens ----
if $R v0.1.5 > "$T/out" 2>&1; then fail "went back to v0.1.5"; fi
grep -q "not newer" "$T/out" || fail "v0.1.5: $(cat "$T/out")"
# v0.1.11 is out, and update.sh still lets a fresh install start at v0.1.10
echo v0.1.11 >> "$G/published"
if NO_MAC=1 $R v0.1.12 > "$T/out" 2>&1; then fail "released while KIT_FLOOR is behind the last release"; fi
grep -q "KIT_FLOOR in deploy/prod/update.sh is v0.1.10, older than the last release v0.1.11" "$T/out" && ! git rev-parse -q --verify refs/tags/v0.1.12 >/dev/null || fail "KIT_FLOOR: $(cat "$T/out")"
grep -vx v0.1.11 "$G/published" > "$T/p" && mv "$T/p" "$G/published"   # back to the draft the cases below work on
echo x > stray; git add stray
if $R > "$T/out" 2>&1; then fail "released with uncommitted changes"; fi
git reset -q; rm stray
ssh-keygen -q -t ed25519 -N '' -f "$T/other"
if RELEASE_KEY=$T/other $R > "$T/out" 2>&1; then fail "signed with a key no build knows"; fi
grep -q "is not in internal/update/release_keys" "$T/out" || fail "unknown key: $(cat "$T/out")"
if GITEA_TOKEN= GITEA_TOKEN_FILE=$T/none $R > "$T/out" 2>&1; then fail "ran without a token"; fi
if FAKE_PUSH=false $R > "$T/out" 2>&1; then fail "went on with a token that may not write"; fi
if GITHUB_TOKEN= GITHUB_TOKEN_FILE=$T/none $R > "$T/out" 2>&1; then fail "ran without a GitHub token"; fi
grep -q "NO_GITHUB=1" "$T/out" || fail "no GitHub token: $(cat "$T/out")"
if FAKE_GH_PUSH=false $R > "$T/out" 2>&1; then fail "went on with a GitHub token that may not write"; fi
grep -q "does not get write access" "$T/out" || fail "read-only token: $(cat "$T/out")"
[ -z "$(git tag -l v0.1.12)" ] || fail "a refused run left a tag behind"
# the token goes to the configured host only
ci_draft one; mac_built; apk_built
jq '.[0].assets[0].browser_download_url = "http://elsewhere.test/dl/x"' "$G/releases.json" > "$T/r" && mv "$T/r" "$G/releases.json"
if $R $V > "$T/out" 2>&1; then fail "followed a download URL on another host"; fi
! grep -q elsewhere "$G/calls" || fail "the token was sent to another host"

# NO_GITHUB: no token needed, nothing sent there
ci_draft one; mac_built; apk_built
GITHUB_TOKEN= GITHUB_TOKEN_FILE=$T/none NO_GITHUB=1 $R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "NO_GITHUB release failed"; }
! grep -q github "$G/calls" || fail "NO_GITHUB still talked to GitHub"

# ---- 6. the Android app ----
# a certificate that is not the pinned one: Android would refuse the update, so
# the release stops and nothing goes out
ci_draft one; mac_built; apk_built
if FAKE_CERT=$CERT_B $R $V > "$T/out" 2>&1; then fail "released an APK signed by an unpinned certificate"; fi
grep -q "pins $CERT_A" "$T/out" || fail "wrong reason: $(cat "$T/out")"
[ ! -e "$G/uploaded/manifest.json" ] && [ ! -e "$G/patched" ] || fail "something went out although the certificate was wrong"
[ ! -e "dist/release/$V/BoundGate-0.1.11.apk" ] || fail "the wrongly signed APK was left behind"

# no APK built yet: release.sh builds one (in images; docker is stood in for here)
ci_draft one; mac_built; rm -f dist/.release-apk "dist/BoundGate-$V-unsigned.apk"
$R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "release with an Android build failed"; }
grep -q "building the Android app" "$T/out" || fail "did not build the APK: $(cat "$T/out")"
grep -q "apk $V release" "dist/BoundGate-$V-unsigned.apk" || fail "the build was not asked for a release APK"
jq -e '[.assets[] | select(.kind == "apk")] | length == 1' "$G/uploaded/manifest.json" >/dev/null || fail "the built APK is not in the manifest"

# NO_APK: a release without it, and nothing Android in the manifest
ci_draft one; mac_built; apk_built
NO_APK=1 $R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "NO_APK release failed"; }
grep -q "NO_APK: this release gets no Android app" "$T/out" || fail "NO_APK: $(cat "$T/out")"
jq -e '(.assets | length) == 5 and ([.assets[] | select(.kind == "apk")] | length) == 0' "$G/uploaded/manifest.json" >/dev/null || fail "NO_APK still named an APK"

# manifest.sh refuses an unsigned APK outright: whatever puts one in the
# directory, it does not get a name in a signed manifest
mkdir -p "$T/m"; echo apk > "$T/m/BoundGate-0.1.11-unsigned.apk"
if sh deploy/release/manifest.sh $V "$T/m" > "$T/out" 2>&1; then fail "the manifest named an unsigned APK"; fi
grep -q "is unsigned" "$T/out" || fail "wrong reason: $(cat "$T/out")"
mv "$T/m/BoundGate-0.1.11-unsigned.apk" "$T/m/BoundGate-0.1.11.apk"
sh deploy/release/manifest.sh $V "$T/m" | jq -e '.assets[0] | .kind == "apk" and .os == "android" and .arch == "universal"' >/dev/null \
  || fail "manifest.sh does not know the signed APK"

# the signing key is checked before the tag is pushed
rm -f dist/.release-apk "dist/BoundGate-v0.1.12-unsigned.apk"
if NO_MAC=1 APK_KS=$T/none.jks $R v0.1.12 > "$T/out" 2>&1; then fail "went on without a keystore"; fi
grep -q "cannot read the keystore" "$T/out" || fail "wrong reason: $(cat "$T/out")"
[ -z "$(git tag -l v0.1.12)" ] || fail "a run refused over the APK key left a tag behind"

# ---- 7. the highest tag was never published: a run without a version takes it up again, at HEAD ----
# v0.1.11 is out; an attempt at v0.1.12 tagged a commit whose CI run failed, and the fix came after it
echo v0.1.11 >> "$G/published"
printf '#!/bin/sh\nKIT_FLOOR=v0.1.11\n' > deploy/prod/update.sh; git commit -qam "floor v0.1.11"
git tag -a v0.1.12 -m "BoundGate v0.1.12"; git push -q origin main refs/tags/v0.1.12
OLD=$(git rev-parse HEAD)
echo fix > fix; git add fix; git commit -qm fix; git push -q origin main
V=v0.1.12; HEAD=$(git rev-parse HEAD)
ci_draft one; apk_built
NO_MAC=1 $R > "$T/out" 2>&1 || { cat "$T/out"; fail "resuming the unpublished tag failed"; }
grep -q "v0.1.12 is tagged but nothing of it is published: resuming it" "$T/out" || fail "did not take up v0.1.12: $(cat "$T/out")"
grep -q "moving the tag" "$T/out" && grep -q "released v0.1.12" "$T/out" || fail "v0.1.12: $(cat "$T/out")"
[ "$(git rev-parse 'v0.1.12^{commit}')" = "$HEAD" ] && [ "$(git ls-remote origin 'refs/tags/v0.1.12^{}' | cut -f1)" = "$HEAD" ] || fail "the tag did not move to HEAD (was $OLD)"
[ -z "$(git tag -l v0.1.13)" ] || fail "counted past the unpublished tag"

echo "release.sh test: ok"
