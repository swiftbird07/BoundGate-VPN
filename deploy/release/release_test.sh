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
cp "$SRC/deploy/release/release.sh" "$SRC/deploy/release/manifest.sh" "$SRC/deploy/release/mirror-github.sh" deploy/release/
ssh-keygen -q -t ed25519 -N '' -C test-release-key -f private/release_signing_key
{ echo "# test keys"; cat private/release_signing_key.pub; } > internal/update/release_keys
cp internal/update/release_keys deploy/prod/release_keys
printf 'private/\ndist/\n' > .gitignore
GO_WANT=$(sed -n 's/^toolchain //p' "$SRC/go.mod"); [ -n "$GO_WANT" ] || fail "go.mod has no toolchain line"
printf 'module example.test/r\n\ngo 1.26.0\n\ntoolchain %s\n' "$GO_WANT" > go.mod
git add -A; git commit -qm init
git remote add origin "$T/origin.git"; git push -q -u origin main

R="sh deploy/release/release.sh"
# ---- version numbers ----
[ "$($R --next)" = v0.1.0 ] || fail "first version: $($R --next)"
for t in v0.1.0 v0.1.9 v0.1.10 v0.2.0-rc1 nightly; do git tag "$t"; done
[ "$($R --next)" = v0.1.11 ] || fail "next patch after v0.1.10 (numeric, not alphabetic; other tags ignored): $($R --next)"
[ "$(BUMP=minor $R --next)" = v0.2.0 ] || fail "minor: $(BUMP=minor $R --next)"
[ "$(BUMP=major $R --next)" = v1.0.0 ] || fail "major"
git push -q origin --tags

# ---- the stand-in for Gitea, and for GitHub (three hosts: website, API, uploads) ----
G=$T/gitea; mkdir -p "$G/assets" "$G/uploaded" "$T/bin"
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
  "GET "*"/releases/tags/"*) [ -f "$FAKE/patched" ] || exit 22; echo '{"draft":false}' ;;
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

# ---- 1. the whole way, version chosen by the script ----
ci_draft one; mac_built
$R > "$T/out" 2>&1 || { cat "$T/out"; fail "release failed"; }
grep -q "released $V" "$T/out" || fail "did not pick $V: $(cat "$T/out")"
[ "$(git ls-remote --tags origin refs/tags/$V | wc -l | tr -d ' ')" = 1 ] || fail "tag not pushed"
for f in manifest.json manifest.json.sig BoundGate-0.1.11-macos.zip BoundGate-0.1.11.dmg; do [ -f "$G/uploaded/$f" ] || fail "$f not uploaded"; done
[ ! -e "$G/uploaded/boundgate-$V-linux-amd64.tar.gz" ] && [ ! -e "$G/uploaded/boundgate-$V-windows-amd64.zip" ] || fail "CI's files were uploaded a second time"
M=$G/uploaded/manifest.json
sed 's/^/boundgate-release /' private/release_signing_key.pub > "$T/allowed"
ssh-keygen -Y verify -f "$T/allowed" -I boundgate-release -n boundgate-release -s "$M.sig" < "$M" >/dev/null 2>&1 || fail "uploaded manifest does not verify"
jq -e --arg v $V --arg c "$HEAD" '.type == "boundgate-release" and .version == $v and .commit == $c and .image.digest == "sha256:'"$(printf %064d 7)"'" and (.assets | length) == 5 and ([.assets[] | select(.os == "windows" and .kind == "binaries")] | length) == 1' "$M" >/dev/null || fail "manifest: $(cat "$M")"
for n in $(jq -r '.assets[].name' "$M"); do
  f=$G/assets/$n; [ -f "$f" ] || f=dist/$n
  [ "$(jq -r --arg n "$n" '.assets[] | select(.name == $n) | .sha256' "$M")" = "$(sha "$f")" ] || fail "hash of $n"
done
jq -e '.draft == false' "$G/patched" >/dev/null || fail "draft not published"
grep -qx 3 "$G/deleted" || fail "CI's build.json was not removed from the published release"
# order: nothing is published before the signature is up
[ "$(grep -n 'PATCH http://gitea.test' "$G/calls" | cut -d: -f1)" -gt "$(grep -n 'gitea.test.*name=manifest.json.sig' "$G/calls" | cut -d: -f1)" ] || fail "published before the signature was uploaded"
# the mirror: the same seven files, the manifest and signature byte for byte, published last, as the latest release
[ "$(ls "$G/gh-uploaded" | wc -l | tr -d ' ')" = 7 ] || fail "GitHub got: $(ls "$G/gh-uploaded")"
for f in manifest.json manifest.json.sig; do cmp -s "$G/uploaded/$f" "$G/gh-uploaded/$f" || fail "GitHub's $f differs from Gitea's"; done
for n in $(jq -r '.assets[].name' "$M"); do [ "$(jq -r --arg n "$n" '.assets[] | select(.name == $n) | .sha256' "$M")" = "$(sha "$G/gh-uploaded/$n")" ] || fail "GitHub's $n is not the file the manifest names"; done
jq -e --arg v $V '.tag_name == $v and .draft == true' "$G/gh-created" >/dev/null && jq -e '.draft == false and .make_latest == "true"' "$G/gh-patched" >/dev/null || fail "GitHub release: $(cat "$G/gh-created" "$G/gh-patched")"
[ "$(grep -n 'PATCH http://api.github.test' "$G/calls" | cut -d: -f1)" -gt "$(grep -n 'uploads.github.test.*name=manifest.json.sig' "$G/calls" | cut -d: -f1)" ] || fail "GitHub: published before the signature was uploaded"
grep -q "mirrored $V" "$T/out" || fail "no mirror: $(cat "$T/out")"

# ---- 2. resume: same version again, tag exists; leftovers of the first attempt are replaced ----
ci_draft one; mac_built
jq '.[0].assets += [{id:9, name:"manifest.json", browser_download_url:"http://gitea.test/dl/manifest.json"}]' "$G/releases.json" > "$T/r" && mv "$T/r" "$G/releases.json"
$R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "resume failed"; }
grep -q "resuming" "$T/out" && grep -qx 9 "$G/deleted" || fail "resume did not replace the old manifest"

# ---- 2b. the mirror alone: a tag on GitHub that is not ours gets no release; a second run has only the mirror left ----
ci_draft one; mac_built
if FAKE_GH_TAG=0000 $R $V > "$T/out" 2>&1; then fail "attached a release to a foreign tag"; fi
grep -q "somebody else made" "$T/out" && [ -e "$G/patched" ] && [ ! -e "$G/gh-created" ] || fail "foreign tag: $(cat "$T/out")"
: > "$G/calls"
$R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "mirror-only run failed"; }
grep -q "is published on http://gitea.test already" "$T/out" && grep -q "mirrored $V" "$T/out" || fail "mirror-only run: $(cat "$T/out")"
! grep -q 'POST http://gitea.test\|PATCH http://gitea.test' "$G/calls" || fail "the mirror-only run changed the published release"
[ "$(ls "$G/gh-uploaded" | wc -l | tr -d ' ')" = 7 ] || fail "mirror-only run uploaded: $(ls "$G/gh-uploaded")"
# and once it is there, nothing is uploaded again
rm -rf "$G/gh-uploaded"; mkdir "$G/gh-uploaded"; jq -n --arg v $V '[{id:70, tag_name:$v, draft:false}]' > "$G/gh-releases.json"
sh deploy/release/mirror-github.sh $V > "$T/out" 2>&1 && grep -q "on GitHub already" "$T/out" && [ -z "$(ls "$G/gh-uploaded")" ] || fail "mirrored twice: $(cat "$T/out")"
# a file changed after signing does not go out
echo x >> dist/release/$V/boundgate-$V-linux-amd64.tar.gz; echo '[]' > "$G/gh-releases.json"
if sh deploy/release/mirror-github.sh $V > "$T/out" 2>&1; then fail "mirrored a file the manifest does not name"; fi
[ -z "$(ls "$G/gh-uploaded")" ] || fail "something went to GitHub although the check failed"

# ---- 3. a file that is not what CI recorded is not signed ----
ci_draft one; mac_built; echo tampered > "$G/assets/boundgate-$V-linux-arm64.tar.gz"
if $R $V > "$T/out" 2>&1; then fail "signed a file that differs from CI's record"; fi
grep -q "does not have the hash CI recorded" "$T/out" || fail "wrong reason: $(cat "$T/out")"
[ ! -e "$G/uploaded/manifest.json" ] && [ ! -e "$G/patched" ] || fail "something went out although the check failed"

# ---- 4. CI built another commit than the one tagged here ----
ci_draft one; mac_built; jq '.commit = "0000"' "$G/assets/build.json" > "$T/b" && mv "$T/b" "$G/assets/build.json"
if $R $V > "$T/out" 2>&1; then fail "accepted a build of another commit"; fi

# ---- 4b. CI built with another Go than go.mod's toolchain line, or did not say ----
for go in go1.26.0 ""; do
  ci_draft one; mac_built; jq --arg go "$go" 'if $go == "" then del(.go) else .go = $go end' "$G/assets/build.json" > "$T/b" && mv "$T/b" "$G/assets/build.json"
  if $R $V > "$T/out" 2>&1; then fail "accepted a build made with Go '${go:-unrecorded}'"; fi
  grep -q "go.mod pins $GO_WANT" "$T/out" && [ ! -e "$G/patched" ] || fail "Go '${go:-unrecorded}': $(cat "$T/out")"
done

# ---- 5. refusals before anything happens ----
if $R v0.1.5 > "$T/out" 2>&1; then fail "went back to v0.1.5"; fi
grep -q "not newer" "$T/out" || fail "v0.1.5: $(cat "$T/out")"
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
ci_draft one; mac_built
jq '.[0].assets[0].browser_download_url = "http://elsewhere.test/dl/x"' "$G/releases.json" > "$T/r" && mv "$T/r" "$G/releases.json"
if $R $V > "$T/out" 2>&1; then fail "followed a download URL on another host"; fi
! grep -q elsewhere "$G/calls" || fail "the token was sent to another host"

# NO_GITHUB: no token needed, nothing sent there
ci_draft one; mac_built
GITHUB_TOKEN= GITHUB_TOKEN_FILE=$T/none NO_GITHUB=1 $R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "NO_GITHUB release failed"; }
! grep -q github "$G/calls" || fail "NO_GITHUB still talked to GitHub"

echo "release.sh test: ok"
