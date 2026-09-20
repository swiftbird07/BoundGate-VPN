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
cp "$SRC/deploy/release/release.sh" "$SRC/deploy/release/manifest.sh" deploy/release/
ssh-keygen -q -t ed25519 -N '' -C test-release-key -f private/release_signing_key
{ echo "# test keys"; cat private/release_signing_key.pub; } > internal/update/release_keys
cp internal/update/release_keys deploy/prod/release_keys
printf 'private/\ndist/\n' > .gitignore
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

# ---- the stand-in for Gitea ----
G=$T/gitea; mkdir -p "$G/assets" "$G/uploaded" "$T/bin"
cat > "$T/bin/curl" <<'EOF'
#!/bin/sh
# understands what release.sh sends: -K file, -X METHOD, -o FILE, -F attachment=@FILE, -d @-, URL last
method=GET; out=; attach=; auth=
while [ $# -gt 1 ]; do
  case "$1" in
    -X) method=$2; shift ;; -o) out=$2; shift ;; -K) auth=$2; shift ;; -H) shift ;;
    -F) attach=${2#attachment=@}; shift ;; -d) cat > "$FAKE/body"; shift ;;
  esac
  shift
done
url=$1
grep -q 'Authorization: token test-token' "$auth" 2>/dev/null || { echo "curl: 401" >&2; exit 22; }
echo "$method $url" >> "$FAKE/calls"
case "$method $url" in
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

V=v0.1.11; HEAD=$(git rev-parse HEAD)
# what CI leaves in the draft: two tarballs and its build record
ci_draft() {
  rm -rf "$G/assets" "$G/uploaded" "$G/calls" "$G/deleted" "$G/patched"; mkdir -p "$G/assets" "$G/uploaded"
  for a in amd64 arm64; do echo "linux $a $1" > "$G/assets/boundgate-$V-linux-$a.tar.gz"; done
  COMMIT=$HEAD sh deploy/release/manifest.sh $V "$G/assets" registry.test/boundgate sha256:$(printf %064d 7) | jq '.type = "boundgate-build"' > "$T/build.json"
  cp "$T/build.json" "$G/assets/build.json"
  jq -n --arg v $V '{id:7, tag_name:$v, draft:true, assets:[
    {id:1, name:"boundgate-\($v)-linux-amd64.tar.gz", browser_download_url:"http://gitea.test/dl/boundgate-\($v)-linux-amd64.tar.gz"},
    {id:2, name:"boundgate-\($v)-linux-arm64.tar.gz", browser_download_url:"http://gitea.test/dl/boundgate-\($v)-linux-arm64.tar.gz"},
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
[ ! -e "$G/uploaded/boundgate-$V-linux-amd64.tar.gz" ] || fail "CI's files were uploaded a second time"
M=$G/uploaded/manifest.json
sed 's/^/boundgate-release /' private/release_signing_key.pub > "$T/allowed"
ssh-keygen -Y verify -f "$T/allowed" -I boundgate-release -n boundgate-release -s "$M.sig" < "$M" >/dev/null 2>&1 || fail "uploaded manifest does not verify"
jq -e --arg v $V --arg c "$HEAD" '.type == "boundgate-release" and .version == $v and .commit == $c and .image.digest == "sha256:'"$(printf %064d 7)"'" and (.assets | length) == 4' "$M" >/dev/null || fail "manifest: $(cat "$M")"
for n in $(jq -r '.assets[].name' "$M"); do
  f=$G/assets/$n; [ -f "$f" ] || f=dist/$n
  [ "$(jq -r --arg n "$n" '.assets[] | select(.name == $n) | .sha256' "$M")" = "$(sha "$f")" ] || fail "hash of $n"
done
jq -e '.draft == false' "$G/patched" >/dev/null || fail "draft not published"
grep -qx 3 "$G/deleted" || fail "CI's build.json was not removed from the published release"
# order: nothing is published before the signature is up
[ "$(grep -n 'PATCH' "$G/calls" | cut -d: -f1)" -gt "$(grep -n 'name=manifest.json.sig' "$G/calls" | cut -d: -f1)" ] || fail "published before the signature was uploaded"

# ---- 2. resume: same version again, tag exists; leftovers of the first attempt are replaced ----
ci_draft one; mac_built
jq '.[0].assets += [{id:9, name:"manifest.json", browser_download_url:"http://gitea.test/dl/manifest.json"}]' "$G/releases.json" > "$T/r" && mv "$T/r" "$G/releases.json"
$R $V > "$T/out" 2>&1 || { cat "$T/out"; fail "resume failed"; }
grep -q "resuming" "$T/out" && grep -qx 9 "$G/deleted" || fail "resume did not replace the old manifest"

# ---- 3. a file that is not what CI recorded is not signed ----
ci_draft one; mac_built; echo tampered > "$G/assets/boundgate-$V-linux-arm64.tar.gz"
if $R $V > "$T/out" 2>&1; then fail "signed a file that differs from CI's record"; fi
grep -q "does not have the hash CI recorded" "$T/out" || fail "wrong reason: $(cat "$T/out")"
[ ! -e "$G/uploaded/manifest.json" ] && [ ! -e "$G/patched" ] || fail "something went out although the check failed"

# ---- 4. CI built another commit than the one tagged here ----
ci_draft one; mac_built; jq '.commit = "0000"' "$G/assets/build.json" > "$T/b" && mv "$T/b" "$G/assets/build.json"
if $R $V > "$T/out" 2>&1; then fail "accepted a build of another commit"; fi

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
[ -z "$(git tag -l v0.1.12)" ] || fail "a refused run left a tag behind"
# the token goes to the configured host only
ci_draft one; mac_built
jq '.[0].assets[0].browser_download_url = "http://elsewhere.test/dl/x"' "$G/releases.json" > "$T/r" && mv "$T/r" "$G/releases.json"
if $R $V > "$T/out" 2>&1; then fail "followed a download URL on another host"; fi
! grep -q elsewhere "$G/calls" || fail "the token was sent to another host"

echo "release.sh test: ok"
