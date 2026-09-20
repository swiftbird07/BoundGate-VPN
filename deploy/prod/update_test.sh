#!/bin/sh
# Tests deploy/prod/update.sh against a static stand-in for Gitea (busybox
# httpd in a container) and a stand-in for docker. Needs docker, curl, jq,
# ssh-keygen. The release is built with the real tools: deploy/release/manifest.sh
# and ssh-keygen -Y sign.
#   deploy/prod/update_test.sh
set -eu
cd "$(dirname "$0")/../.."
REPO_DIR=$PWD
T=${TMPDIR_TEST:-$HOME/.cache/boundgate-update-test}; rm -rf "$T"; mkdir -p "$T/www/api/v1/repos/o/r/releases" "$T/www/dl" "$T/kit" "$T/rel"
PORT=18473; NAME=boundgate-update-test
cleanup() { docker rm -f $NAME >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT INT TERM
docker rm -f $NAME >/dev/null 2>&1 || true
docker run -d --name $NAME -p 127.0.0.1:$PORT:80 -v "$T/www":/www:ro busybox:stable httpd -f -h /www >/dev/null
fail() { echo "FAIL: $*" >&2; exit 1; }

ssh-keygen -q -t ed25519 -N '' -C release -f "$T/key"; ssh-keygen -q -t ed25519 -N '' -C stranger -f "$T/stranger"
cp "$T/key.pub" "$T/release_keys"
DIGEST=sha256:$(printf 'image' | openssl dgst -sha256 -r | cut -d' ' -f1)

publish() { # publish VERSION KEYFILE [TAG]
  rm -f "$T"/rel/* "$T"/www/dl/*
  mkdir -p "$T/bin"; printf '#!/bin/sh\necho node %s\n' "$1" > "$T/bin/boundgate-node"; printf 'ctl %s' "$1" > "$T/bin/boundgatectl"
  tar -C "$T/bin" -czf "$T/rel/boundgate-$1-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/').tar.gz" .
  deploy/release/manifest.sh "$1" "$T/rel" registry.test/boundgate "$DIGEST" > "$T/rel/manifest.json"
  ssh-keygen -q -Y sign -n boundgate-release -f "$2" "$T/rel/manifest.json"
  cp "$T"/rel/* "$T/www/dl/"
  assets=$(for f in "$T"/rel/*; do n=$(basename "$f"); printf '{"name":"%s","browser_download_url":"http://127.0.0.1:%s/dl/%s"}\n' "$n" $PORT "$n"; done | jq -cs .)
  jq -n --arg t "${3:-$1}" --argjson a "$assets" '{tag_name:$t, assets:$a}' > "$T/www/api/v1/repos/o/r/releases/latest"
  # the web server sees the directory through the VM's file sharing: wait until it serves this release
  for i in $(seq 1 40); do
    [ "$(curl -fs http://127.0.0.1:$PORT/dl/manifest.json | jq -r .version 2>/dev/null)" = "$1" ] \
      && [ "$(curl -fs http://127.0.0.1:$PORT/api/v1/repos/o/r/releases/latest | jq -r .tag_name 2>/dev/null)" = "${3:-$1}" ] && return 0
    sleep 0.25
  done
  fail "the test web server does not serve $1"
}

# a docker that records what it is asked and reports the state in $T/state
cat > "$T/docker" <<'EOS'
#!/bin/sh
echo "$*" >> "$LOG"
case "$*" in *"compose ps"*) printf '{"Name":"node","State":"%s"}\n' "$(cat "$STATE")" ;; esac
EOS
chmod +x "$T/docker"; printf 'services: {}\n' > "$T/kit/docker-compose.yml"; echo running > "$T/state"
run() { (cd "$T/kit" && LOG="$T/log" STATE="$T/state" DOCKER="$T/docker" SETTLE=0 RELEASE_KEYS="$T/release_keys" \
  BOUNDGATE_UPDATE_URL=http://127.0.0.1:$PORT BOUNDGATE_UPDATE_REPO=o/r "$@" "$REPO_DIR/deploy/prod/update.sh" ${ARGS:-}); }
for i in 1 2 3 4 5 6 7 8 9 10; do curl -fs -o /dev/null http://127.0.0.1:$PORT/ && break; sleep 0.5; done

echo "== 1. a signed release is installed by digest"
publish v1.0.0 "$T/key"; echo 'KEEP=me' > "$T/kit/.env"
run env | grep -q 'updated unknown -> v1.0.0' || fail "no update"
grep -q "^BOUNDGATE_IMAGE=registry.test/boundgate@$DIGEST\$" "$T/kit/.env" && grep -q '^BOUNDGATE_RELEASE=v1.0.0$' "$T/kit/.env" && grep -q '^KEEP=me$' "$T/kit/.env" || fail ".env: $(cat "$T/kit/.env")"
grep -q "^pull -q registry.test/boundgate@$DIGEST\$" "$T/log" && grep -q '^compose up -d' "$T/log" || fail "docker calls: $(cat "$T/log")"

echo "== 2. the same release again: nothing happens; check reports a newer one"
: > "$T/log"; run env | grep -q 'up to date: v1.0.0' || fail "not up to date"
[ ! -s "$T/log" ] || fail "docker was called for nothing"
# (an assignment in front of a function call outlives the call in POSIX sh: set and reset it)
publish v1.0.1 "$T/key"; ARGS=check; run env | grep -q 'update available: v1.0.0 -> v1.0.1' || fail "check"
[ ! -s "$T/log" ] || fail "check changed something"
# -q: an update is still reported (cron mails it), "nothing to do" is silent
ARGS=-q; run env | grep -q 'updated v1.0.0 -> v1.0.1' || fail "quiet apply"; [ -z "$(run env)" ] || fail "-q is not quiet when there is nothing to do"; ARGS=; grep -q '^BOUNDGATE_RELEASE=v1.0.1$' "$T/kit/.env" || fail "v1.0.1 not installed"

echo "== 3. refused: stranger's signature, changed manifest, old manifest under a new tag, downgrade"
before=$(cat "$T/kit/.env"); : > "$T/log"
publish v1.1.0 "$T/stranger"; if run env >/dev/null 2>&1; then fail "a stranger's release was installed"; fi
publish v1.1.0 "$T/key"; sed -i.bak 's/registry.test/evil.test/' "$T/www/dl/manifest.json"
for i in $(seq 1 40); do curl -fs http://127.0.0.1:$PORT/dl/manifest.json | grep -q evil.test && break; sleep 0.25; done
if run env >/dev/null 2>&1; then fail "a changed manifest was installed"; fi
publish v1.0.1 "$T/key" v9.9.9; if run env >/dev/null 2>&1; then fail "an old manifest under a new tag was installed"; fi
publish v0.9.0 "$T/key"; out=$(run env 2>&1) || true; echo "$out" | grep -q 'up to date' || fail "a downgrade was not ignored: $out"
[ "$(cat "$T/kit/.env")" = "$before" ] && [ ! -s "$T/log" ] || fail "a refused release changed something"

echo "== 4. the new release does not stay up: back to the previous image"
publish v1.2.0 "$T/key"; echo exited > "$T/state"
if run env >/dev/null 2>&1; then fail "a broken release was kept"; fi
[ "$(cat "$T/kit/.env")" = "$before" ] || fail "no rollback: $(cat "$T/kit/.env")"
[ "$(grep -c '^compose up -d' "$T/log")" = 2 ] || fail "the previous image was not started again"
echo running > "$T/state"

echo "== 5. MODE=binaries: checked against the manifest, only installed binaries are replaced"
mkdir -p "$T/inst"; echo old > "$T/inst/boundgate-node"
run env MODE=binaries INSTALL_DIR="$T/inst" RESTART_CMD="touch $T/restarted" | grep -q 'updated unknown -> v1.2.0' || fail "binaries"
grep -q 'node v1.2.0' "$T/inst/boundgate-node" && [ ! -e "$T/inst/boundgatectl" ] && [ -e "$T/restarted" ] || fail "binaries install"
publish v1.3.0 "$T/key"; for f in "$T"/www/dl/*.tar.gz; do echo tampered >> "$f"; done; sleep 2
if run env MODE=binaries INSTALL_DIR="$T/inst" RESTART_CMD=true >/dev/null 2>&1; then fail "a tampered tarball was installed"; fi
grep -q 'node v1.2.0' "$T/inst/boundgate-node" || fail "tampered tarball reached the install dir"

echo "PASS: update.sh"
