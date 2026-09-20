#!/bin/sh
# deploy/release/tag-latest.sh against a real registry (registry:2 in a
# container, no login). Needs docker, curl, jq, ssh-keygen, openssl.
set -eu
cd "$(dirname "$0")/../.."
T=$HOME/.cache/boundgate-tag-latest-test; rm -rf "$T"; mkdir -p "$T/rel"
PORT=18474; NAME=boundgate-tag-latest-test; REPO=localhost:$PORT/t/boundgate
cleanup() { docker rm -f $NAME >/dev/null 2>&1 || true; rm -rf "$T"; }
trap cleanup EXIT INT TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
docker rm -f $NAME >/dev/null 2>&1 || true
docker run -d --name $NAME -p 127.0.0.1:$PORT:5000 registry:2 >/dev/null
for i in $(seq 1 40); do curl -fs -o /dev/null http://localhost:$PORT/v2/ && break; sleep 0.25; done
digest_of() { curl -fsS -I -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' "http://localhost:$PORT/v2/t/boundgate/manifests/$1" | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: *//p'; }
push() { docker pull -q "$1" >/dev/null; docker tag "$1" $REPO:$2; docker push -q $REPO:$2 >/dev/null; digest_of $2; }
release() { # release VERSION DIGEST KEY -> $T/rel/manifest.json(.sig)
  rm -f "$T"/rel/*; echo bin > "$T/rel/boundgate-$1-linux-amd64.tar.gz"; deploy/release/manifest.sh "$1" "$T/rel" $REPO "$2" > "$T/manifest.json"; mv "$T/manifest.json" "$T/rel/"
  ssh-keygen -q -Y sign -n boundgate-release -f "$3" "$T/rel/manifest.json"
}
ssh-keygen -q -t ed25519 -N '' -f "$T/key"; ssh-keygen -q -t ed25519 -N '' -f "$T/stranger"
export RELEASE_KEYS=$T/key.pub
run() { deploy/release/tag-latest.sh "$T/rel/manifest.json" "$T/rel/manifest.json.sig" "$@"; }

D1=$(push busybox:stable v1.0.0); D2=$(push busybox:musl v1.0.1)
[ -n "$D1" ] && [ -n "$D2" ] && [ "$D1" != "$D2" ] || fail "test images: $D1 $D2"

echo "== 1. latest follows the signed release"
release v1.0.0 "$D1" "$T/key"; run | grep -q "$REPO:latest -> v1.0.0 ($D1)" || fail "v1.0.0"
[ "$(digest_of latest)" = "$D1" ] || fail "latest is $(digest_of latest)"
release v1.0.1 "$D2" "$T/key"; run >/dev/null; [ "$(digest_of latest)" = "$D2" ] || fail "latest did not move to v1.0.1"
docker pull -q $REPO:latest >/dev/null || fail "docker cannot pull what was tagged"

echo "== 2. refused: a stranger's signature, a digest the registry does not hold, a manifest changed after signing"
release v1.0.2 "$D1" "$T/stranger"; if run >/dev/null 2>&1; then fail "moved latest for a stranger"; fi
release v1.0.2 "sha256:$(printf x | openssl dgst -sha256 -r | cut -d' ' -f1)" "$T/key"; if run >/dev/null 2>&1; then fail "tagged a digest that is not there"; fi
release v1.0.2 "$D1" "$T/key"; sed -i.bak "s/$D1/$D2/" "$T/rel/manifest.json"; if run >/dev/null 2>&1; then fail "accepted a changed manifest"; fi
[ "$(digest_of latest)" = "$D2" ] || fail "a refused run moved latest"

echo "== 3. another tag, another repository argument"
release v1.0.0 "$D1" "$T/key"; TAG=stable run $REPO | grep -q ":stable -> v1.0.0" || fail "TAG=stable"
[ "$(digest_of stable)" = "$D1" ] && [ "$(digest_of latest)" = "$D2" ] || fail "stable/latest"
echo "PASS: tag-latest.sh"
