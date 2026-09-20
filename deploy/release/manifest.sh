#!/bin/sh
# Writes the manifest of a release: every file in DIR with size and SHA-256,
# and the container image by digest. The manifest is what gets signed
# (namespace boundgate-release); clients install nothing it does not name
# (internal/update, deploy/prod/update.sh).
#
#   deploy/release/manifest.sh v1.2.3 dist/release [IMAGE_REF sha256:DIGEST] > dist/release/manifest.json
#
# File names decide what an asset is:
#   boundgate-<version>-linux-<arch>.tar.gz   kind binaries
#   BoundGate-<version>-macos.zip             kind app (what the Mac updater installs)
#   BoundGate-<version>.dmg                   kind dmg (for people)
# Needs jq and sha256sum or openssl.
set -eu
VERSION=${1:?usage: manifest.sh vX.Y.Z DIR [IMAGE_REF IMAGE_DIGEST]}
DIR=${2:?usage: manifest.sh vX.Y.Z DIR [IMAGE_REF IMAGE_DIGEST]}
IMAGE_REF=${3:-}; IMAGE_DIGEST=${4:-}
echo "$VERSION" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || { echo "manifest: version must be vMAJOR.MINOR.PATCH, got $VERSION" >&2; exit 2; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else openssl dgst -sha256 -r "$1" | cut -d' ' -f1; fi; }
size() { wc -c < "$1" | tr -d ' '; }

assets='[]'
for f in "$DIR"/*; do
  n=$(basename "$f")
  case "$n" in
    manifest.json|manifest.json.sig) continue ;;
    boundgate-*-linux-amd64.tar.gz) kind=binaries; os=linux; arch=amd64 ;;
    boundgate-*-linux-arm64.tar.gz) kind=binaries; os=linux; arch=arm64 ;;
    BoundGate-*-macos.zip)          kind=app;      os=darwin; arch=universal ;;
    BoundGate-*.dmg)                kind=dmg;      os=darwin; arch=universal ;;
    *) echo "manifest: do not know what $n is" >&2; exit 2 ;;
  esac
  assets=$(printf '%s' "$assets" | jq -c --arg n "$n" --arg k "$kind" --arg os "$os" --arg a "$arch" --argjson s "$(size "$f")" --arg h "$(sha "$f")" \
    '. + [{name:$n, kind:$k, os:$os, arch:$a, size:$s, sha256:$h}]')
done
[ "$assets" != "[]" ] || { echo "manifest: no assets in $DIR" >&2; exit 2; }
if [ -n "$IMAGE_REF" ]; then
  echo "$IMAGE_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$' || { echo "manifest: image digest must be sha256:<64 hex>" >&2; exit 2; }
  image=$(jq -cn --arg r "$IMAGE_REF" --arg d "$IMAGE_DIGEST" '{ref:$r, digest:$d}')
else
  image=null
fi
jq -n --arg v "$VERSION" --arg c "${COMMIT:-}" --arg t "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson image "$image" --argjson assets "$assets" \
  '{type:"boundgate-release", version:$v} + (if $c != "" then {commit:$c} else {} end) + {created:$t} + (if $image != null then {image:$image} else {} end) + {assets:$assets}'
