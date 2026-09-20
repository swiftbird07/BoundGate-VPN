#!/bin/sh
# Builds dist/BoundGate.app: the Swift menu-bar app, the Go daemon and CLI,
# the LaunchDaemon definition, signed.
#
#   apps/macos/build-app.sh                 # sign with the best identity in the keychain
#   SIGN_IDENTITY="Developer ID Application: …" apps/macos/build-app.sh
#   SIGN_IDENTITY=- apps/macos/build-app.sh # ad hoc: runs, but macOS refuses to register the service
#
#   RELEASE=v1.2.3 UNIVERSAL=1 apps/macos/build-app.sh   # what `make release` runs
#
# Go is built in the box (make build-darwin); Swift and codesign run on the Mac.
#   RELEASE=vX.Y.Z  release build: that version in the binaries (they update
#                   themselves only then) and in Info.plist
#   UNIVERSAL=1     arm64 + x86_64 in one bundle (lipo; needs both Go builds)
#   SKIP_GO=1       take bin/darwin_* as they are (built elsewhere, so that
#                   this Mac needs neither Go nor the box)
set -eu
cd "$(dirname "$0")/../.."
REPO=$PWD
RELEASE=${RELEASE:-}
VERSION=${VERSION:-${RELEASE#v}}
VERSION=${VERSION:-0.8.0}
UNIVERSAL=${UNIVERSAL:-}
BUILD=${BUILD:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}
BUNDLE_ID=${BUNDLE_ID:-de.swiftbird.boundgate}
ARCH=$(uname -m | sed 's/x86_64/amd64/')
APP=dist/BoundGate.app

ARCHS=$ARCH; SWIFT_ARCH=""
if [ -n "$UNIVERSAL" ]; then ARCHS="arm64 amd64"; SWIFT_ARCH="--arch arm64 --arch x86_64"; fi
if [ -z "${SKIP_GO:-}" ]; then
  echo "== Go binaries (box)"
  for a in $ARCHS; do make build-darwin GOARCH=$a ${RELEASE:+VERSION=$RELEASE} >/dev/null; done
fi
GOBIN=bin/darwin_$ARCH
if [ -n "$UNIVERSAL" ]; then
  GOBIN=bin/darwin_universal; mkdir -p $GOBIN
  for b in boundgate-node boundgatectl; do lipo -create -output $GOBIN/$b bin/darwin_arm64/$b bin/darwin_amd64/$b; done
fi
echo "== Swift app (release)"
for p in BoundGate bgtool boundgate-sekey; do
  swift build --package-path apps/macos -c release $SWIFT_ARCH --product $p 2>&1 | tail -1
done
BIN=$(swift build --package-path apps/macos -c release $SWIFT_ARCH --show-bin-path)

echo "== bundle"
rm -rf "$APP" dist/icon
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchDaemons" dist/icon
cp "$BIN/BoundGate" "$APP/Contents/MacOS/BoundGate"
cp "$GOBIN/boundgate-node" "$GOBIN/boundgatectl" "$APP/Contents/MacOS/"
# Secure Enclave bridge of the daemon (key_kind auto / secure-enclave); the
# daemon looks for it next to itself
cp "$BIN/boundgate-sekey" "$APP/Contents/MacOS/boundgate-sekey"
cp apps/macos/Bundle/node.yaml "$APP/Contents/Resources/node.yaml"
for f in Info.plist com.boundgate.node.plist; do
  sed -e "s/@BUNDLE_ID@/$BUNDLE_ID/g" -e "s/@VERSION@/$VERSION/g" -e "s/@BUILD@/$BUILD/g" "apps/macos/Bundle/$f" > "dist/$f"
done
mv dist/Info.plist "$APP/Contents/Info.plist"
# the file name equals the Label: BTM identifies the service by it
mv dist/com.boundgate.node.plist "$APP/Contents/Library/LaunchDaemons/$BUNDLE_ID.node.plist"
"$BIN/bgtool" icon dist/icon
iconutil -c icns -o "$APP/Contents/Resources/AppIcon.icns" dist/icon/BoundGate.iconset
rm -rf dist/icon

echo "== sign"
if [ -z "${SIGN_IDENTITY:-}" ]; then
  ids=$(security find-identity -v -p codesigning)
  SIGN_IDENTITY=$(printf '%s\n' "$ids" | sed -n 's/.*"\(Developer ID Application: [^"]*\)".*/\1/p' | head -1)
  [ -n "$SIGN_IDENTITY" ] || SIGN_IDENTITY=$(printf '%s\n' "$ids" | sed -n 's/.*"\(Apple Development: [^"]*\)".*/\1/p' | head -1)
  [ -n "$SIGN_IDENTITY" ] || SIGN_IDENTITY=-
fi
case "$SIGN_IDENTITY" in
  "Developer ID"*) TS=--timestamp ;;   # needed for notarization
  *) TS=--timestamp=none ;;
esac
echo "   identity: $SIGN_IDENTITY"
# inside out: helpers first, the bundle last; hardened runtime everywhere
for b in boundgate-node boundgatectl boundgate-sekey; do
  codesign --force --options runtime $TS --identifier "$BUNDLE_ID.${b#boundgate-}" --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/$b"
done
codesign --force --options runtime $TS --sign "$SIGN_IDENTITY" "$APP"
codesign --verify --deep --strict "$APP" && echo "   signature verifies"
[ "$SIGN_IDENTITY" != - ] || echo "   WARNING: ad hoc signature; SMAppService will not register the background service"

echo "== done: $REPO/$APP"
echo "   install: copy it to /Applications, open it, press \"Install service\""
case "$SIGN_IDENTITY" in "Developer ID"*) echo "   distribute: apps/macos/notarize.sh (docs/MACOS-APP.md)";; esac
