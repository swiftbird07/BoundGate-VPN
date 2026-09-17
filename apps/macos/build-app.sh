#!/bin/sh
# Builds dist/BoundGate.app: the Swift menu-bar app, the Go daemon and CLI,
# the LaunchDaemon definition, signed.
#
#   apps/macos/build-app.sh                 # sign with the best identity in the keychain
#   SIGN_IDENTITY="Developer ID Application: …" apps/macos/build-app.sh
#   SIGN_IDENTITY=- apps/macos/build-app.sh # ad hoc: runs, but macOS refuses to register the service
#
# Go is built in the box (make build-darwin); Swift and codesign run on the Mac.
set -eu
cd "$(dirname "$0")/../.."
REPO=$PWD
VERSION=${VERSION:-0.8.0}
BUILD=${BUILD:-$(git rev-list --count HEAD 2>/dev/null || echo 1)}
BUNDLE_ID=${BUNDLE_ID:-com.net407.boundgate}
ARCH=$(uname -m | sed 's/x86_64/amd64/')
APP=dist/BoundGate.app

echo "== Go binaries (box)"
make build-darwin >/dev/null
echo "== Swift app (release)"
swift build --package-path apps/macos -c release --product BoundGate 2>&1 | tail -1
swift build --package-path apps/macos -c release --product bgtool 2>&1 | tail -1
BIN=$(swift build --package-path apps/macos -c release --show-bin-path)

echo "== bundle"
rm -rf "$APP" dist/icon
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchDaemons" dist/icon
cp "$BIN/BoundGate" "$APP/Contents/MacOS/BoundGate"
cp "bin/darwin_$ARCH/boundgate-node" "bin/darwin_$ARCH/boundgatectl" "$APP/Contents/MacOS/"
cp apps/macos/Bundle/node.yaml "$APP/Contents/Resources/node.yaml"
for f in Info.plist com.boundgate.node.plist; do
  sed -e "s/@BUNDLE_ID@/$BUNDLE_ID/g" -e "s/@VERSION@/$VERSION/g" -e "s/@BUILD@/$BUILD/g" "apps/macos/Bundle/$f" > "dist/$f"
done
mv dist/Info.plist "$APP/Contents/Info.plist"
mv dist/com.boundgate.node.plist "$APP/Contents/Library/LaunchDaemons/com.boundgate.node.plist"
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
for b in boundgate-node boundgatectl; do
  codesign --force --options runtime $TS --identifier "$BUNDLE_ID.${b#boundgate-}" --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/$b"
done
codesign --force --options runtime $TS --sign "$SIGN_IDENTITY" "$APP"
codesign --verify --deep --strict "$APP" && echo "   signature verifies"
[ "$SIGN_IDENTITY" != - ] || echo "   WARNING: ad hoc signature; SMAppService will not register the background service"

echo "== done: $REPO/$APP"
echo "   install: copy it to /Applications, open it, press \"Install service\""
case "$SIGN_IDENTITY" in "Developer ID"*) echo "   distribute: apps/macos/notarize.sh (docs/MACOS-APP.md)";; esac
