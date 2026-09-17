#!/bin/sh
# Notarizes dist/BoundGate.app and wraps it in a disk image. Needs an app signed
# with a "Developer ID Application" identity and notarytool credentials in the
# keychain, stored once by you:
#
#   xcrun notarytool store-credentials boundgate-notary --apple-id YOU@example.com --team-id TEAMID
#
# (it asks for an app-specific password from appleid.apple.com). Nothing here
# ever sees that password.
set -eu
cd "$(dirname "$0")/../.."
PROFILE=${NOTARY_PROFILE:-boundgate-notary}
APP=dist/BoundGate.app
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist")
DMG=dist/BoundGate-$VERSION.dmg

codesign -dv "$APP" 2>&1 | grep -q 'Authority=Developer ID Application' || { echo "sign with a Developer ID Application identity first" >&2; exit 1; }
echo "== notarize the app"
ditto -c -k --keepParent "$APP" dist/BoundGate.zip
xcrun notarytool submit dist/BoundGate.zip --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"
rm -f dist/BoundGate.zip

echo "== disk image"
rm -rf dist/dmg "$DMG"; mkdir -p dist/dmg
cp -R "$APP" dist/dmg/; ln -s /Applications dist/dmg/Applications
hdiutil create -volname BoundGate -srcfolder dist/dmg -ov -format UDZO "$DMG" >/dev/null
rm -rf dist/dmg
ID=$(codesign -dv "$APP" 2>&1 | sed -n 's/^Authority=\(Developer ID Application: .*\)$/\1/p' | head -1)
codesign --force --timestamp --sign "$ID" "$DMG"
xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$DMG"
spctl -a -t open --context context:primary-signature -v "$DMG" || true
echo "== done: $DMG"
