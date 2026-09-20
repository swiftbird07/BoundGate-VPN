#!/bin/sh
# Notarizes dist/BoundGate.app and wraps it in a disk image. Needs an app signed
# with a "Developer ID Application" identity and notarytool credentials in the
# keychain, stored once by you:
#
#   xcrun notarytool store-credentials boundgate-notary --key AuthKey_KEYID.p8 --key-id KEYID --issuer ISSUER-UUID
#
# That is an App Store Connect API key (appstoreconnect.apple.com > Users and
# Access > Integrations > Team Keys, access "Developer"): it belongs to the
# team and reaches App Store Connect and the notary service, nothing else.
# `--apple-id YOU --team-id TEAMID` with an app-specific password works too,
# but that password also opens the mail, contacts and calendars of a personal
# Apple account. Nothing here ever sees either secret.
#
# Without a keychain profile (a build machine), the key file does directly:
#   NOTARY_KEY_FILE=AuthKey_XXXX.p8 NOTARY_KEY_ID=XXXX NOTARY_ISSUER=uuid apps/macos/notarize.sh
#
# Results: dist/BoundGate-<version>.dmg for people, and
# dist/BoundGate-<version>-macos.zip, the stapled app, which is what the
# built-in updater downloads (internal/update).
set -eu
cd "$(dirname "$0")/../.."
PROFILE=${NOTARY_PROFILE:-boundgate-notary}
submit() {
  if [ -n "${NOTARY_KEY_FILE:-}" ]; then
    xcrun notarytool submit "$1" --key "$NOTARY_KEY_FILE" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" --wait
  else
    xcrun notarytool submit "$1" --keychain-profile "$PROFILE" --wait
  fi
}
APP=dist/BoundGate.app
VERSION=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$APP/Contents/Info.plist")
DMG=dist/BoundGate-$VERSION.dmg

codesign -dvv "$APP" 2>&1 | grep -q 'Authority=Developer ID Application' || { echo "sign with a Developer ID Application identity first" >&2; exit 1; }
echo "== notarize the app"
ditto -c -k --keepParent "$APP" dist/BoundGate.zip
submit dist/BoundGate.zip
xcrun stapler staple "$APP"
rm -f dist/BoundGate.zip
# for the updater: the app as it is now, with the notarization ticket stapled
ditto -c -k --keepParent "$APP" "dist/BoundGate-$VERSION-macos.zip"

echo "== disk image"
rm -rf dist/dmg "$DMG"; mkdir -p dist/dmg
cp -R "$APP" dist/dmg/; ln -s /Applications dist/dmg/Applications
hdiutil create -volname BoundGate -srcfolder dist/dmg -ov -format UDZO "$DMG" >/dev/null
rm -rf dist/dmg
ID=$(codesign -dvv "$APP" 2>&1 | sed -n 's/^Authority=\(Developer ID Application: .*\)$/\1/p' | head -1)
codesign --force --timestamp --sign "$ID" "$DMG"
submit "$DMG"
xcrun stapler staple "$DMG"
spctl -a -t open --context context:primary-signature -v "$DMG" || true
echo "== done: $DMG and dist/BoundGate-$VERSION-macos.zip"
