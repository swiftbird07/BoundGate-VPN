#!/bin/sh
# Signs the Android app for a release (docs/ANDROID.md). CI builds the APK
# unsigned, because it holds no key; the signature is made on the maintainer's
# machine, like the Mac app's.
#
#   deploy/release/sign-apk.sh IN-unsigned.apk OUT.apk
#   deploy/release/sign-apk.sh --check          only: is everything in place?
#
# --check is what `make release` asks before it pushes a tag, so that a
# missing tool or password stops the release while nothing has happened yet.
#
# Android pins what it installed: an update must be signed by the same
# certificate, or by a successor the old key signed over to (apksigner rotate,
# APK_LINEAGE). There is no issuer who could replace a lost key, so the
# certificate this uses decides the app's identity for as long as it exists.
# Therefore the certificate is pinned here too: its SHA-256 goes into
# deploy/release/apk_cert_sha256 on the first release and is compared on every
# one after it. A key the maintainer did not mean to use stops the release
# instead of reaching a phone.
#
# Environment:
#   APKSIGNER       apksigner to use (default: the newest build-tools of
#                   $ANDROID_HOME, $ANDROID_SDK_ROOT or ~/Library/Android/sdk)
#   APK_KS          keystore (default private/boundgate-apk.jks, git-ignored
#                   and masked in the box). For a key in hardware: NONE
#   APK_KS_TYPE     keystore type, e.g. PKCS11 for a YubiKey's PIV applet
#   APK_KS_PROVIDER_CLASS, APK_KS_PROVIDER_ARG   the PKCS#11 provider and its
#                   configuration file
#   APK_KS_PASS     password or PIN in apksigner's notation (pass:, env:,
#                   file:, stdin). Default: the macOS keychain item
#                   APK_KEYCHAIN_ITEM (boundgate-apk-keystore), read with
#                   security(1) and handed over in the environment, so it is
#                   in no command line
#   APK_KEY_ALIAS   key in the keystore (default boundgate)
#   APK_LINEAGE     proof-of-rotation from the first certificate to this key
#                   (apksigner rotate); needed only after a key change
#   APK_MIN_SDK     the app's minSdk (default 33): which platforms the
#                   signature must be valid for
#   APK_CERT_FILE   where the pinned certificate hash lives
#                   (default deploy/release/apk_cert_sha256)
set -eu
cd "$(dirname "$0")/../.."

die() { echo "sign-apk: $*" >&2; exit 1; }
CHECK=
if [ "${1:-}" = --check ]; then
  CHECK=1
else
  IN=${1:?usage: sign-apk.sh IN-unsigned.apk OUT.apk (or --check)}
  OUT=${2:?usage: sign-apk.sh IN-unsigned.apk OUT.apk (or --check)}
  [ -f "$IN" ] || die "$IN does not exist"
fi

# ---- apksigner ----
if [ -z "${APKSIGNER:-}" ]; then
  for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [ -n "$sdk" ] && [ -d "$sdk/build-tools" ] || continue
    # the newest build-tools directory that has the tool
    for d in $(ls "$sdk/build-tools" | sort -Vr); do
      [ -x "$sdk/build-tools/$d/apksigner" ] || continue
      APKSIGNER=$sdk/build-tools/$d/apksigner; break
    done
    [ -n "${APKSIGNER:-}" ] && break
  done
fi
[ -n "${APKSIGNER:-}" ] && [ -x "$APKSIGNER" ] \
  || die "no apksigner found: install Android build-tools, or set APKSIGNER (docs/ANDROID.md)"

# ---- key ----
KS=${APK_KS:-private/boundgate-apk.jks}
ALIAS=${APK_KEY_ALIAS:-boundgate}
MIN_SDK=${APK_MIN_SDK:-33}
CERT_FILE=${APK_CERT_FILE:-deploy/release/apk_cert_sha256}
# No v4 signature: apksigner would write OUT.apk.idsig beside the APK, and
# that file belongs to "adb install --incremental" and Play's streaming
# install, not to a release that is distributed by manifest. The manifest
# names every file in the directory and refuses what it cannot classify.
set -- sign --ks "$KS" --ks-key-alias "$ALIAS" --min-sdk-version "$MIN_SDK" --v4-signing-enabled false
[ -z "${APK_KS_TYPE:-}" ] || set -- "$@" --ks-type "$APK_KS_TYPE"
[ -z "${APK_KS_PROVIDER_CLASS:-}" ] || set -- "$@" --ks-provider-class "$APK_KS_PROVIDER_CLASS"
[ -z "${APK_KS_PROVIDER_ARG:-}" ] || set -- "$@" --ks-provider-arg "$APK_KS_PROVIDER_ARG"
[ -z "${APK_LINEAGE:-}" ] || set -- "$@" --lineage "$APK_LINEAGE"
case "$KS" in NONE) ;; *) [ -r "$KS" ] || die "cannot read the keystore $KS (docs/ANDROID.md says how to create it)" ;; esac

# The password never goes into a command line (ps(1) shows those): either the
# caller names a source in apksigner's own notation, or it comes from the
# keychain into one variable of this process.
if [ -n "${APK_KS_PASS:-}" ]; then
  set -- "$@" --ks-pass "$APK_KS_PASS"
else
  command -v security >/dev/null \
    || die "no APK_KS_PASS and no keychain on this system: say where the password comes from (docs/ANDROID.md)"
  item=${APK_KEYCHAIN_ITEM:-boundgate-apk-keystore}
  BG_APK_PASS=$(security find-generic-password -s "$item" -w 2>/dev/null) \
    || die "the keychain has no password for \"$item\" (store it once: security add-generic-password -s $item -a \"\$USER\" -w)"
  export BG_APK_PASS
  set -- "$@" --ks-pass env:BG_APK_PASS
fi

if [ -n "$CHECK" ]; then
  # never the password itself: APK_KS_PASS may be "pass:<it>"
  case "${APK_KS_PASS:-}" in "") src="the keychain" ;; stdin) src="standard input" ;; *) src="${APK_KS_PASS%%:*}:…" ;; esac
  echo "sign-apk: ok — $APKSIGNER, key $ALIAS in $KS, password from $src"
  exit 0
fi

# apksigner writes nothing on failure, but a leftover from an earlier attempt
# would be signed by whatever ran then: never leave one behind.
rm -f "$OUT" "$OUT.idsig"
echo "== signing $(basename "$IN") with $KS"
"$APKSIGNER" "$@" --out "$OUT" "$IN" || die "apksigner refused to sign"
unset BG_APK_PASS

# ---- what a phone will check ----
# From here on a refusal takes the file with it: an APK signed by the wrong key
# must not be left where a later step could pick it up.
reject() { rm -f "$OUT" "$OUT.idsig"; die "$@"; }
certs=$("$APKSIGNER" verify --min-sdk-version "$MIN_SDK" --print-certs "$OUT") \
  || reject "the signature of $OUT does not verify for minSdk $MIN_SDK"
got=$(printf '%s\n' "$certs" | sed -n 's/^Signer #1 certificate SHA-256 digest: *//p' | head -1)
echo "$got" | grep -Eq '^[0-9a-f]{64}$' || reject "apksigner printed no certificate digest: $certs"
if [ -f "$CERT_FILE" ]; then
  want=$(grep -v '^#' "$CERT_FILE" | grep . | head -1)
  [ "$got" = "$want" ] || reject "this APK is signed by $got, $CERT_FILE pins $want.
A certificate that is not the pinned one installs on no phone that has this app
(Android refuses the update), unless the old key signed it over: apksigner
rotate, then APK_LINEAGE. If the key really changed on purpose, change the pin
in the same commit."
  echo "   certificate $got (as pinned)"
else
  printf '# SHA-256 of the certificate that signs the Android app (deploy/release/sign-apk.sh).\n# Android installs an update only from this certificate or a successor it signed over to.\n%s\n' "$got" > "$CERT_FILE"
  echo "   certificate $got — first release: wrote $CERT_FILE, commit it"
fi
echo "   $OUT"
