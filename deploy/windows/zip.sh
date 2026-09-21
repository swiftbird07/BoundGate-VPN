#!/bin/sh
# Packs the Windows release zip: the three programs from BINDIR, the install,
# uninstall and acceptance scripts and the default node.yaml, in one folder
# boundgate-<version>-windows-<arch>. wintun.dll is not in it: the user
# downloads it from wintun.net and install.ps1 checks its signature
# (docs/WINDOWS.md). Used by CI and by `make windows-zip`.
#
#   deploy/windows/zip.sh v1.2.3 amd64 bin/windows_amd64 dist/release
set -eu
V=${1:?usage: zip.sh VERSION ARCH BINDIR OUTDIR}; ARCH=${2:?}; BIN=${3:?}; OUT=${4:?}
HERE=$(cd "$(dirname "$0")" && pwd)
NAME=boundgate-$V-windows-$ARCH
command -v zip >/dev/null || { echo "zip.sh: needs zip" >&2; exit 2; }
for f in boundgate-node.exe boundgatectl.exe boundgate-tray.exe; do
  [ -f "$BIN/$f" ] || { echo "zip.sh: $BIN/$f is missing" >&2; exit 2; }
done
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/bgzip.XXXXXX")
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/$NAME"
cp "$BIN/boundgate-node.exe" "$BIN/boundgatectl.exe" "$BIN/boundgate-tray.exe" "$STAGE/$NAME/"
cp "$HERE/install.ps1" "$HERE/uninstall.ps1" "$HERE/e2e.ps1" "$HERE/node.yaml" "$STAGE/$NAME/"
# Windows tools want CRLF in what people open in Notepad
sed 's/$/\r/' "$HERE/README.txt" > "$STAGE/$NAME/README.txt"
# same bytes for the same inputs: fixed times, sorted names, no extra attributes
find "$STAGE/$NAME" -exec touch -t 202601010000 {} +
rm -f "$OUT/$NAME.zip"
(cd "$STAGE" && find "$NAME" -type f | LC_ALL=C sort | zip -qX -@ "$OUT/$NAME.zip")
echo "$OUT/$NAME.zip"
