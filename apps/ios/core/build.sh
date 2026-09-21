#!/bin/sh
# Builds BoundGateCore.xcframework (the node for the iOS app, its packet
# tunnel and later the macOS network extension; docs/EMBED.md) from
# cmd/libboundgate.
#
# This is the one place Go runs on the Mac and not in the box: a C archive for
# iOS links against Apple's SDKs. The toolchain lives in ~/.local/go-apple
# (the official go.dev tarball, checked against its published SHA-256; not on
# PATH) or wherever APPLE_GO points. The modules come from the box (`go mod
# vendor`, with the box's cooldown), so the Mac needs no module proxy.
#
#   make apple-core VERSION=v0.1.6
set -eu
cd "$(dirname "$0")/../../.."
GO=${APPLE_GO:-$HOME/.local/go-apple/bin/go}
VERSION=${VERSION:-dev}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
OUT=build/apple
[ -x "$GO" ] || { echo "apple-core: no Go toolchain at $GO (docs/IOS.md, 'Building the core')" >&2; exit 1; }
want=$(sed -n 's/^go \([0-9.]*\).*/\1/p' go.mod)
have=$("$GO" env GOVERSION)
echo "apple-core: $have (go.mod asks for go $want), version $VERSION"

rm -rf vendor "$OUT"
box go mod vendor
trap 'rm -rf vendor' EXIT
mkdir -p "$OUT/headers"

# lib SDK GOOS TARGET OUTDIR
lib() {
	sdk=$1 goos=$2 target=$3 dir=$4
	sysroot=$(xcrun -sdk "$sdk" --show-sdk-path)
	cc="$(xcrun -sdk "$sdk" -f clang) -isysroot $sysroot -target $target"
	arch=arm64
	case $target in x86_64-*) arch=amd64 ;; esac
	echo "apple-core: $dir ($target)"
	env GOOS="$goos" GOARCH="$arch" CGO_ENABLED=1 CC="$cc" CGO_CFLAGS="-O2" CGO_LDFLAGS="" \
		GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local \
		"$GO" build -buildmode=c-archive -trimpath \
		-ldflags "-s -w -X gitlab.net407.com/SBH/BoundGate-VPN/internal/version.Version=$VERSION -X gitlab.net407.com/SBH/BoundGate-VPN/internal/version.Commit=$COMMIT" \
		-o "$OUT/$dir/libboundgate.a" ./cmd/libboundgate
	rm -f "$OUT/$dir/libboundgate.h" # cgo's own header; the apps use boundgate.h
}
lib iphoneos ios arm64-apple-ios16.0 ios-arm64
lib iphonesimulator ios arm64-apple-ios16.0-simulator ios-arm64-simulator
lib macosx darwin arm64-apple-macos13.0 macos-arm64
lib macosx darwin x86_64-apple-macos13.0 macos-x86_64
mkdir -p "$OUT/macos"
lipo -create "$OUT/macos-arm64/libboundgate.a" "$OUT/macos-x86_64/libboundgate.a" -output "$OUT/macos/libboundgate.a"

cp cmd/libboundgate/boundgate.h "$OUT/headers/"
cat > "$OUT/headers/module.modulemap" <<'MAP'
module BoundGateCore {
    header "boundgate.h"
    // what the Go runtime and crypto/x509 import on Darwin
    link "resolv"
    link framework "Security"
    link framework "CoreFoundation"
    export *
}
MAP
xcodebuild -create-xcframework \
	-library "$OUT/ios-arm64/libboundgate.a" -headers "$OUT/headers" \
	-library "$OUT/ios-arm64-simulator/libboundgate.a" -headers "$OUT/headers" \
	-library "$OUT/macos/libboundgate.a" -headers "$OUT/headers" \
	-output "$OUT/BoundGateCore.xcframework"
ls -la "$OUT"/ios-arm64/libboundgate.a
echo "apple-core: $OUT/BoundGateCore.xcframework"
