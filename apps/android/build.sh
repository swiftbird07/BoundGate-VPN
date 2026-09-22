#!/bin/sh
# Builds the Android app (docs/ANDROID.md): libboundgate.so from
# cmd/libboundgate for arm64 phones and the x86-64 emulator (image of
# Dockerfile.core, native), then the APK (image of Dockerfile, x86-64). Go and
# Gradle never run on the Mac.
#
#   make android                           debug APK (installable with adb)
#   make android ANDROID_BUILD=release     unsigned release APK (the user signs it)
#   ANDROID_VERIFY=write make android      regenerates gradle/verification-metadata.xml
#                                          after a version bump; review the diff
set -eu
cd "$(dirname "$0")/../.."
VERSION=${VERSION:-dev}
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD=${ANDROID_BUILD:-debug}
IMAGE=boundgate-android-build
VPKG=gitlab.net407.com/SBH/BoundGate-VPN/internal/version

# vX.Y.Z -> X*10000 + Y*100 + Z: grows with every release, which Android
# needs to install an update over the old app
code=1
case $VERSION in
v[0-9]*.[0-9]*.[0-9]*)
	code=$(echo "$VERSION" | sed 's/^v//; s/-.*//' | awk -F. '{ print $1*10000 + $2*100 + $3 }') ;;
esac

docker build -q --platform linux/amd64 -t "$IMAGE" apps/android >/dev/null
docker build -q -t "$IMAGE-core" -f apps/android/Dockerfile.core apps/android >/dev/null 2>&1

# the modules come from the box and its cooldown; the image builds with GOPROXY=off
rm -rf vendor 2>/dev/null || rm -rf vendor
box go mod vendor
# virtiofs sometimes needs a second pass for a large tree
trap 'rm -rf vendor 2>/dev/null || rm -rf vendor' EXIT

gradle_task=assembleDebug
[ "$BUILD" = release ] && gradle_task=assembleRelease
verify=""
[ "${ANDROID_VERIFY:-}" = write ] && verify="--write-verification-metadata sha256"

# ./private stays out of the containers, as with box
run() {
	docker run --rm -v "$PWD":/work -w /work --mount type=tmpfs,destination=/work/private \
		-v boundgate-android-cache:/cache "$@"
}

# the core: a native clang against the NDK's sysroot and compiler-rt
run -e VERSION="$VERSION" -e COMMIT="$COMMIT" -e VPKG="$VPKG" "$IMAGE-core" sh -euc '
	# ABI, GOARCH, clang target (API 31, the app'"'"'s minSdk), compiler-rt directory
	for spec in arm64-v8a:arm64:aarch64-linux-android31:aarch64 x86_64:amd64:x86_64-linux-android31:x86_64; do
		abi=${spec%%:*}; rest=${spec#*:}; arch=${rest%%:*}; rest=${rest#*:}; target=${rest%%:*}; cpu=${rest#*:}
		out=build/android/jniLibs/$abi
		echo "android: libboundgate.so for $abi"
		mkdir -p "$out"
		# 16 KB pages: Android 15 devices may use them
		GOOS=android GOARCH=$arch CGO_ENABLED=1 \
			CC="clang --target=$target --sysroot=/opt/ndk/sysroot -resource-dir=/opt/ndk/clang" \
			CGO_LDFLAGS="-fuse-ld=lld -rtlib=compiler-rt -unwindlib=libunwind -L/opt/ndk/clang/lib/linux/$cpu -Wl,-z,max-page-size=16384" \
			go build -buildmode=c-shared -trimpath \
			-ldflags "-s -w -X $VPKG.Version=$VERSION -X $VPKG.Commit=$COMMIT" \
			-o "$out/libboundgate.so" ./cmd/libboundgate
		rm -f "$out/libboundgate.h"
	done
'

# the APK
echo "android: gradle $gradle_task"
run --platform linux/amd64 -e HOME=/cache/home -e ANDROID_USER_HOME=/cache/android "$IMAGE" sh -euc "
	mkdir -p \$HOME
	cd apps/android
	gradle --no-daemon --console=plain -q $verify \
		-PbgVersion=$VERSION -PbgVersionCode=$code -PbgJniLibs=/work/build/android/jniLibs $gradle_task
"

mkdir -p dist
if [ "$BUILD" = release ]; then
	cp apps/android/app/build/outputs/apk/release/app-release-unsigned.apk "dist/BoundGate-$VERSION-unsigned.apk"
	echo "android: dist/BoundGate-$VERSION-unsigned.apk (sign it: docs/ANDROID.md)"
else
	cp apps/android/app/build/outputs/apk/debug/app-debug.apk "dist/BoundGate-$VERSION-debug.apk"
	echo "android: dist/BoundGate-$VERSION-debug.apk"
fi
