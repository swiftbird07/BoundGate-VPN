#!/bin/sh
# Builds the Android app (docs/ANDROID.md): libboundgate.so from
# cmd/libboundgate for arm64 phones and the x86-64 emulator, then the APK,
# all inside the image of apps/android/Dockerfile. Go and Gradle never run on
# the Mac.
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

# the modules come from the box and its cooldown; the image builds with GOPROXY=off
rm -rf vendor
box go mod vendor
trap 'rm -rf vendor' EXIT

gradle_task=assembleDebug
[ "$BUILD" = release ] && gradle_task=assembleRelease
verify=""
[ "${ANDROID_VERIFY:-}" = write ] && verify="--write-verification-metadata sha256"

# ./private stays out of the container, as with box
docker run --rm --platform linux/amd64 \
	-v "$PWD":/work -w /work --mount type=tmpfs,destination=/work/private \
	-v boundgate-android-cache:/cache \
	-e VERSION="$VERSION" -e COMMIT="$COMMIT" -e VPKG="$VPKG" -e CODE="$code" \
	-e TASK="$gradle_task" -e VERIFY="$verify" -e HOME=/cache/home -e ANDROID_USER_HOME=/cache/android \
	"$IMAGE" sh -euc '
		mkdir -p "$HOME"
		tc=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
		# ABI, GOARCH, clang target (API 31, the app'"'"'s minSdk)
		for spec in arm64-v8a:arm64:aarch64-linux-android31 x86_64:amd64:x86_64-linux-android31; do
			abi=${spec%%:*}; rest=${spec#*:}; arch=${rest%%:*}; target=${rest#*:}
			out=build/android/jniLibs/$abi
			echo "android: libboundgate.so for $abi"
			mkdir -p "$out"
			GOOS=android GOARCH=$arch CGO_ENABLED=1 CC="$tc/$target-clang" \
				go build -buildmode=c-shared -trimpath \
				-ldflags "-s -w -X $VPKG.Version=$VERSION -X $VPKG.Commit=$COMMIT" \
				-o "$out/libboundgate.so" ./cmd/libboundgate
			rm -f "$out/libboundgate.h"
		done
		cd apps/android
		echo "android: gradle $TASK"
		gradle --no-daemon --console=plain -q $VERIFY \
			-PbgVersion="$VERSION" -PbgVersionCode="$CODE" -PbgJniLibs=/work/build/android/jniLibs $TASK
	'

mkdir -p dist
if [ "$BUILD" = release ]; then
	cp apps/android/app/build/outputs/apk/release/app-release-unsigned.apk "dist/BoundGate-$VERSION-unsigned.apk"
	echo "android: dist/BoundGate-$VERSION-unsigned.apk (sign it: docs/ANDROID.md)"
else
	cp apps/android/app/build/outputs/apk/debug/app-debug.apk "dist/BoundGate-$VERSION-debug.apk"
	echo "android: dist/BoundGate-$VERSION-debug.apk"
fi
