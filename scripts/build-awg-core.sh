#!/usr/bin/env bash
set -euo pipefail

# Builds the AmneziaWG userspace Go bridge that WireGuardKit links statically.
# Swift Package Manager intentionally does not run this Makefile by itself.
#
# Usage:
#   bash scripts/build-awg-core.sh [derived-data-path] [configuration] [sdk]
# Defaults: ./DerivedData Debug iphoneos
#
# Run this after `xcodebuild -resolvePackageDependencies` (or after Xcode has
# resolved packages once). Repeat with sdk=iphonesimulator before a simulator
# build: both SDKs intentionally produce out/libwg-go.a, the path hardcoded by
# WireGuardKitGo's Package.swift linker settings.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DERIVED_DATA="${1:-$ROOT_DIR/DerivedData}"
CONFIGURATION="${2:-Debug}"
SDK="${3:-iphoneos}"

case "$SDK" in
  iphoneos)
    ARCHS="arm64"
    DEPLOYMENT_FLAG="miphoneos-version-min"
    ;;
  iphonesimulator)
    ARCHS="x86_64 arm64"
    DEPLOYMENT_FLAG="mios-simulator-version-min"
    ;;
  *)
    echo "error: sdk must be iphoneos or iphonesimulator (got: $SDK)" >&2
    exit 2
    ;;
esac

CHECKOUT_DIR="$DERIVED_DATA/SourcePackages/checkouts/amneziawg-apple"
WG_GO_DIR="$CHECKOUT_DIR/Sources/WireGuardKitGo"

if [[ ! -f "$WG_GO_DIR/Makefile" ]]; then
  cat >&2 <<'EOF'
error: AmneziaWG package checkout was not found.
Resolve packages first, for example:
  xcodegen generate
  xcodebuild -resolvePackageDependencies -project OmniWARP.xcodeproj -scheme OmniWARP -derivedDataPath ./DerivedData
EOF
  exit 1
fi

for tool in go rsync xcrun make clang lipo patch sed; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: required build tool is missing: $tool" >&2
    exit 1
  fi
done

SDK_PATH="$(xcrun --sdk "$SDK" --show-sdk-path)"
TEMP_DIR="$WG_GO_DIR/.tmp/$SDK-$CONFIGURATION"

echo "Building out/libwg-go.a for $SDK/$ARCHS ($CONFIGURATION)..."
# The upstream Makefile defines GOOS_iphoneos but no GOOS_iphonesimulator.
# Select the simulator solely through SDKROOT while keeping GOOS=ios.
make -C "$WG_GO_DIR" \
  PLATFORM_NAME=iphoneos \
  ARCHS="$ARCHS" \
  SDKROOT="$SDK_PATH" \
  CONFIGURATION_BUILD_DIR="$WG_GO_DIR/out" \
  CONFIGURATION_TEMP_DIR="$TEMP_DIR" \
  DEPLOYMENT_TARGET_CLANG_FLAG_NAME="$DEPLOYMENT_FLAG" \
  DEPLOYMENT_TARGET_CLANG_ENV_NAME="IPHONEOS_DEPLOYMENT_TARGET" \
  IPHONEOS_DEPLOYMENT_TARGET="17.0" \
  build version-header

echo "AmneziaWG Go bridge ready: $WG_GO_DIR/out/libwg-go.a"
