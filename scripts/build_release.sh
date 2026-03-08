#!/usr/bin/env bash
# Build release tarball for harmoniis-wallet.
# Usage: bash scripts/build_release.sh <VERSION> [PLATFORM]
# If PLATFORM is omitted, auto-detect from the current host.
set -euo pipefail

VERSION="${1:?Usage: build_release.sh <VERSION> [PLATFORM]}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -n "${2:-}" ]; then
    PLATFORM="$2"
else
    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)    PLATFORM="linux-x86_64"   ;;
        Linux-aarch64)   PLATFORM="linux-aarch64"   ;;
        Darwin-arm64)    PLATFORM="macos-aarch64"   ;;
        Darwin-x86_64)   PLATFORM="macos-x86_64"   ;;
        MINGW*|MSYS*|CYGWIN*) PLATFORM="windows-x86_64" ;;
        *)               echo "Unsupported platform: $(uname -s)-$(uname -m)"; exit 1 ;;
    esac
fi

# Determine binary name
case "$PLATFORM" in
    windows-*) BINARY="hrmw.exe" ;;
    *)         BINARY="hrmw" ;;
esac

TARBALL="harmoniis-wallet-${VERSION}-${PLATFORM}.tar.gz"
STAGING="harmoniis-wallet-${VERSION}"

echo "==> Building release tarball: ${TARBALL}"

if [ ! -f "target/release/${BINARY}" ]; then
    echo "Error: target/release/${BINARY} not found. Run 'cargo build --release' first."
    exit 1
fi

rm -rf "$STAGING"
mkdir -p "$STAGING/bin"

cp "target/release/${BINARY}" "$STAGING/bin/"
cp LICENSE "$STAGING/" 2>/dev/null || true
cp README.md "$STAGING/" 2>/dev/null || true

echo "Release contents:"
find "$STAGING" -type f | sort | while read -r f; do
    echo "  $f"
done

tar czf "$TARBALL" "$STAGING"
rm -rf "$STAGING"

CHECKSUM_FILE="${TARBALL}.sha256"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$TARBALL" > "$CHECKSUM_FILE"
else
    shasum -a 256 "$TARBALL" > "$CHECKSUM_FILE"
fi

echo "==> Created ${TARBALL} ($(du -h "$TARBALL" | cut -f1))"
echo "==> Checksum: $(cat "$CHECKSUM_FILE")"
