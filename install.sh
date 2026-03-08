#!/bin/sh
# harmoniis-wallet installer
# Usage: curl -fsSL https://github.com/harmoniis/harmoniis-wallet/releases/latest/download/install.sh | sh
set -eu

REPO="harmoniis/harmoniis-wallet"
PREFIX="${HRMW_PREFIX:-$HOME/.local}"
VERSION="${HRMW_VERSION:-}"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m==>\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m==>\033[0m %s\n' "$1"; }
error() { printf '\033[1;31m==>\033[0m %s\n' "$1" >&2; exit 1; }

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    case "$OS" in
        Linux)   OS="linux"   ;;
        Darwin)  OS="macos"   ;;
        FreeBSD) OS="freebsd" ;;
        *)       error "Unsupported OS: $OS" ;;
    esac
    case "$ARCH" in
        x86_64|amd64)          ARCH="x86_64"   ;;
        aarch64|arm64)         ARCH="aarch64"  ;;
        *)                     error "Unsupported architecture: $ARCH" ;;
    esac
    PLATFORM="${OS}-${ARCH}"
}

latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/'
}

fetch() {
    curl -fSL --progress-bar -o "$2" "$1"
}

main() {
    printf '\n\033[1;36m  harmoniis-wallet installer\033[0m\n\n'

    detect_platform

    if [ -z "$VERSION" ]; then
        info "Detecting latest release..."
        VERSION="$(latest_version)"
        [ -n "$VERSION" ] || error "Could not determine latest version"
    fi

    info "Installing harmoniis-wallet v${VERSION} for ${PLATFORM}"

    TARBALL="harmoniis-wallet-${VERSION}-${PLATFORM}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/${TARBALL}"

    TMPDIR="$(mktemp -d)"
    trap 'rm -rf "$TMPDIR"' EXIT

    info "Downloading ${URL}..."
    fetch "$URL" "$TMPDIR/$TARBALL"

    CHECKSUM_URL="${URL}.sha256"
    if fetch "$CHECKSUM_URL" "$TMPDIR/${TARBALL}.sha256" 2>/dev/null; then
        info "Verifying checksum..."
        cd "$TMPDIR"
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum -c "${TARBALL}.sha256" || error "Checksum verification failed"
        elif command -v shasum >/dev/null 2>&1; then
            shasum -a 256 -c "${TARBALL}.sha256" || error "Checksum verification failed"
        else
            warn "No sha256sum or shasum found, skipping verification"
        fi
        cd - >/dev/null
    else
        warn "Checksum file not available, skipping verification"
    fi

    info "Extracting..."
    tar xzf "$TMPDIR/$TARBALL" -C "$TMPDIR"

    TARBALL_DIR="$(find "$TMPDIR" -maxdepth 1 -type d -name 'harmoniis-wallet-*' | head -1)"
    [ -d "$TARBALL_DIR" ] || error "Extraction failed"

    mkdir -p "$PREFIX/bin"
    cp "$TARBALL_DIR/bin/hrmw" "$PREFIX/bin/"
    chmod +x "$PREFIX/bin/hrmw"

    ok "Installed hrmw to ${PREFIX}/bin/hrmw"

    case ":$PATH:" in
        *":$PREFIX/bin:"*) ;;
        *)
            warn "Add to your PATH:"
            printf '  export PATH="%s/bin:$PATH"\n' "$PREFIX"
            ;;
    esac

    if [ -x "$PREFIX/bin/hrmw" ]; then
        printf '\n  Version: %s\n\n' "$("$PREFIX/bin/hrmw" --version 2>/dev/null || echo 'unknown')"
    fi
}

main "$@"
