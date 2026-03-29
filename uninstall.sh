#!/bin/sh
# harmoniis-wallet uninstaller (Linux, macOS, FreeBSD)
#
# Removes the hrmw binary and PATH entry.
# DOES NOT touch wallet data at ~/.harmoniis/ — your keys and funds are safe.
set -eu

PREFIX="${HRMW_PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin/hrmw"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m==>\033[0m %s\n' "$1"; }
warn()  { printf '\033[1;33m==>\033[0m %s\n' "$1"; }

printf '\n\033[1;36m  harmoniis-wallet uninstaller\033[0m\n\n'

if [ -f "$BIN" ]; then
    info "Removing $BIN"
    rm -f "$BIN"
    ok "Binary removed"
else
    warn "Binary not found at $BIN — already uninstalled?"
fi

# Clean up empty bin directory (only if we created it).
if [ -d "$PREFIX/bin" ] && [ -z "$(ls -A "$PREFIX/bin" 2>/dev/null)" ]; then
    rmdir "$PREFIX/bin" 2>/dev/null || true
fi

printf '\n'
ok "hrmw has been uninstalled."
printf '\n'
printf '  Your wallet data at ~/.harmoniis/ has NOT been touched.\n'
printf '  Your keys and funds are safe.\n'
printf '\n'
printf '  To remove wallet data permanently (IRREVERSIBLE):\n'
printf '    rm -rf ~/.harmoniis/\n'
printf '\n'
