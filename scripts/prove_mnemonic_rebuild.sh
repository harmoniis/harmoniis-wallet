#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${1:-${REPO_DIR}/../wallets/rebuild-proof}"
NETWORK="${NETWORK:-bitcoin}"

HRMW() {
  (cd "${REPO_DIR}" && cargo run --quiet --bin hrmw -- "$@")
}

capture_snapshot() {
  local wallet_db="$1"
  local out_dir="$2"
  mkdir -p "${out_dir}"

  HRMW --wallet "${wallet_db}" key fingerprint > "${out_dir}/key_fingerprint.txt"
  HRMW --wallet "${wallet_db}" identity pgp-list > "${out_dir}/pgp_list.txt"
  awk 'NR > 2 { print $2, $3, $4 }' "${out_dir}/pgp_list.txt" > "${out_dir}/pgp_keys.txt"
  HRMW --wallet "${wallet_db}" bitcoin address --network "${NETWORK}" --kind taproot --index 0 > "${out_dir}/taproot_index0.txt"
  HRMW --wallet "${wallet_db}" bitcoin address --network "${NETWORK}" --kind segwit --index 0 > "${out_dir}/segwit_index0.txt"
  HRMW --wallet "${wallet_db}" bitcoin ark board --network "${NETWORK}" > "${out_dir}/ark_boarding.txt"
  HRMW --wallet "${wallet_db}" bitcoin ark offchain --network "${NETWORK}" > "${out_dir}/ark_offchain.txt"
}

compare_snapshot_file() {
  local left="$1"
  local right="$2"
  local label="$3"
  if ! diff -u "${left}" "${right}" >/dev/null; then
    echo "Mismatch: ${label}" >&2
    diff -u "${left}" "${right}" || true
    exit 1
  fi
}

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/source" "${OUT_DIR}/restored"

SOURCE_DB="${OUT_DIR}/source/master.db"
RESTORED_DB="${OUT_DIR}/restored/master.db"

echo "[1/6] Create source wallet"
HRMW --wallet "${SOURCE_DB}" setup --password-manager off >/dev/null
HRMW --wallet "${SOURCE_DB}" identity pgp-new --label ops-signing >/dev/null
HRMW --wallet "${SOURCE_DB}" identity pgp-new --label market-maker >/dev/null
HRMW --wallet "${SOURCE_DB}" identity pgp-use --label ops-signing >/dev/null

echo "[2/6] Export mnemonic"
MNEMONIC="$(HRMW --wallet "${SOURCE_DB}" key export --format mnemonic)"
printf '%s\n' "${MNEMONIC}" > "${OUT_DIR}/source/mnemonic.txt"
chmod 600 "${OUT_DIR}/source/mnemonic.txt"

echo "[3/6] Capture source deterministic snapshot"
capture_snapshot "${SOURCE_DB}" "${OUT_DIR}/source"
HRMW --wallet "${SOURCE_DB}" webcash info >/dev/null
HRMW --wallet "${SOURCE_DB}" bitcoin info --network "${NETWORK}" >/dev/null

echo "[4/6] Restore wallet from mnemonic"
HRMW --wallet "${RESTORED_DB}" setup --password-manager off >/dev/null
HRMW --wallet "${RESTORED_DB}" key import --mnemonic "${MNEMONIC}" --force >/dev/null
HRMW --wallet "${RESTORED_DB}" identity pgp-new --label ops-signing >/dev/null
HRMW --wallet "${RESTORED_DB}" identity pgp-new --label market-maker >/dev/null
HRMW --wallet "${RESTORED_DB}" identity pgp-use --label ops-signing >/dev/null

echo "[5/6] Capture restored deterministic snapshot"
capture_snapshot "${RESTORED_DB}" "${OUT_DIR}/restored"
HRMW --wallet "${RESTORED_DB}" webcash info >/dev/null
HRMW --wallet "${RESTORED_DB}" bitcoin info --network "${NETWORK}" >/dev/null

echo "[6/6] Verify parity"
compare_snapshot_file "${OUT_DIR}/source/key_fingerprint.txt" "${OUT_DIR}/restored/key_fingerprint.txt" "key fingerprint (root/rgb/webcash/bitcoin)"
compare_snapshot_file "${OUT_DIR}/source/pgp_keys.txt" "${OUT_DIR}/restored/pgp_keys.txt" "pgp identity keys (index/active/fingerprint)"
compare_snapshot_file "${OUT_DIR}/source/taproot_index0.txt" "${OUT_DIR}/restored/taproot_index0.txt" "bitcoin taproot index0"
compare_snapshot_file "${OUT_DIR}/source/segwit_index0.txt" "${OUT_DIR}/restored/segwit_index0.txt" "bitcoin segwit index0"
compare_snapshot_file "${OUT_DIR}/source/ark_boarding.txt" "${OUT_DIR}/restored/ark_boarding.txt" "ark boarding address"
compare_snapshot_file "${OUT_DIR}/source/ark_offchain.txt" "${OUT_DIR}/restored/ark_offchain.txt" "ark offchain address"

if [[ ! -f "${OUT_DIR}/source/webcash.db" || ! -f "${OUT_DIR}/restored/webcash.db" ]]; then
  echo "Webcash DB missing after snapshot generation" >&2
  exit 1
fi

if [[ ! -f "${OUT_DIR}/source/bitcoin.db" || ! -f "${OUT_DIR}/restored/bitcoin.db" ]]; then
  echo "Bitcoin DB missing after snapshot generation" >&2
  exit 1
fi

if [[ ! -f "${OUT_DIR}/source/rgb.db" || ! -f "${OUT_DIR}/restored/rgb.db" ]]; then
  echo "RGB DB missing after snapshot generation" >&2
  exit 1
fi

cat > "${OUT_DIR}/RESULT.txt" <<EOF
status=ok
network=${NETWORK}
verified=mnemonic_restore_full_parity
checks=key_fingerprint,pgp_keys,taproot0,segwit0,ark_boarding,ark_offchain,webcash_db,bitcoin_db,rgb_db
source_wallet=${SOURCE_DB}
restored_wallet=${RESTORED_DB}
EOF

echo
echo "Mnemonic rebuild proof complete: ${OUT_DIR}/RESULT.txt"
