#!/usr/bin/env bash
#
# Regenerate the portal-side bundled puzzle hex constants for the
# Phase 4 mint-publish flow.
#
# The TS service ``populis_portal/src/app/services/mint-proposal-v2/
# mint-publish.service.ts`` re-implements ``build_mint_publish_artifacts``
# in TS using the WASM ``Clvm`` shim.  It needs the same four puzzles
# the Python driver loads via ``populis_puzzles.load_puzzle`` —
# bundled as TS string literals so the portal never round-trips to
# populis_api just to obtain a puzzle.
#
# Puzzles bundled by this script:
#   * smart_deed_inner.clsp         → the post-purchase deed inner
#   * mint_offer_delegate.clsp      → the eve deed inner (offer)
#   * singleton_launcher_with_did.clsp → DID-gated deed launcher
#   * purchase_payment.clsp         → ephemeral buyer payment coin
#
# Cross-repo guard: the byte-equivalence test in
# ``populis_portal/src/app/services/mint-proposal-v2/
# mint-publish.service.spec.ts`` reads the fixture emitted by
# ``populis_protocol/scripts/dump_mint_publish_fixtures.py`` and
# asserts the TS service's recurried hashes match Python byte-for-byte.
# Drift in any of these puzzle .clsp sources will surface there.
#
# Usage:
#   cd populis_protocol
#   bash scripts/dump_mint_publish_puzzle_hex.sh

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
PUZZLES_DIR="$REPO_ROOT/populis_puzzles"
DEST_DIR="$REPO_ROOT/../populis_portal/src/app/services/mint-proposal-v2"

mkdir -p "$DEST_DIR"

# Args: <puzzle-basename> <ts-export-name> <ts-filename-stem> <doc-purpose>
dump_one() {
  local puzzle="$1"
  local ts_export="$2"
  local ts_stem="$3"
  local purpose="$4"

  local src="$PUZZLES_DIR/${puzzle}.clsp.hex"
  local dest="$DEST_DIR/${ts_stem}.puzzle-hex.ts"

  if [[ ! -f "$src" ]]; then
    echo "ERROR: puzzle hex not found at $src" >&2
    echo "  Compile first:" >&2
    echo "    cd populis_protocol && .venv/bin/python -c 'from populis_puzzles import load_puzzle; load_puzzle(\"${puzzle}.clsp\")'" >&2
    exit 1
  fi

  local hex
  hex="$(tr -d '[:space:]' < "$src")"
  local size_bytes=$((${#hex} / 2))

  cat > "$dest" <<HEADER
/**
 * Compiled bytecode of \`${puzzle}.clsp\` (Phase 4 mint-publish).
 *
 * Bundled at build time from
 * \`\`populis_protocol/populis_puzzles/${puzzle}.clsp.hex\`\`
 * via the helper script
 * \`\`populis_protocol/scripts/dump_mint_publish_puzzle_hex.sh\`\`.
 *
 * Purpose: ${purpose}
 *
 * The portal feeds this hex into \`\`Clvm.deserialize()\`\` (chia-wallet-sdk-wasm)
 * to construct the puzzle Program client-side.  No API call needed.
 *
 * **CRITICAL**: this constant MUST stay in sync with the .hex file in
 * populis_protocol.  The cross-repo Karma spec
 * \`\`mint-publish.service.spec.ts\`\` reads the canonical fixture
 * emitted by \`\`populis_protocol/scripts/dump_mint_publish_fixtures.py\`\`
 * and asserts byte-equivalence — drift here surfaces there.
 *
 * If the puzzle source changes, regenerate via:
 *
 *     cd populis_protocol
 *     bash scripts/dump_mint_publish_puzzle_hex.sh
 *
 * which rewrites this file.
 */
export const ${ts_export} =
  '0x' +
HEADER

  printf "  '%s';\n" "$hex" >> "$dest"

  echo "wrote $dest ($size_bytes bytes)"
}

dump_one \
  "smart_deed_inner" \
  "SMART_DEED_INNER_PUZZLE_HEX" \
  "smart-deed-inner" \
  "post-purchase deed inner puzzle (transitions the deed once a buyer co-spends an ephemeral purchase_payment coin)"

dump_one \
  "mint_offer_delegate" \
  "MINT_OFFER_DELEGATE_PUZZLE_HEX" \
  "mint-offer-delegate" \
  "eve deed inner puzzle (standing on-chain mint offer) curried with the smart_deed_inner hash + par value + protocol DID"

dump_one \
  "singleton_launcher_with_did" \
  "SINGLETON_LAUNCHER_WITH_DID_PUZZLE_HEX" \
  "singleton-launcher-with-did" \
  "DID-gated singleton launcher used by the deed to constrain its launch authorisation to the protocol DID singleton lineage"

dump_one \
  "purchase_payment" \
  "PURCHASE_PAYMENT_PUZZLE_HEX" \
  "purchase-payment" \
  "ephemeral buyer-side payment coin spawned during mint-offer settlement (only its mod hash is curried into the eve mint-offer inner — needed here so the TS service can independently derive that hash without trusting the fixture)"
