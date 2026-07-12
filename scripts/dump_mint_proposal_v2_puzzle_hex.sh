#!/usr/bin/env bash
#
# Regenerate the portal-side bundled puzzle hex constant for
# mint_proposal_inner_v2.clsp (Phase 9-Hermes-D).
#
# Mirrors ``dump_v2_puzzle_hex.sh`` (admin-authority-v2) but for the
# MIPS-pluggable mint-proposal puzzle.  The portal can't depend on
# solslot_puzzles at runtime (different language, different repo),
# so the compiled bytecode is bundled as a TS string literal.
#
# Run this whenever the .clsp source changes.  The cross-repo
# regression test
# ``tests/test_mint_proposal_v2.py::TestModHash::test_mod_hash_pinned``
# pins the expected tree hash, so if you change the source you'll
# need to update both the hex constant AND the pinned hash (and the
# matching value in the TS service).

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
SOURCE="$REPO_ROOT/solslot_puzzles/mint_proposal_inner_v2.clsp.hex"
DEST="$REPO_ROOT/../populis_portal/src/app/services/mint-proposal-v2/mint-proposal-v2.puzzle-hex.ts"

if [[ ! -f "$SOURCE" ]]; then
  echo "ERROR: puzzle hex not found at $SOURCE" >&2
  echo "  Try: cd populis_protocol && .venv/bin/python -c 'from solslot_puzzles import load_puzzle; load_puzzle(\"mint_proposal_inner_v2.clsp\")'" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"

HEX="$(tr -d '[:space:]' < "$SOURCE")"
SIZE_BYTES=$((${#HEX} / 2))

cat > "$DEST" <<'HEADER'
/**
 * Compiled bytecode of `mint_proposal_inner_v2.clsp` (Phase 9-Hermes-D).
 *
 * Bundled at build time from
 * ``populis_protocol/solslot_puzzles/mint_proposal_inner_v2.clsp.hex``
 * via the helper script
 * ``populis_protocol/scripts/dump_mint_proposal_v2_puzzle_hex.sh``.
 *
 * The portal feeds this hex into ``Clvm.deserialize()`` (chia-wallet-sdk-wasm)
 * to construct the V2 inner puzzle Program client-side.  No API call
 * needed to obtain the puzzle.
 *
 * **CRITICAL**: this constant MUST stay in sync with the .hex file in
 * populis_protocol.  The cross-repo regression test
 * ``tests/test_mint_proposal_v2.py::TestModHash::test_mod_hash_pinned``
 * pins the tree hash of this bytecode (``0x1d3838f0...``).  If the
 * puzzle source changes, regenerate via:
 *
 *     cd populis_protocol
 *     bash scripts/dump_mint_proposal_v2_puzzle_hex.sh
 *
 * which rewrites this file.
 */
export const MINT_PROPOSAL_INNER_V2_PUZZLE_HEX =
  '0x' +
HEADER

printf "  '%s';\n" "$HEX" >> "$DEST"

echo "wrote $DEST"
echo "  size: $SIZE_BYTES bytes ($(printf '%d' "${#HEX}") hex chars)"
