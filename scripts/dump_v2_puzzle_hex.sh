#!/usr/bin/env bash
#
# Regenerate the portal-side bundled puzzle hex constant for
# admin_authority_v2_inner.clsp.
#
# The portal can't depend on solslot_puzzles at runtime (different
# language, different repo), so the compiled bytecode is bundled as
# a TS string literal.  This script reads
# ``solslot_puzzles/admin_authority_v2_inner.clsp.hex`` and rewrites
# ``solslot-portal/src/app/services/admin-authority-v2/admin-authority-v2.puzzle-hex.ts``.
#
# Run this whenever the .clsp source changes.  The cross-repo
# regression test (``tests/test_v2_fixtures.py::test_mod_hash_is_a_known_constant``)
# pins the expected tree hash, so if you change the source you'll
# need to update both the hex constant AND the pinned hash.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
PORTAL_ROOT="${SOLSLOT_PORTAL_ROOT:-$REPO_ROOT/../solslot-portal}"
SOURCE="$REPO_ROOT/solslot_puzzles/admin_authority_v2_inner.clsp.hex"
DEST="$PORTAL_ROOT/src/app/services/admin-authority-v2/admin-authority-v2.puzzle-hex.ts"

if [[ ! -f "$SOURCE" ]]; then
  echo "ERROR: puzzle hex not found at $SOURCE" >&2
  echo "  Try: cd solslot-protocol && .venv/bin/python -c 'from solslot_puzzles import load_puzzle; load_puzzle(\"admin_authority_v2_inner.clsp\")'" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"

HEX="$(tr -d '[:space:]' < "$SOURCE")"
SIZE_BYTES=$((${#HEX} / 2))

cat > "$DEST" <<'HEADER'
/**
 * Compiled bytecode of `admin_authority_v2_inner.clsp` (Phase 9-Hermes-C).
 *
 * Bundled at build time from
 * ``solslot-protocol/solslot_puzzles/admin_authority_v2_inner.clsp.hex``
 * via the helper script ``solslot-protocol/scripts/dump_v2_puzzle_hex.sh``.
 *
 * The portal feeds this hex into ``Clvm.deserialize()`` (chia-wallet-sdk-wasm)
 * to construct the inner puzzle Program client-side.  This is what makes the
 * WASM-first path possible: no API call needed to obtain the puzzle.
 *
 * **CRITICAL**: this constant MUST stay in sync with the .hex file in
 * solslot-protocol.  The cross-repo regression test
 * ``solslot-protocol/tests/test_v2_fixtures.py::test_mod_hash_is_a_known_constant``
 * pins the tree hash of this bytecode.  If the puzzle source changes,
 * regenerate via:
 *
 *     cd solslot-protocol
 *     bash scripts/dump_v2_puzzle_hex.sh
 *
 * which rewrites this file.
 */
export const ADMIN_AUTHORITY_V2_INNER_PUZZLE_HEX =
  '0x' +
HEADER

printf "  '%s';\n" "$HEX" >> "$DEST"

echo "wrote $DEST"
echo "  size: $SIZE_BYTES bytes ($(printf '%d' "${#HEX}") hex chars)"
