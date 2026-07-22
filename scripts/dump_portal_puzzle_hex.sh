#!/usr/bin/env bash
# Regenerate every active Solslot portal puzzle bundle from this checkout.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
PORTAL_ROOT="${SOLSLOT_PORTAL_ROOT:-$REPO_ROOT/../solslot-portal}"
PUZZLES_DIR="$REPO_ROOT/solslot_puzzles"

write_module() {
  local puzzle="$1"
  local export_name="$2"
  local relative_path="$3"
  local source="$PUZZLES_DIR/${puzzle}.clsp.hex"
  local destination="$PORTAL_ROOT/$relative_path"

  [[ -f "$source" ]] || {
    echo "missing compiled puzzle: $source" >&2
    exit 1
  }
  mkdir -p "$(dirname "$destination")"
  local hex
  hex="$(tr -d '[:space:]' < "$source")"
  cat > "$destination" <<EOF
/**
 * Generated from solslot-protocol/solslot_puzzles/${puzzle}.clsp.hex.
 * Do not edit by hand; run scripts/dump_portal_puzzle_hex.sh.
 */
export const ${export_name} =
  '0x' +
  '${hex}';
EOF
  echo "wrote $destination"
}

write_module admin_authority_v2_inner ADMIN_AUTHORITY_V2_INNER_PUZZLE_HEX \
  src/app/services/admin-authority-v2/admin-authority-v2.puzzle-hex.ts
write_module mint_offer_delegate MINT_OFFER_DELEGATE_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/mint-offer-delegate.puzzle-hex.ts
write_module mint_offer_delegate_v2 MINT_OFFER_DELEGATE_V2_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/mint-offer-delegate-v2.puzzle-hex.ts
write_module mint_proposal_inner_v2 MINT_PROPOSAL_INNER_V2_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/mint-proposal-v2.puzzle-hex.ts
write_module property_registry_inner PROPERTY_REGISTRY_INNER_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/property-registry-inner.puzzle-hex.ts
write_module quorum_did_inner QUORUM_DID_INNER_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/quorum-did-inner.puzzle-hex.ts
write_module purchase_payment PURCHASE_PAYMENT_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/purchase-payment.puzzle-hex.ts
write_module singleton_launcher_with_did SINGLETON_LAUNCHER_WITH_DID_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/singleton-launcher-with-did.puzzle-hex.ts
write_module smart_deed_inner_v2 SMART_DEED_INNER_PUZZLE_HEX \
  src/app/services/mint-proposal-v2/smart-deed-inner.puzzle-hex.ts
write_module p2_vault P2_VAULT_CURRENT_PUZZLE_HEX \
  src/app/services/p2-vault-current.puzzle-hex.ts
write_module p2_vault P2_VAULT_PUZZLE_HEX \
  src/app/services/p2-vault.puzzle-hex.ts
write_module pool_token_tail POOL_TOKEN_TAIL_PUZZLE_HEX \
  src/app/services/pool-token-tail.puzzle-hex.ts
write_module protocol_config_inner PROTOCOL_CONFIG_INNER_PUZZLE_HEX \
  src/app/services/protocol-config/protocol-config.puzzle-hex.ts
write_module sgt_tail SGT_TAIL_PUZZLE_HEX \
  src/app/services/sgt-driver/sgt-tail.puzzle-hex.ts
write_module sgt_free_inner SGT_FREE_INNER_PUZZLE_HEX \
  src/app/services/sgt-driver/sgt-free-inner.puzzle-hex.ts
write_module sgt_locked_inner SGT_LOCKED_INNER_PUZZLE_HEX \
  src/app/services/sgt-driver/sgt-locked-inner.puzzle-hex.ts
write_module governance_singleton_inner GOVERNANCE_TRACKER_INNER_PUZZLE_HEX \
  src/app/services/sgt-driver/governance-singleton-inner.puzzle-hex.ts
write_module vault_singleton_inner VAULT_CURRENT_INNER_PUZZLE_HEX \
  src/app/services/vault-current-inner.puzzle-hex.ts

vault_hex="$(tr -d '[:space:]' < "$PUZZLES_DIR/vault_singleton_inner.clsp.hex")"
bridge_hex="$(tr -d '[:space:]' < "$PUZZLES_DIR/zkpassport_bridge_message.clsp.hex")"
combined="$PORTAL_ROOT/src/app/services/zkpassport-vault-enrollment.puzzle-hex.ts"
cat > "$combined" <<EOF
/** Generated from the frozen Solslot protocol checkout. */
export const VAULT_SINGLETON_INNER_PUZZLE_HEX = '0x${vault_hex}';
export const ZKPASSPORT_BRIDGE_MESSAGE_PUZZLE_HEX = '0x${bridge_hex}';
EOF
echo "wrote $combined"
