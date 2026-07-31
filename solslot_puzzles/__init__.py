"""Solslot Protocol puzzle loader with integrity verification.

Compiles .clsp files on first access and caches them. Provides a SHA256
checksum over all compiled puzzle tree hashes so that downstream code can
detect accidental or malicious corruption of the deployed puzzles.

Usage:
    from solslot_puzzles import load_puzzle, verify_puzzle_checksum

    pool_mod = load_puzzle("pool_singleton_inner_v3.clsp")
    verify_puzzle_checksum()  # raises PuzzleIntegrityError on mismatch
"""
from __future__ import annotations

import hashlib
import logging
from typing import Dict, Optional

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm

logger = logging.getLogger(__name__)

# ── All contract filenames in canonical order (determines checksum) ──
PUZZLE_FILENAMES = (
    "singleton_launcher_with_did.clsp",
    "smart_deed_inner_v2.clsp",
    "vault_singleton_inner.clsp",
    "p2_vault.clsp",
    "p2_pool_v2.clsp",
    "pool_token_tail.clsp",
    "pool_singleton_inner_v3.clsp",
    "governance_singleton_inner.clsp",
    "quorum_did_inner.clsp",
    "mint_offer_delegate.clsp",
    "mint_offer_delegate_v2.clsp",
    "purchase_payment.clsp",
    "p2_deed_settlement.clsp",
    "sgt_tail.clsp",
    "sgt_free_inner.clsp",
    "sgt_locked_inner.clsp",
    # A.3 — protocol_config singleton, replaces 3 off-chain env-var trust roots.
    "protocol_config_inner.clsp",
    # A.2 v2 — MIPS-based admin_authority. Per-admin OneOfN bundles let admins
    # mix BLS / EIP-712 / passkey / etc. in the same quorum, and add/remove
    # auth methods over time with cooldown-based defence-in-depth. See
    # research/SOLSLOT_ADMIN_AUTHORITY_V2_DESIGN.md. Currently implements the
    # SKELETON + OPERATIONAL spend (tag 0x01); KEY_ADD_* / KEY_REMOVE_* land
    # in C.2b/C.2c.
    "admin_authority_v2_inner.clsp",
    # A.4 — property_registry singleton; uniqueness-enforced on-chain log of
    # registered property ids.
    "property_registry_inner.clsp",
    # Pool Economic V2 — governed collection NAV registry.  This is the
    # on-chain appraisal source used by NAV-based deed swap/redemption quotes.
    "collection_nav_registry_inner.clsp",
    # A.1 v2 — MIPS-pluggable mint_proposal singleton.  Replaces the
    # hard-coded BLS OWNER_PUBKEY / GOV_PUBKEY of v1 with curried
    # CHIP-0043 member tree hashes so a single deployment can mix BLS
    # / Eip712Member (EVM) / passkey / etc. member types freely.
    # State machine semantics unchanged from v1; auth surface is the
    # only refactor.  See research/PHASE_9_HERMES_D_SESSION_SUMMARY.md
    # and the puzzle docstring for the binding-hash construction that
    # blocks signature replay across transitions / proposals.
    "mint_proposal_inner_v2.clsp",
    "zkpassport_bridge_message.clsp",
    # Vault upgrade — vault_version_registry singleton.  On-chain canonical vault
    # version source: VAULT_INNER_MOD_HASH + CANONICAL_PARAMS_HASH +
    # exact-incrementing
    # VAULT_VERSION, with two publish paths (admin_authority_v2 params-only
    # fast-track / SGT-tracker routine).  See
    # research/SOLSLOT_VAULT_UPGRADE_DESIGN.md and the puzzle docstring.
    "vault_version_registry_inner.clsp",
    "voucher_presale_series_v1.clsp",
    "voucher_nft_inner_v1.clsp",
    # RC20 refundable presale. These are additive modules; RC19 puzzle bytes
    # remain frozen and their individual hashes are asserted by release tests.
    "voucher_burn_v2.clsp",
    "voucher_presale_series_v2.clsp",
    "voucher_nft_inner_v2.clsp",
    "voucher_payment_escrow_v2.clsp",
    "voucher_external_escrow_receipt_v2.clsp",
    "voucher_base_result_authorization_v2.clsp",
    "voucher_purchase_launcher_v2.clsp",
    "mint_offer_delegate_v3.clsp",
    "mint_offer_delegate_v4.clsp",
    # RC22 Sols economics. RC20 bytes remain frozen; the new proposal tracker
    # adds typed statute bills and the unified statutes singleton replaces
    # mutable BLS-key parameter/NAV publication for fresh genesis only.
    "governance_singleton_inner_v2.clsp",
    "protocol_statutes_inner_v1.clsp",
    # RC22 protocol-only Sols market. The vault authorizes one exact
    # zkPassport-bound operation and Pool V4 enforces both exchange directions.
    "vault_singleton_inner_v2.clsp",
    "pool_singleton_inner_v4.clsp",
    # Governed funded redemption. Each wUSDC.b leaf is a permanent standard
    # offer for one exact SmartDeed and has no withdrawal or timeout path.
    "p2_deed_redemption_v1.clsp",
    "redemption_treasury_v1.clsp",
    # RC23 recovery-aware authority. The roster is three immutable identity
    # singleton launcher ids; key rotations happen behind those identities
    # and one pending intent freezes every privileged operation.
    "admin_authority_v3_inner.clsp",
    "admin_authority_action_v1.clsp",
    "admin_identity_action_v1.clsp",
    "admin_identity_terminal_action_v1.clsp",
    "admin_identity_prepare_announcement_v1.clsp",
    "eip712_member_v2.clsp",
    # RC24 external-payment settlement. Stripe state is independently
    # authenticated by the configured 2-of-3 validators before a one-mojo
    # receipt can atomically deliver the exact governed deed to its vault.
    "stripe_settlement_receipt_v1.clsp",
    "mint_offer_inventory_available_v1.clsp",
    "mint_offer_delegate_v5.clsp",
    # Stripe presales reuse the frozen RC20 series and launcher. These two
    # additive puzzles bind the nontransferable voucher and its terminal
    # validator-authenticated Stripe receipt without exposing a PaymentIntent.
    "voucher_nft_inner_v3.clsp",
    "voucher_stripe_receipt_v1.clsp",
)

# ── Frozen checksum — update after every intentional puzzle change ──
# Set to None to skip verification (development mode).
# Generate with: python -c "from solslot_puzzles import compute_puzzles_checksum; print(compute_puzzles_checksum())"
FROZEN_CHECKSUM: Optional[str] = (
    # RC22 appends the typed SGT-governance tracker and unified statutes
    # singleton. Its release manifest explicitly records the p2_vault and
    # p2_pool_v2 replacements plus the final Pool V4 and vault V2 hashes.
    # RC20 preserves every RC19 module byte-for-byte and appends the strictly
    # bound refundable voucher series, non-transferable voucher singleton,
    # XCH escrow, external escrow receipt, chain-authorized Base result handoff,
    # atomic issuance launcher, and voucher-bound primary deed settlement
    # delegates.
    # RC19 includes 2026-07-19 PA16 exact version increments for protocol_config and
    # vault_version_registry + PA3 governance PROPOSE bill-tag whitelist +
    # 2026-07-18 PA17 live acquisition KYC pairing +
    # PA2 operation-bound admin member signatures + PA4 exact admin authority
    # version increments + PA6 settlement target binding + PA13 SmartDeed
    # pool-identity freeze:
    #   - announcement namespace 0x53;
    #   - SGT governance modules;
    #   - commitment-bound SmartDeed and p2_pool custody;
    #   - SmartDeed deposit/redeem authorization binds sanctioned pool launcher
    #     identity in curry, not spend solution;
    #   - governance PROPOSE rejects unknown bill tags before a malformed bill
    #     can enter the OPEN state and later deadlock EXECUTE/EXPIRE;
    #   - settlement CLAIM requires both p2_pool_v2 burn proof and a
    #     pool coin announcement binding the governance-approved payout target;
    #   - admin authority KEY_* member approvals prepend the canonical key
    #     operation hash before running each member puzzle;
    #   - admin authority V2 requires every spend to advance AUTHORITY_VERSION
    #     by exactly one step;
    #   - protocol_config and vault_version_registry require exact one-step
    #     version increments to prevent authority-signed self-bricks;
    #   - pool V3 with retired exits disabled and governance identity pinned;
    #   - pool V3 case-6 deed acquisition requires a canonical enrolled buyer
    #     vault authorization under the trusted zkPassport bridge policy;
    #   - Solslot V2 vault and credential domains;
    #   - five-spend governance/DID/registry/proposal/deed mint execution;
    #   - RC17 MINT EXECUTE requires the immutable, dedicated KoS co-signer
    #     public key to sign the governance singleton/proposal commitment;
    #   - no retired contract implementations in the canonical package;
    #   - RC19 native XCH/CAT primary purchases use a dedicated on-demand
    #     offer delegate that binds one exact deed to one canonical vault and
    #     exposes no standalone external-payment escrow branch.
    # RC24 appends validator-authenticated direct Stripe settlement, exact deed
    # reservation, and a refundable Stripe voucher that reuses the frozen RC20
    # series. RC23 bytes remain frozen in its manifest.
    "6a4e0c968febd112bb5acfb6a61890c56ad8ff07d92ac60feba9f256ff3b6f53"
)

# ── Cache ──
_puzzle_cache: Dict[str, Program] = {}


class PuzzleIntegrityError(Exception):
    """Raised when compiled puzzle checksums do not match the frozen value."""
    pass


def load_puzzle(filename: str) -> Program:
    """Load and cache a compiled Chialisp puzzle by filename."""
    if filename not in _puzzle_cache:
        _puzzle_cache[filename] = load_clvm(
            filename,
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _puzzle_cache[filename]


def compute_puzzles_checksum() -> str:
    """Compute a SHA256 checksum over all puzzle tree hashes in canonical order.

    Returns the hex-encoded digest string.
    """
    h = hashlib.sha256()
    for filename in PUZZLE_FILENAMES:
        mod = load_puzzle(filename)
        h.update(bytes(mod.get_tree_hash()))
    return h.hexdigest()


def verify_puzzle_checksum() -> None:
    """Verify compiled puzzles against the frozen checksum.

    Raises PuzzleIntegrityError if the checksums do not match.
    Does nothing if FROZEN_CHECKSUM is None (development mode).
    """
    if FROZEN_CHECKSUM is None:
        logger.debug("Puzzle integrity check skipped (FROZEN_CHECKSUM is None)")
        return

    actual = compute_puzzles_checksum()
    if actual != FROZEN_CHECKSUM:
        raise PuzzleIntegrityError(
            f"Puzzle integrity check failed!\n"
            f"  Expected: {FROZEN_CHECKSUM}\n"
            f"  Actual:   {actual}\n"
            f"  This may indicate corrupted or tampered puzzle files."
        )
    logger.debug("Puzzle integrity check passed: %s", actual)
