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
    # version source: VAULT_INNER_MOD_HASH + CANONICAL_PARAMS_HASH + monotonic
    # VAULT_VERSION, with two publish paths (admin_authority_v2 params-only
    # fast-track / SGT-tracker routine).  See
    # research/SOLSLOT_VAULT_UPGRADE_DESIGN.md and the puzzle docstring.
    "vault_version_registry_inner.clsp",
)

# ── Frozen checksum — update after every intentional puzzle change ──
# Set to None to skip verification (development mode).
# Generate with: python -c "from solslot_puzzles import compute_puzzles_checksum; print(compute_puzzles_checksum())"
FROZEN_CHECKSUM: Optional[str] = (
    # 2026-07-18 PA4 exact admin authority version increments +
    # PA6 settlement target binding + PA13 SmartDeed pool-identity freeze:
    #   - announcement namespace 0x53;
    #   - SGT governance modules;
    #   - commitment-bound SmartDeed and p2_pool custody;
    #   - SmartDeed deposit/redeem authorization binds sanctioned pool launcher
    #     identity in curry, not spend solution;
    #   - settlement CLAIM requires both p2_pool_v2 burn proof and a
    #     pool coin announcement binding the governance-approved payout target;
    #   - admin authority V2 requires every spend to advance AUTHORITY_VERSION
    #     by exactly one step;
    #   - pool V3 with retired exits disabled and governance identity pinned;
    #   - Solslot V2 vault and credential domains;
    #   - five-spend governance/DID/registry/proposal/deed mint execution;
    #   - no retired contract implementations in the canonical package.
    "15b1f9972139dd9823f043e83741ce7d38eb9717d3e9abcccd6e6a4451c7ac19"
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
