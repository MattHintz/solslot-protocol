"""Populis Protocol puzzle loader with integrity verification.

Compiles .clsp files on first access and caches them. Provides a SHA256
checksum over all compiled puzzle tree hashes so that downstream code can
detect accidental or malicious corruption of the deployed puzzles.

Usage:
    from populis_puzzles import load_puzzle, verify_puzzle_checksum

    pool_mod = load_puzzle("pool_singleton_inner.clsp")
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
    "smart_deed_inner.clsp",
    "vault_singleton_inner.clsp",
    "p2_vault.clsp",
    "p2_pool.clsp",
    "pool_token_tail.clsp",
    "pool_singleton_inner.clsp",
    "governance_singleton_inner.clsp",
    "quorum_did_inner.clsp",
    "mint_offer_delegate.clsp",
    "purchase_payment.clsp",
    "p2_deed_settlement.clsp",
    "pgt_tail.clsp",
    "pgt_free_inner.clsp",
    "pgt_locked_inner.clsp",
    # A.3 — protocol_config singleton, replaces 3 off-chain env-var trust roots.
    "protocol_config_inner.clsp",
    # A.2 — admin_authority singleton, replaces POPULIS_ADMIN_PUBKEY_ALLOWLIST
    # + JWT secret with m-of-n quorum on-chain rotation.
    "admin_authority_inner.clsp",
    # A.2 v2 — MIPS-based admin_authority. Per-admin OneOfN bundles let admins
    # mix BLS / EIP-712 / passkey / etc. in the same quorum, and add/remove
    # auth methods over time with cooldown-based defence-in-depth. See
    # research/POPULIS_ADMIN_AUTHORITY_V2_DESIGN.md. Currently implements the
    # SKELETON + OPERATIONAL spend (tag 0x01); KEY_ADD_* / KEY_REMOVE_* land
    # in C.2b/C.2c.
    "admin_authority_v2_inner.clsp",
    # A.4 — property_registry singleton; uniqueness-enforced on-chain log of
    # registered property ids.
    "property_registry_inner.clsp",
    # Pool Economic V2 — governed collection NAV registry.  This is the
    # on-chain appraisal source used by NAV-based deed swap/redemption quotes.
    "collection_nav_registry_inner.clsp",
    # A.1 — mint_proposal singleton; per-proposal state machine
    # (DRAFT → APPROVED → CANCELLED) replacing MintProposalStore.
    "mint_proposal_inner.clsp",
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
    # fast-track / PGT-tracker routine).  See
    # research/POPULIS_VAULT_UPGRADE_DESIGN.md and the puzzle docstring.
    "vault_version_registry_inner.clsp",
)

# ── Frozen checksum — update after every intentional puzzle change ──
# Set to None to skip verification (development mode).
# Generate with: python -c "from populis_puzzles import compute_puzzles_checksum; print(compute_puzzles_checksum())"
# Refrozen after the POP-CANON-017 + POP-CANON-018 hardening landed:
#   - admin_authority_inner: added all-bls-g1-pubkeys + has-no-duplicates
#     guards against ALLOWLIST and new_allowlist.
#   - mint_proposal_inner: added is-size-bls-g1 guards on OWNER_PUBKEY
#     and GOV_PUBKEY.
#   - protocol_config_inner: added is-size-bls-g1 guard on GOV_PUBKEY.
#   - property_registry_inner: added is-size-bls-g1 guard on GOV_PUBKEY.
# All four A.x puzzles' mod hashes therefore changed; the new values
# are pinned in the corresponding driver caches and API singletons.py.
FROZEN_CHECKSUM: Optional[str] = (
    # 2026-07-02: refrozen for pool_token_tail CAT2 invocation compatibility.
    #   - pool_token_tail.clsp now accepts the canonical CAT2 TAIL invocation
    #     shape and unpacks the Populis mint/melt authorization payload from
    #     tail_solution, while retaining the direct five-field test fixture
    #     path.  This lets real CAT spends replay the pool-token TAIL.
    # 2026-07-01: refrozen for fully curried Pool Economic V2 state.
    #   - pool_singleton_inner.clsp now curries TOTAL_POOL_TOKEN_SUPPLY and
    #     TREASURY_RESERVE_TOKENS alongside status, NAV/TVL, and deed count.
    #     Deposit/redeem/swap/redemption/acquisition state recreation hashes
    #     commit supply/reserve transitions directly instead of trusting
    #     caller-supplied solution fields.
    # 2026-07-01: refrozen for Pool Economic V2 reserve acquisition branch.
    #   - pool_singleton_inner.clsp added POOL_SPEND_V2_RESERVE_ACQUISITION,
    #     which asserts governed NAV evidence, smart-deed collection/share
    #     deposit evidence, a fixed seller reserve-payment assertion, optional
    #     fresh-mint shortfall authorization, and bounded payment fanout.
    # 2026-07-01: refrozen for Pool Economic V2 specific-deed swap branch.
    #   - pool_singleton_inner.clsp added POOL_SPEND_V2_SPECIFIC_DEED_SWAP,
    #     which asserts governed NAV evidence, smart-deed collection/share
    #     release evidence, CAT settlement payment fanout, 0.3% protocol fee,
    #     0.7% PGT rewards-root fee, and treasury-reserve principal lockup.
    # 2026-06-30: refrozen for Pool Economic V2 true-redemption branch.
    #   - pool_singleton_inner.clsp added POOL_SPEND_V2_TRUE_REDEMPTION,
    #     which asserts governed NAV evidence, smart-deed collection/share
    #     metadata, pool-token CAT melt authorization, and recreates the pool
    #     with NAV/deed-count decremented.
    # 2026-06-30: refrozen for Pool Economic V2 NAV read evidence.
    #   - collection_nav_registry_inner.clsp now supports no-op current-version
    #     read spends that recreate the registry unchanged and emit
    #     PROTOCOL_PREFIX || sha256tree(NAVE collection nav root version), so
    #     pool swap/redemption spends can assert governed on-chain NAV evidence.
    # 2026-06-30: refrozen for Pool Economic V2 smart-deed metadata binding.
    #   - smart_deed_inner.clsp now curries collection_id_canon and share_ppm
    #     and includes them in deed deposit/redeem announcements.
    # 2026-06-30: refrozen for Pool Economic V2 NAV registry introduction.
    #   - collection_nav_registry_inner.clsp added to PUZZLE_FILENAMES as the
    #     governed on-chain collection NAV source for deed swap/redemption
    #     pricing.
    # 2026-06-29: refrozen for A4 property registry uniqueness hardening.
    #   - property_registry_inner.clsp now curries REGISTERED_IDS_ROOT and
    #     requires each registration spend to supply the full current
    #     registered-id list as a non-membership witness.
    #   - The recreated singleton carries
    #     sha256tree((property_id_canon . registered_ids)), so duplicate
    #     registry entries are consensus-impossible in the A.4 registry.
    # 2026-06-29: refrozen for governance settlement release-set binding.
    #   - governance_singleton_inner.clsp SETTLE bills now carry
    #     deed_releases_hash = sha256tree(deed_releases), and EXECUTE emits the
    #     pool message over (SETT splitxch_root amount count releases_hash).
    #   - pool_singleton_inner.clsp settlement spends recompute that hash from
    #     the provided release list and require the matching governance message,
    #     so count-only settlement approval can no longer authorize a different
    #     release set.
    # 2026-06-29: refrozen for SOR-1 / p2_deed_settlement burn hardening.
    #   - p2_deed_settlement.clsp no longer curries BURN_INNER_PUZHASH as
    #     external setup meaning.  The settlement burn destination is now the
    #     canonical all-zero inner puzzle hash inside the puzzle itself, so
    #     settlement leaves cannot redefine what "burned deed" means.
    # 2026-06-21: refrozen for the governance vault-version bill (Brick 3.5a).
    #   - governance_singleton_inner.clsp gained the BILL_VAULT_VERSION ('V')
    #     dispatch branch: EXECUTE of a vault-version bill emits the routine-path
    #     CREATE_PUZZLE_ANNOUNCEMENT the vault_version_registry SPEND_CODE_ROUTINE
    #     asserts (PROTOCOL_PREFIX || REGISTRY_TAG_ROUTINE || content_hash), so its
    #     mod hash changed.  Only this one puzzle changed in this freeze.
    # 2026-06-16: refrozen for the vault-upgrade feature.  This value also
    # absorbs a previously-unfrozen *committed* change — c8eef7e
    # (eip712: vault chainId -> Base Sepolia 84532) changed
    # vault_singleton_inner's mod hash but did not refreeze — so the frozen
    # value had silently drifted from the committed puzzles.  Deltas since the
    # prior freeze (c75bdcf):
    #   - c8eef7e: vault EIP-712 chainId updated to Base Sepolia (84532).
    #   - ceb141a: vault_singleton_inner gained the 'm' (migrate) spend case
    #     for the vault upgrade flow (research/POPULIS_VAULT_UPGRADE_DESIGN.md).
    #   - vault_version_registry_inner.clsp added to PUZZLE_FILENAMES.
    "ae78630b16ca47f8317e73e13110a8265841b61238fabf28233b81e15fe8e554"
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
            package_or_requirement="populis_puzzles",
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
