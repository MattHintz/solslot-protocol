"""Integrity tests for the solslot_puzzles canonical set + frozen checksum.

These guard the exact failure mode that let commit c8eef7e (the vault EIP-712
chainId change to Base Sepolia) silently drift the compiled puzzles away from
``FROZEN_CHECKSUM`` without anyone noticing: any future puzzle change must be
accompanied by a refreeze, or ``test_frozen_checksum_matches_compiled_puzzles``
fails loudly in CI.
"""
from solslot_puzzles import (
    FROZEN_CHECKSUM,
    PUZZLE_FILENAMES,
    compute_puzzles_checksum,
    load_puzzle,
    verify_puzzle_checksum,
)


def test_frozen_checksum_matches_compiled_puzzles():
    """The committed puzzles must match FROZEN_CHECKSUM — refreeze on any change."""
    assert FROZEN_CHECKSUM is not None, "FROZEN_CHECKSUM must be pinned, not None"
    assert compute_puzzles_checksum() == FROZEN_CHECKSUM


def test_verify_puzzle_checksum_passes():
    """verify_puzzle_checksum() must not raise for the committed puzzle tree."""
    verify_puzzle_checksum()  # raises PuzzleIntegrityError on mismatch


def test_vault_version_registry_is_canonical_and_loadable():
    """The vault version registry singleton is part of the integrity-checked set."""
    assert "vault_version_registry_inner.clsp" in PUZZLE_FILENAMES
    mod = load_puzzle("vault_version_registry_inner.clsp")
    assert mod is not None
    # Deterministic tree hash across loads (cache + recompile agree).
    assert (
        mod.get_tree_hash()
        == load_puzzle("vault_version_registry_inner.clsp").get_tree_hash()
    )


def test_solslot_v2_pool_modules_are_canonical_and_loadable():
    for filename in (
        "pool_singleton_inner_v3.clsp",
        "smart_deed_inner_v2.clsp",
        "p2_pool_v2.clsp",
    ):
        assert filename in PUZZLE_FILENAMES
        assert load_puzzle(filename).get_tree_hash() is not None


def test_native_primary_purchase_module_is_canonical_and_loadable():
    filename = "mint_offer_delegate_v2.clsp"
    assert filename in PUZZLE_FILENAMES
    assert load_puzzle(filename).get_tree_hash() is not None


def test_no_duplicate_puzzle_filenames():
    """Canonical order must not contain duplicates (would double-count the checksum)."""
    assert len(PUZZLE_FILENAMES) == len(set(PUZZLE_FILENAMES))
