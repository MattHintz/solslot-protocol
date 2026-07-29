"""Integrity tests for the solslot_puzzles canonical set + frozen checksum.

These guard the exact failure mode that let commit c8eef7e (the vault EIP-712
chainId change to Base Sepolia) silently drift the compiled puzzles away from
``FROZEN_CHECKSUM`` without anyone noticing: any future puzzle change must be
accompanied by a refreeze, or ``test_frozen_checksum_matches_compiled_puzzles``
fails loudly in CI.
"""
import hashlib
import json
from pathlib import Path
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
    for filename in (
        "mint_offer_delegate_v2.clsp",
        "mint_offer_delegate_v3.clsp",
        "mint_offer_delegate_v4.clsp",
    ):
        assert filename in PUZZLE_FILENAMES
        assert load_puzzle(filename).get_tree_hash() is not None


def test_no_duplicate_puzzle_filenames():
    """Canonical order must not contain duplicates (would double-count the checksum)."""
    assert len(PUZZLE_FILENAMES) == len(set(PUZZLE_FILENAMES))


def test_rc20_manifest_remains_a_complete_historical_freeze():
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "release-manifests"
        / "rc20-puzzle-hashes.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    preserved = manifest["preservedPuzzleHashes"]
    canonical_names = PUZZLE_FILENAMES[: len(preserved)]
    assert set(preserved) == set(canonical_names)
    checksum = hashlib.sha256()
    for filename in canonical_names:
        checksum.update(bytes.fromhex(preserved[filename]))
    assert checksum.hexdigest() == manifest["preservedCanonicalChecksum"]


def test_rc20_manifest_records_every_new_puzzle_hash():
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "release-manifests"
        / "rc20-puzzle-hashes.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    additions = manifest["newPuzzleHashes"]
    preserved_count = len(manifest["preservedPuzzleHashes"])
    assert tuple(additions) == PUZZLE_FILENAMES[
        preserved_count : preserved_count + len(additions)
    ]
    for filename, expected_hash in additions.items():
        assert bytes(load_puzzle(filename).get_tree_hash()).hex() == expected_hash


def test_rc22_manifest_records_every_replacement_and_additive_module():
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "release-manifests"
        / "rc22-puzzle-hashes.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rc20_manifest = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "release-manifests"
            / "rc20-puzzle-hashes.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["preservedCanonicalChecksum"] == rc20_manifest["canonicalChecksum"]
    replacements = manifest["changedPuzzleHashes"]
    assert set(replacements) == {"p2_pool_v2.clsp", "p2_vault.clsp"}
    assert set(manifest["changeReasons"]) == set(replacements)
    for filename, historical_hash in {
        **rc20_manifest["preservedPuzzleHashes"],
        **rc20_manifest["newPuzzleHashes"],
    }.items():
        expected_hash = replacements.get(filename, historical_hash)
        assert bytes(load_puzzle(filename).get_tree_hash()).hex() == expected_hash
    additions = manifest["newPuzzleHashes"]
    rc22_end = PUZZLE_FILENAMES.index("redemption_treasury_v1.clsp") + 1
    assert tuple(additions) == PUZZLE_FILENAMES[
        rc22_end - len(additions) : rc22_end
    ]
    for filename, expected_hash in additions.items():
        assert bytes(load_puzzle(filename).get_tree_hash()).hex() == expected_hash
    checksum = hashlib.sha256()
    for filename in PUZZLE_FILENAMES[:rc22_end]:
        checksum.update(bytes(load_puzzle(filename).get_tree_hash()))
    assert checksum.hexdigest() == manifest["canonicalChecksum"]


def test_rc23_manifest_preserves_rc22_and_records_authority_v3():
    manifest_path = (
        Path(__file__).resolve().parents[1]
        / "release-manifests"
        / "rc23-puzzle-hashes.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rc22_manifest = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "release-manifests"
            / "rc22-puzzle-hashes.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["preservedCanonicalChecksum"] == (
        rc22_manifest["canonicalChecksum"]
    )
    additions = manifest["newPuzzleHashes"]
    assert tuple(additions) == PUZZLE_FILENAMES[-len(additions) :]
    assert set(manifest["changeReasons"]) == set(additions)
    for filename, expected_hash in additions.items():
        assert bytes(load_puzzle(filename).get_tree_hash()).hex() == expected_hash
    assert compute_puzzles_checksum() == manifest["canonicalChecksum"]
