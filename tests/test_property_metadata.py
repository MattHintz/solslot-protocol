from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.property_metadata import (
    MAX_CANONICAL_METADATA_BYTES,
    MAX_MEMO_BYTES,
    MetadataCommitment,
    MetadataReference,
    MetadataValidationError,
    build_metadata_memos,
    build_metadata_reference_memo,
    canonicalize_json,
    commit_metadata,
    estimate_consensus_cost,
    parse_metadata_reference_memo,
    reconstruct_metadata_memos,
    validate_deed_allocation,
)
from solslot_puzzles.mint_proposal_v2_driver import compute_proposal_data_hash
from solslot_puzzles.mint_publish_driver import compute_proposal_hash_for_mint


FIXTURE_PATH = (
    Path(__file__).parents[1] / "fixtures" / "property-metadata-v1.fixture.json"
)


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_cross_language_fixture_is_current() -> None:
    fixture = _fixture()
    commitment = commit_metadata(fixture["dossier"])
    memos = build_metadata_memos(commitment)
    assert commitment.canonical_json.decode("utf-8") == fixture["canonicalJson"]
    assert "0x" + commitment.metadata_root.hex() == fixture["metadataRoot"]
    assert commitment.byte_size == fixture["canonicalByteSize"]
    assert ["0x" + memo.hex() for memo in memos] == fixture["memoHex"]


def test_jcs_orders_keys_by_utf16_and_rejects_ambiguous_numbers() -> None:
    assert canonicalize_json({"z": 1, "a": [True, None, "x"]}) == (
        b'{"a":[true,null,"x"],"z":1}'
    )
    with pytest.raises(MetadataValidationError, match="floating-point"):
        canonicalize_json({"amount": 1.25})
    with pytest.raises(MetadataValidationError, match="safe range"):
        canonicalize_json({"amount": 1 << 53})


def test_allocation_requires_unique_ids_and_exact_total() -> None:
    valid = _fixture()["dossier"]["deedAllocation"]
    validate_deed_allocation(valid)

    duplicate = copy.deepcopy(valid)
    duplicate[1]["deedId"] = duplicate[0]["deedId"].lower()
    with pytest.raises(MetadataValidationError, match="duplicate"):
        validate_deed_allocation(duplicate)

    wrong_total = copy.deepcopy(valid)
    wrong_total[1]["sharePpm"] = 399999
    with pytest.raises(MetadataValidationError, match="totals"):
        validate_deed_allocation(wrong_total)


def test_memo_round_trip_and_integrity_failures() -> None:
    commitment = commit_metadata(_fixture()["dossier"])
    memos = list(build_metadata_memos(commitment))
    assert all(len(memo) <= MAX_MEMO_BYTES for memo in memos)
    assert reconstruct_metadata_memos(memos) == commitment

    with pytest.raises(MetadataValidationError, match="chunk count"):
        reconstruct_metadata_memos(memos[:-1])

    reordered = [memos[0], memos[2], memos[1], *memos[3:]]
    with pytest.raises(MetadataValidationError, match="reordered"):
        reconstruct_metadata_memos(reordered)

    altered = list(memos)
    altered[-1] = altered[-1][:-1] + bytes([altered[-1][-1] ^ 1])
    with pytest.raises(MetadataValidationError, match="root mismatch"):
        reconstruct_metadata_memos(altered)


def test_metadata_cap_and_cost_estimate() -> None:
    oversized = MetadataCommitment(
        canonical_json=b"x" * (MAX_CANONICAL_METADATA_BYTES + 1),
        metadata_root=bytes32(b"r" * 32),
    )
    with pytest.raises(MetadataValidationError, match="exceeds"):
        build_metadata_memos(oversized)
    assert estimate_consensus_cost(1024) == 12_288_000


def test_reference_memo_round_trip() -> None:
    reference = MetadataReference(
        metadata_root=bytes32(b"r" * 32),
        metadata_anchor_id=bytes32(b"a" * 32),
    )
    assert parse_metadata_reference_memo(build_metadata_reference_memo(reference)) == reference


def test_extended_mint_commitments_match_cross_language_fixture() -> None:
    fixture = _fixture()
    vector = fixture["mintVector"]
    inputs = vector["inputs"]
    root = bytes32.from_hexstr(fixture["metadataRoot"])
    anchor = bytes32.from_hexstr(inputs["metadataAnchorId"])
    proposal_data_hash = compute_proposal_data_hash(
        property_id_canon=bytes32.from_hexstr(inputs["propertyIdCanon"]),
        collection_id_canon=bytes32.from_hexstr(inputs["collectionIdCanon"]),
        share_ppm=inputs["sharePpm"],
        par_value_mojos=int(inputs["parValueMojos"]),
        royalty_bps=inputs["royaltyBps"],
        quorum_threshold=inputs["quorumThreshold"],
        metadata_root=root,
        metadata_anchor_id=anchor,
    )
    proposal_hash = compute_proposal_hash_for_mint(
        deed_full_puzhash=bytes32.from_hexstr(inputs["deedFullPuzhash"]),
        property_id_canon=bytes32.from_hexstr(inputs["propertyIdCanon"]),
        property_registry_puzzle_hash=bytes32.from_hexstr(
            inputs["propertyRegistryPuzhash"]
        ),
        metadata_root=root,
        metadata_anchor_id=anchor,
    )
    assert "0x" + proposal_data_hash.hex() == vector["expected"]["proposalDataHash"]
    assert "0x" + proposal_hash.hex() == vector["expected"]["billProgramHash"]


def test_extended_commitments_require_root_and_anchor_together() -> None:
    with pytest.raises(ValueError, match="supplied together"):
        compute_proposal_data_hash(
            property_id_canon=bytes32(b"p" * 32),
            collection_id_canon=bytes32(b"c" * 32),
            share_ppm=1_000_000,
            par_value_mojos=1,
            royalty_bps=0,
            quorum_threshold=1,
            metadata_root=bytes32(b"r" * 32),
        )
