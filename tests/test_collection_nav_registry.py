from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

from populis_puzzles.collection_nav_registry_driver import (
    EMPTY_COLLECTION_NAV_ROOT,
    CollectionNavRegistryState,
    NAV_EVIDENCE_TAG,
    build_nav_update_spend,
    build_nav_read_evidence_spend,
    collection_nav_registry_inner_mod,
    collection_nav_registry_inner_mod_hash,
    collection_nav_root,
    compute_nav_evidence_message,
    compute_nav_message,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    parse_inner_puzzle,
    upsert_nav_entry,
)


GOV_PUBKEY = b"\x42" * 48


def b32(byte: int) -> bytes32:
    return bytes32(bytes([byte]) * 32)


def test_module_compiles():
    mod = load_clvm(
        "collection_nav_registry_inner.clsp",
        package_or_requirement="populis_puzzles",
        recompile=True,
    )
    assert mod is not None
    assert collection_nav_registry_inner_mod().get_tree_hash() == mod.get_tree_hash()


def test_empty_root_matches_driver_default():
    assert collection_nav_root([]) == EMPTY_COLLECTION_NAV_ROOT
    assert len(EMPTY_COLLECTION_NAV_ROOT) == 32


def test_upsert_adds_then_replaces_collection_nav():
    cid1 = b32(0xA1)
    cid2 = b32(0xA2)
    entries = upsert_nav_entry([], cid1, 1_000_000)
    assert entries == [(cid1, 1_000_000)]
    entries = upsert_nav_entry(entries, cid2, 2_000_000)
    assert entries == [(cid2, 2_000_000), (cid1, 1_000_000)]
    entries = upsert_nav_entry(entries, cid1, 3_000_000)
    assert entries == [(cid2, 2_000_000), (cid1, 3_000_000)]


def test_parse_round_trip():
    root = collection_nav_root([(b32(0xA1), 1_000_000)])
    puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=7, nav_root=root)
    state = parse_inner_puzzle(puzzle)
    assert state.self_mod_hash == collection_nav_registry_inner_mod_hash()
    assert state.gov_pubkey == GOV_PUBKEY
    assert state.collection_nav_root == root
    assert state.registry_version == 7


def test_distinct_roots_change_inner_hash():
    root1 = collection_nav_root([(b32(0xA1), 1_000_000)])
    root2 = collection_nav_root([(b32(0xA1), 2_000_000)])
    assert make_inner_puzzle_hash(GOV_PUBKEY, 1, root1) != make_inner_puzzle_hash(
        GOV_PUBKEY,
        1,
        root2,
    )


def test_build_nav_update_spend_matches_clvm_conditions():
    cid = b32(0xA1)
    state = CollectionNavRegistryState(
        self_mod_hash=collection_nav_registry_inner_mod_hash(),
        gov_pubkey=GOV_PUBKEY,
        collection_nav_root=EMPTY_COLLECTION_NAV_ROOT,
        registry_version=0,
    )
    artifacts = build_nav_update_spend(
        current=state,
        collection_id_canon=cid,
        nav_value_mojos=1_500_000_000,
        current_entries=[],
        my_amount=1,
    )

    puzzle = make_inner_puzzle(GOV_PUBKEY, 0, EMPTY_COLLECTION_NAV_ROOT)
    conditions = list(puzzle.run(artifacts.inner_solution).as_iter())

    assert len(conditions) == 4
    emitted_create = next(c for c in conditions if int(c.first().as_int()) == 51)
    assert bytes32(emitted_create.rest().first().as_atom()) == artifacts.new_inner_puzzle_hash

    emitted_announcement = next(c for c in conditions if int(c.first().as_int()) == 62)
    assert bytes(emitted_announcement.rest().first().as_atom()) == artifacts.announcement_message

    expected_message = compute_nav_message(
        cid,
        1_500_000_000,
        EMPTY_COLLECTION_NAV_ROOT,
        artifacts.new_collection_nav_root,
        1,
    )
    assert artifacts.signing_message == expected_message
    assert artifacts.announcement_message == b"\x50" + expected_message


def test_build_nav_read_evidence_spend_matches_clvm_conditions():
    cid = b32(0xA1)
    entries = [(cid, 1_500_000_000)]
    root = collection_nav_root(entries)
    state = CollectionNavRegistryState(
        self_mod_hash=collection_nav_registry_inner_mod_hash(),
        gov_pubkey=GOV_PUBKEY,
        collection_nav_root=root,
        registry_version=12,
    )
    artifacts = build_nav_read_evidence_spend(
        current=state,
        collection_id_canon=cid,
        current_entries=entries,
        my_amount=1,
    )

    puzzle = make_inner_puzzle(GOV_PUBKEY, 12, root)
    conditions = list(puzzle.run(artifacts.inner_solution).as_iter())

    assert len(conditions) == 3
    emitted_create = next(c for c in conditions if int(c.first().as_int()) == 51)
    assert bytes32(emitted_create.rest().first().as_atom()) == artifacts.inner_puzzle_hash

    emitted_announcement = next(c for c in conditions if int(c.first().as_int()) == 62)
    assert bytes(emitted_announcement.rest().first().as_atom()) == artifacts.announcement_message

    expected_message = compute_nav_evidence_message(
        cid,
        1_500_000_000,
        root,
        12,
    )
    assert artifacts.evidence_message == expected_message
    assert artifacts.announcement_message == b"\x50" + expected_message
    assert artifacts.evidence_message == bytes32(
        Program.to([NAV_EVIDENCE_TAG, cid, 1_500_000_000, root, 12]).get_tree_hash()
    )


def test_nav_read_evidence_rejects_absent_collection():
    cid = b32(0xA1)
    root = collection_nav_root([])
    state = CollectionNavRegistryState(
        self_mod_hash=collection_nav_registry_inner_mod_hash(),
        gov_pubkey=GOV_PUBKEY,
        collection_nav_root=root,
        registry_version=12,
    )
    with pytest.raises(ValueError, match="not present"):
        build_nav_read_evidence_spend(
            current=state,
            collection_id_canon=cid,
            current_entries=[],
            my_amount=1,
        )


def test_driver_rejects_duplicate_current_entries():
    with pytest.raises(ValueError, match="duplicate"):
        collection_nav_root([(b32(0xA1), 1), (b32(0xA1), 2)])
