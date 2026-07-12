"""Tests for property_registry_inner.clsp and property_registry_driver.py.

Append-only on-chain log of registered Solslot property identifiers.
This file exhaustively exercises:

  * Module compilation + tree-hash stability (regression guard).
  * Canonicalisation of human property ids (off-chain ↔ on-chain contract).
  * Signing-message determinism + replay-binding.
  * Inner-puzzle round-trip (curry → parse).
  * Registration spend conditions (count, types, message body).
  * Replay protection (Python + CLVM both reject version skips).
  * Input validation (short pubkeys, even amount, malformed property ids).
"""
from __future__ import annotations

import hashlib
import re

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.property_registry_driver import (
    EMPTY_REGISTERED_IDS_ROOT,
    PropertyRegistryState,
    build_registration_coin_spend,
    build_registration_spend,
    canonicalise_property_id,
    compute_signing_message,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    parse_inner_puzzle,
    property_registry_inner_mod,
    property_registry_inner_mod_hash,
    registration_announcement_id,
    registration_announcement_message,
    registered_ids_root,
)


GOV_PUBKEY = b"\x42" * 48
OTHER_GOV = b"\x99" * 48


# ── Compilation ─────────────────────────────────────────────────────────


class TestCompile:
    def test_module_compiles(self):
        mod = load_clvm(
            "property_registry_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None

    def test_mod_hash_stable_across_calls(self):
        h1 = property_registry_inner_mod_hash()
        h2 = property_registry_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32


# ── Canonicalisation ────────────────────────────────────────────────────


class TestCanonicalise:
    def test_returns_bytes32(self):
        out = canonicalise_property_id("PROP-001")
        assert isinstance(out, bytes)
        assert len(out) == 32

    def test_strip_whitespace(self):
        a = canonicalise_property_id("  PROP-001  ")
        b = canonicalise_property_id("PROP-001")
        assert a == b

    def test_uppercase_normalisation(self):
        a = canonicalise_property_id("prop-001")
        b = canonicalise_property_id("PROP-001")
        assert a == b

    def test_distinct_inputs_yield_distinct_hashes(self):
        a = canonicalise_property_id("PROP-001")
        b = canonicalise_property_id("PROP-002")
        assert a != b

    def test_unicode_stable(self):
        # Determinism across multiple calls with same input.
        a = canonicalise_property_id("ÜNI-CØDE")
        b = canonicalise_property_id("ÜNI-CØDE")
        assert a == b

    def test_rejects_empty_after_strip(self):
        with pytest.raises(ValueError, match="non-empty"):
            canonicalise_property_id("   ")


# ── Signing message ─────────────────────────────────────────────────────


class TestSigningMessage:
    def test_determinism(self):
        pid = canonicalise_property_id("PROP-1")
        new_root = registered_ids_root([pid])
        m1 = compute_signing_message(pid, EMPTY_REGISTERED_IDS_ROOT, new_root, 1)
        m2 = compute_signing_message(pid, EMPTY_REGISTERED_IDS_ROOT, new_root, 1)
        assert m1 == m2

    def test_property_id_sensitivity(self):
        pid1 = canonicalise_property_id("PROP-1")
        pid2 = canonicalise_property_id("PROP-2")
        m1 = compute_signing_message(pid1, EMPTY_REGISTERED_IDS_ROOT, registered_ids_root([pid1]), 1)
        m2 = compute_signing_message(pid2, EMPTY_REGISTERED_IDS_ROOT, registered_ids_root([pid2]), 1)
        assert m1 != m2

    def test_version_sensitivity(self):
        pid = canonicalise_property_id("PROP-1")
        root1 = registered_ids_root([pid])
        root2 = registered_ids_root([canonicalise_property_id("PROP-2"), pid])
        m1 = compute_signing_message(pid, EMPTY_REGISTERED_IDS_ROOT, root1, 1)
        m2 = compute_signing_message(pid, root1, root2, 2)
        assert m1 != m2

    def test_root_sensitivity(self):
        pid = canonicalise_property_id("PROP-1")
        other = canonicalise_property_id("PROP-0")
        m1 = compute_signing_message(pid, EMPTY_REGISTERED_IDS_ROOT, registered_ids_root([pid]), 1)
        m2 = compute_signing_message(pid, registered_ids_root([other]), registered_ids_root([pid, other]), 2)
        assert m1 != m2


# ── Inner puzzle construction + parsing ─────────────────────────────────


class TestParse:
    def test_round_trip(self):
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        state = parse_inner_puzzle(puzzle)
        assert state.gov_pubkey == GOV_PUBKEY
        assert state.registry_version == 5
        assert state.registered_ids_root == EMPTY_REGISTERED_IDS_ROOT
        assert state.self_mod_hash == property_registry_inner_mod_hash()

    def test_distinct_states_yield_distinct_puzhashes(self):
        a = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=0)
        b = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=1)
        assert a != b

    def test_distinct_roots_yield_distinct_puzhashes(self):
        pid = canonicalise_property_id("PROP-1")
        a = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=0)
        b = make_inner_puzzle_hash(
            GOV_PUBKEY,
            registry_version=1,
            registered_ids_root=registered_ids_root([pid]),
        )
        assert a != b

    def test_distinct_govs_yield_distinct_puzhashes(self):
        a = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=0)
        b = make_inner_puzzle_hash(OTHER_GOV, registry_version=0)
        assert a != b

    def test_parse_rejects_wrong_module(self):
        bogus = Program.to(1).curry(b"\x00" * 32, GOV_PUBKEY, 0)
        with pytest.raises(ValueError, match="property_registry_inner"):
            parse_inner_puzzle(bogus)

    def test_parse_rejects_non_curried(self):
        # Bare program with no currying — uncurry yields None or the
        # mod-hash mismatch path (both indicate "not parseable").
        with pytest.raises(ValueError, match="(?:not curried|property_registry_inner)"):
            parse_inner_puzzle(Program.to(1))


# ── Construction validation ─────────────────────────────────────────────


class TestConstruction:
    def test_make_inner_puzzle_rejects_short_pubkey(self):
        with pytest.raises(ValueError, match="48 bytes"):
            make_inner_puzzle(b"\x00" * 32, registry_version=0)

    def test_make_inner_puzzle_rejects_negative_version(self):
        with pytest.raises(ValueError, match="≥ 0"):
            make_inner_puzzle(GOV_PUBKEY, registry_version=-1)


# ── Registration spend ──────────────────────────────────────────────────


class TestRegistrationSpend:
    @pytest.fixture
    def state(self):
        return PropertyRegistryState(
            self_mod_hash=property_registry_inner_mod_hash(),
            gov_pubkey=GOV_PUBKEY,
            registered_ids_root=EMPTY_REGISTERED_IDS_ROOT,
            registry_version=0,
        )

    def test_emits_correct_condition_count(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        result = puzzle.run(artifacts.inner_solution)
        conditions = list(result.as_iter())
        # AGG_SIG_ME + CREATE_COIN + CREATE_PUZZLE_ANNOUNCEMENT + ASSERT_MY_AMOUNT
        assert len(conditions) == 4

    def test_agg_sig_me_present(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # AGG_SIG_ME = 50 in chia condition codes.
        agg_sig_me = next((c for c in conditions if int(c.first().as_int()) == 50), None)
        assert agg_sig_me is not None
        sig_pubkey = bytes(agg_sig_me.rest().first().as_atom())
        assert sig_pubkey == GOV_PUBKEY

    def test_create_coin_recreates_self_with_bumped_version(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # CREATE_COIN = 51.
        create_coin = next((c for c in conditions if int(c.first().as_int()) == 51), None)
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        expected = artifacts.new_inner_puzzle_hash
        assert emitted_puzhash == expected

    def test_create_coin_recreates_self_with_new_registered_ids_root(self, state):
        pid = canonicalise_property_id("PROP-1")
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=pid,
            my_amount=1,
        )
        expected = make_inner_puzzle_hash(
            GOV_PUBKEY,
            registry_version=1,
            registered_ids_root=registered_ids_root([pid]),
        )
        assert artifacts.new_registered_ids_root == registered_ids_root([pid])
        assert artifacts.new_inner_puzzle_hash == expected

    def test_create_puzzle_announcement_carries_property_id(self, state):
        pid = canonicalise_property_id("PROP-1")
        artifacts = build_registration_spend(
            current=state, property_id_canon=pid, my_amount=1
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # CREATE_PUZZLE_ANNOUNCEMENT = 62.
        ann = next((c for c in conditions if int(c.first().as_int()) == 62), None)
        assert ann is not None
        ann_msg = bytes(ann.rest().first().as_atom())
        # Body = PROTOCOL_PREFIX (0x53) || property_id_canon.
        assert ann_msg == b"\x53" + bytes(pid)
        # Driver should publish the same bytes.
        assert artifacts.announcement_message == ann_msg

    def test_registration_announcement_id_matches_chia_formula(self, state):
        pid = canonicalise_property_id("PROP-1")
        inner = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        launcher_id = bytes32(b"\x9a" * 32)
        full_ph = bytes32(puzzle_for_singleton(launcher_id, inner).get_tree_hash())

        assert registration_announcement_message(pid) == b"\x53" + bytes(pid)
        assert registration_announcement_id(full_ph, pid) == bytes32(
            hashlib.sha256(full_ph + b"\x53" + bytes(pid)).digest()
        )

    def test_full_registration_coin_spend_exposes_assertable_announcement_id(self, state):
        pid = canonicalise_property_id("PROP-1")
        launcher_id = bytes32(b"\x9b" * 32)
        inner = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        full_ph = bytes32(puzzle_for_singleton(launcher_id, inner).get_tree_hash())
        coin = Coin(bytes32(b"\x9c" * 32), full_ph, uint64(1))

        artifacts = build_registration_coin_spend(
            registry_coin=coin,
            registry_inner_puzzle=inner,
            registry_launcher_id=launcher_id,
            lineage_proof=LineageProof(launcher_id),
            property_id_canon=pid,
        )

        assert artifacts.registry_full_puzzle_hash == full_ph
        assert artifacts.announcement_id == registration_announcement_id(full_ph, pid)
        assert artifacts.inner.announcement_id == artifacts.announcement_id
        assert artifacts.coin_spend.coin == coin
        assert bytes32(artifacts.coin_spend.puzzle_reveal.get_tree_hash()) == full_ph

    def test_assert_my_amount_present(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # ASSERT_MY_AMOUNT = 73.
        amt = next((c for c in conditions if int(c.first().as_int()) == 73), None)
        assert amt is not None
        assert int(amt.rest().first().as_int()) == 1

    def test_python_rejects_short_property_id(self, state):
        with pytest.raises(ValueError, match="32 bytes"):
            build_registration_spend(
                current=state, property_id_canon=b"\x00" * 31, my_amount=1
            )

    def test_python_rejects_even_amount(self, state):
        with pytest.raises(ValueError, match="odd"):
            build_registration_spend(
                current=state,
                property_id_canon=canonicalise_property_id("PROP-1"),
                my_amount=2,
            )

    def test_second_distinct_registration_uses_full_set_witness(self, state):
        first = canonicalise_property_id("PROP-1")
        second = canonicalise_property_id("PROP-2")
        first_artifacts = build_registration_spend(
            current=state,
            property_id_canon=first,
            my_amount=1,
        )
        next_state = PropertyRegistryState(
            self_mod_hash=property_registry_inner_mod_hash(),
            gov_pubkey=GOV_PUBKEY,
            registered_ids_root=first_artifacts.new_registered_ids_root,
            registry_version=1,
        )
        second_artifacts = build_registration_spend(
            current=next_state,
            property_id_canon=second,
            registered_ids=[first],
            my_amount=1,
        )
        assert second_artifacts.new_registered_ids_root == registered_ids_root([second, first])

    def test_python_rejects_duplicate_property_id(self, state):
        first = canonicalise_property_id("PROP-1")
        next_state = PropertyRegistryState(
            self_mod_hash=property_registry_inner_mod_hash(),
            gov_pubkey=GOV_PUBKEY,
            registered_ids_root=registered_ids_root([first]),
            registry_version=1,
        )
        with pytest.raises(ValueError, match="already registered"):
            build_registration_spend(
                current=next_state,
                property_id_canon=first,
                registered_ids=[first],
                my_amount=1,
            )

    def test_python_rejects_mismatched_witness_root(self, state):
        with pytest.raises(ValueError, match="witness root"):
            build_registration_spend(
                current=state,
                property_id_canon=canonicalise_property_id("PROP-1"),
                registered_ids=[canonicalise_property_id("PROP-0")],
                my_amount=1,
            )

    def test_python_rejects_witness_count_mismatch(self, state):
        bad_state = PropertyRegistryState(
            self_mod_hash=property_registry_inner_mod_hash(),
            gov_pubkey=GOV_PUBKEY,
            registered_ids_root=EMPTY_REGISTERED_IDS_ROOT,
            registry_version=1,
        )
        with pytest.raises(ValueError, match="witness count"):
            build_registration_spend(
                current=bad_state,
                property_id_canon=canonicalise_property_id("PROP-1"),
                registered_ids=[],
                my_amount=1,
            )


# ── Replay protection ───────────────────────────────────────────────────


class TestReplayProtection:
    def test_clvm_rejects_version_skip(self):
        """new_registry_version must equal REGISTRY_VERSION + 1."""
        # Singleton at version 5; try to register at version 7 (skip 6).
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        bad_solution = Program.to([1, canonicalise_property_id("PROP-1"), [], 7])
        with pytest.raises(Exception):  # CLVM raises on assert failure
            puzzle.run(bad_solution)

    def test_clvm_rejects_version_downgrade(self):
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        bad_solution = Program.to([1, canonicalise_property_id("PROP-1"), [], 4])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)

    def test_clvm_rejects_same_version(self):
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        bad_solution = Program.to([1, canonicalise_property_id("PROP-1"), [], 5])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)

    def test_clvm_rejects_duplicate_property_id(self):
        pid = canonicalise_property_id("PROP-1")
        puzzle = make_inner_puzzle(
            GOV_PUBKEY,
            registry_version=1,
            registered_ids_root=registered_ids_root([pid]),
        )
        bad_solution = Program.to([1, pid, [pid], 2])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)

    def test_clvm_rejects_wrong_registered_ids_witness(self):
        pid = canonicalise_property_id("PROP-1")
        other = canonicalise_property_id("PROP-0")
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        bad_solution = Program.to([1, pid, [other], 1])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)
