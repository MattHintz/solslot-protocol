"""Tests for mint_proposal_inner.clsp and mint_proposal_driver.py.

Per-proposal singleton implementing a state machine:

    DRAFT  ──gov-sig──▶  APPROVED
       │
       │ owner-sig
       ▼
    CANCELLED

This file exhaustively exercises:

  * Module compilation + tree-hash stability.
  * Proposal-data-hash determinism + sensitivity.
  * Signing- and transition-message round-trips.
  * Inner-puzzle round-trip (curry → parse).
  * APPROVE spend (DRAFT → APPROVED) — gov AGG_SIG_ME, recurry, announcement.
  * CANCEL  spend (DRAFT → CANCELLED) — owner AGG_SIG_ME, recurry, announcement.
  * Replay protection (Python + CLVM both reject downgrade/equal version).
  * State-machine guard (transitions from non-DRAFT are refused).
  * Unknown transition_case is refused.
  * Input validation (short pubkeys, even amount, malformed proposal_data_hash).
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm

from solslot_puzzles.mint_proposal_driver import (
    STATE_APPROVED,
    STATE_CANCELLED,
    STATE_DRAFT,
    TRANSITION_APPROVE,
    TRANSITION_CANCEL,
    MintProposalState,
    build_approve_spend,
    build_cancel_spend,
    compute_proposal_data_hash,
    compute_signing_message,
    compute_transition_message,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    mint_proposal_inner_mod_hash,
    parse_inner_puzzle,
)
from solslot_puzzles.property_registry_driver import canonicalise_property_id


OWNER = b"\x77" * 48
OTHER_OWNER = b"\xaa" * 48
GOV = b"\x33" * 48
PROPOSAL_DATA_HASH = compute_proposal_data_hash(
    property_id_canon=canonicalise_property_id("PROP-1"),
    par_value_mojos=1_000_000,
    royalty_bps=500,
    quorum_threshold=10,
)


def _draft_state(state_version: int = 0) -> MintProposalState:
    return MintProposalState(
        self_mod_hash=mint_proposal_inner_mod_hash(),
        owner_pubkey=OWNER,
        gov_pubkey=GOV,
        proposal_data_hash=PROPOSAL_DATA_HASH,
        proposal_state=STATE_DRAFT,
        state_version=state_version,
    )


# ── Compilation ─────────────────────────────────────────────────────────


class TestCompile:
    def test_module_compiles(self):
        mod = load_clvm(
            "mint_proposal_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        assert mod is not None

    def test_mod_hash_stable(self):
        h1 = mint_proposal_inner_mod_hash()
        h2 = mint_proposal_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32


# ── Proposal data hash ──────────────────────────────────────────────────


class TestProposalDataHash:
    def test_determinism(self):
        a = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        b = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        assert a == b
        assert len(a) == 32

    def test_property_id_sensitivity(self):
        a = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        b = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-2"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        assert a != b

    def test_par_value_sensitivity(self):
        a = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        b = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=2, royalty_bps=2, quorum_threshold=3,
        )
        assert a != b

    def test_royalty_sensitivity(self):
        a = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        b = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=99, quorum_threshold=3,
        )
        assert a != b

    def test_quorum_sensitivity(self):
        a = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
        )
        b = compute_proposal_data_hash(
            property_id_canon=canonicalise_property_id("PROP-1"),
            par_value_mojos=1, royalty_bps=2, quorum_threshold=99,
        )
        assert a != b

    def test_rejects_short_property_id(self):
        with pytest.raises(ValueError, match="32 bytes"):
            compute_proposal_data_hash(
                property_id_canon=b"\x00" * 31,
                par_value_mojos=1, royalty_bps=2, quorum_threshold=3,
            )

    def test_rejects_negative_par(self):
        with pytest.raises(ValueError, match="par_value_mojos.*≥ 0"):
            compute_proposal_data_hash(
                property_id_canon=canonicalise_property_id("PROP-1"),
                par_value_mojos=-1, royalty_bps=2, quorum_threshold=3,
            )


# ── Signing & announcement messages ─────────────────────────────────────


class TestMessages:
    def test_signing_message_determinism(self):
        a = compute_signing_message(TRANSITION_APPROVE, 1)
        b = compute_signing_message(TRANSITION_APPROVE, 1)
        assert a == b

    def test_signing_message_transition_sensitivity(self):
        a = compute_signing_message(TRANSITION_APPROVE, 1)
        b = compute_signing_message(TRANSITION_CANCEL, 1)
        assert a != b

    def test_signing_message_version_sensitivity(self):
        a = compute_signing_message(TRANSITION_APPROVE, 1)
        b = compute_signing_message(TRANSITION_APPROVE, 2)
        assert a != b

    def test_transition_message_determinism(self):
        a = compute_transition_message(TRANSITION_APPROVE, STATE_APPROVED, 1)
        b = compute_transition_message(TRANSITION_APPROVE, STATE_APPROVED, 1)
        assert a == b


# ── Inner puzzle construction + parsing ─────────────────────────────────


class TestParse:
    def test_round_trip_draft(self):
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        state = parse_inner_puzzle(puzzle)
        assert state.is_draft
        assert state.state_name == "DRAFT"
        assert not state.is_terminal

    def test_round_trip_approved(self):
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_APPROVED, state_version=1,
        )
        state = parse_inner_puzzle(puzzle)
        assert state.is_approved
        assert state.state_name == "APPROVED"
        assert state.is_terminal

    def test_round_trip_cancelled(self):
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_CANCELLED, state_version=1,
        )
        state = parse_inner_puzzle(puzzle)
        assert state.is_cancelled
        assert state.state_name == "CANCELLED"
        assert state.is_terminal

    def test_distinct_states_yield_distinct_puzhashes(self):
        a = make_inner_puzzle_hash(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        b = make_inner_puzzle_hash(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_APPROVED, state_version=0,
        )
        assert a != b

    def test_parse_rejects_wrong_module(self):
        bogus = Program.to(1).curry(
            b"\x00" * 32, OWNER, GOV, PROPOSAL_DATA_HASH, STATE_DRAFT, 0,
        )
        with pytest.raises(ValueError, match="mint_proposal_inner"):
            parse_inner_puzzle(bogus)


# ── Construction validation ─────────────────────────────────────────────


class TestConstruction:
    def test_make_inner_puzzle_rejects_short_owner(self):
        with pytest.raises(ValueError, match="owner_pubkey must be 48 bytes"):
            make_inner_puzzle(
                owner_pubkey=b"\x00" * 32, gov_pubkey=GOV,
                proposal_data_hash=PROPOSAL_DATA_HASH,
                proposal_state=STATE_DRAFT, state_version=0,
            )

    def test_make_inner_puzzle_rejects_short_gov(self):
        with pytest.raises(ValueError, match="gov_pubkey must be 48 bytes"):
            make_inner_puzzle(
                owner_pubkey=OWNER, gov_pubkey=b"\x00" * 32,
                proposal_data_hash=PROPOSAL_DATA_HASH,
                proposal_state=STATE_DRAFT, state_version=0,
            )

    def test_make_inner_puzzle_rejects_short_data_hash(self):
        with pytest.raises(ValueError, match="proposal_data_hash must be 32 bytes"):
            make_inner_puzzle(
                owner_pubkey=OWNER, gov_pubkey=GOV,
                proposal_data_hash=b"\x00" * 31,
                proposal_state=STATE_DRAFT, state_version=0,
            )

    def test_make_inner_puzzle_rejects_unknown_state(self):
        with pytest.raises(ValueError, match="proposal_state must be one of"):
            make_inner_puzzle(
                owner_pubkey=OWNER, gov_pubkey=GOV,
                proposal_data_hash=PROPOSAL_DATA_HASH,
                proposal_state=99, state_version=0,
            )


# ── APPROVE spend (DRAFT → APPROVED) ───────────────────────────────────


class TestApproveSpend:
    def test_emits_four_conditions(self):
        artifacts = build_approve_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        result = puzzle.run(artifacts.inner_solution)
        assert len(list(result.as_iter())) == 4

    def test_agg_sig_me_uses_gov_pubkey(self):
        artifacts = build_approve_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        agg_sig_me = next(
            (c for c in conditions if int(c.first().as_int()) == 50), None
        )
        assert agg_sig_me is not None
        sig_pubkey = bytes(agg_sig_me.rest().first().as_atom())
        assert sig_pubkey == GOV  # gov authorises APPROVE, not owner

    def test_create_coin_uses_approved_state(self):
        artifacts = build_approve_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None
        )
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        expected = make_inner_puzzle_hash(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_APPROVED, state_version=1,
        )
        assert emitted_puzhash == expected
        assert artifacts.new_inner_puzzle_hash == expected
        assert artifacts.new_state == STATE_APPROVED

    def test_announcement_carries_transition_message(self):
        artifacts = build_approve_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        ann = next(
            (c for c in conditions if int(c.first().as_int()) == 62), None
        )
        assert ann is not None
        ann_msg = bytes(ann.rest().first().as_atom())
        # 0x50 || sha256tree([transition, new_state, new_version])
        expected_body = compute_transition_message(
            TRANSITION_APPROVE, STATE_APPROVED, 1,
        )
        assert ann_msg == b"\x50" + bytes(expected_body)
        assert artifacts.transition_announcement_message == ann_msg


# ── CANCEL spend (DRAFT → CANCELLED) ───────────────────────────────────


class TestCancelSpend:
    def test_agg_sig_me_uses_owner_pubkey(self):
        artifacts = build_cancel_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        agg_sig_me = next(
            (c for c in conditions if int(c.first().as_int()) == 50), None
        )
        assert agg_sig_me is not None
        sig_pubkey = bytes(agg_sig_me.rest().first().as_atom())
        assert sig_pubkey == OWNER  # owner authorises CANCEL

    def test_create_coin_uses_cancelled_state(self):
        artifacts = build_cancel_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        create_coin = next(
            (c for c in conditions if int(c.first().as_int()) == 51), None
        )
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        expected = make_inner_puzzle_hash(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_CANCELLED, state_version=1,
        )
        assert emitted_puzhash == expected
        assert artifacts.new_state == STATE_CANCELLED

    def test_signature_message_distinct_from_approve(self):
        approve = build_approve_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        cancel = build_cancel_spend(
            current=_draft_state(), new_state_version=1, my_amount=1,
        )
        # Different transition_case → different binding → different
        # signing message.  Ensures gov-approve sig cannot be replayed
        # as owner-cancel and vice versa.
        assert approve.agg_sig_me_message != cancel.agg_sig_me_message


# ── State-machine guards ───────────────────────────────────────────────


class TestStateMachineGuards:
    def test_python_rejects_transition_from_approved(self):
        approved = MintProposalState(
            self_mod_hash=mint_proposal_inner_mod_hash(),
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_APPROVED, state_version=1,
        )
        with pytest.raises(ValueError, match="DRAFT"):
            build_approve_spend(
                current=approved, new_state_version=2, my_amount=1,
            )

    def test_python_rejects_transition_from_cancelled(self):
        cancelled = MintProposalState(
            self_mod_hash=mint_proposal_inner_mod_hash(),
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_CANCELLED, state_version=1,
        )
        with pytest.raises(ValueError, match="DRAFT"):
            build_cancel_spend(
                current=cancelled, new_state_version=2, my_amount=1,
            )

    def test_clvm_rejects_transition_from_approved(self):
        # Even if a malicious prover crafts a solution by hand, the
        # puzzle's `(= PROPOSAL_STATE STATE_DRAFT)` assert must fail.
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_APPROVED, state_version=1,
        )
        bad_solution = Program.to([1, TRANSITION_APPROVE, 2])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)

    def test_clvm_rejects_unknown_transition(self):
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=0,
        )
        # 'z' = 0x7a is neither APPROVE nor CANCEL.
        bad_solution = Program.to([1, 0x7a, 1])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)


# ── Replay protection ──────────────────────────────────────────────────


class TestReplayProtection:
    def test_python_rejects_version_downgrade(self):
        with pytest.raises(ValueError, match="new_state_version must be >"):
            build_approve_spend(
                current=_draft_state(state_version=5),
                new_state_version=4, my_amount=1,
            )

    def test_python_rejects_same_version(self):
        with pytest.raises(ValueError, match="new_state_version must be >"):
            build_approve_spend(
                current=_draft_state(state_version=5),
                new_state_version=5, my_amount=1,
            )

    def test_clvm_rejects_version_downgrade(self):
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=5,
        )
        bad_solution = Program.to([1, TRANSITION_APPROVE, 4])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)

    def test_clvm_rejects_same_version(self):
        puzzle = make_inner_puzzle(
            owner_pubkey=OWNER, gov_pubkey=GOV,
            proposal_data_hash=PROPOSAL_DATA_HASH,
            proposal_state=STATE_DRAFT, state_version=5,
        )
        bad_solution = Program.to([1, TRANSITION_APPROVE, 5])
        with pytest.raises(Exception):
            puzzle.run(bad_solution)


# ── Other input validation ─────────────────────────────────────────────


class TestInputValidation:
    def test_python_rejects_even_amount(self):
        with pytest.raises(ValueError, match="odd"):
            build_approve_spend(
                current=_draft_state(), new_state_version=1, my_amount=2,
            )
