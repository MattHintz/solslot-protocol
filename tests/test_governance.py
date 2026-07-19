"""Unit tests for the v2 governance proposal tracker.

The tracker replaces the legacy raw-`vote_weight` puzzle (CRITICAL-3 audit
fix).  Vote weight is now bound to SGT CAT lock announcements; the tracker
enforces a CAT-conservation-backed quorum check before EXECUTE can dispatch
a bill to the pool / DID.

Test scope:
  - PROPOSE opens the tracker correctly and emits the expected assertions.
  - VOTE increments the tally and re-creates state.
  - EXECUTE dispatches the bill and only fires after quorum + deadline.
  - EXPIRE clears state when quorum is not met.
  - Schema validation (proposal_hash == sha256tree(bill_op), idle preconditions).

These tests drive the puzzle directly with synthetic CAT-wrapped SGT
announcements; full CAT2 lifecycle is exercised by the e2e simulator test
(Step D / Milestone 1).
"""
from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.sgt_driver import (
    BILL_FREEZE,
    BILL_MINT,
    BILL_SETTLE,
    BILL_VAULT_VERSION,
    SINGLETON_LAUNCHER_HASH,
    TRK_EXECUTE,
    TRK_EXPIRE,
    TRK_PROPOSE,
    TRK_VOTE,
    bill_freeze,
    bill_mint as build_mint_bill,
    bill_settle,
    bill_vault_version,
    cat_sgt_free_puzzle_hash,
    deed_releases_hash,
    sgt_free_inner_mod,
    sgt_locked_inner_mod,
    proposal_hash_from_bill,
    proposal_tracker_inner_puzzle,
    proposal_tracker_mod,
    vault_version_approval_message,
    vault_version_content_hash,
)
from solslot_puzzles import vault_version_registry_driver as vvr


PuzzleError = ValueError


# ── Condition codes ──────────────────────────────────────────────────────────
CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
SEND_MESSAGE = 66
ASSERT_MY_AMOUNT = 73
ASSERT_MY_COIN_ID = 70
ASSERT_MY_PUZZLEHASH = 72
ASSERT_SECONDS_ABSOLUTE = 81
ASSERT_BEFORE_SECONDS_ABSOLUTE = 85
REMARK = 1


# ── Common fixtures ──────────────────────────────────────────────────────────
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
TRACKER_LAUNCHER_ID = bytes32(b"\xb0" * 32)
TRACKER_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (TRACKER_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)

POOL_LAUNCHER_ID = bytes32(b"\xc0" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)

DID_PUZHASH = bytes32(b"\xd0" * 32)
CAT_MOD_HASH = bytes32(b"\xca" * 32)
SGT_TAIL_HASH = bytes32(b"\xea" * 32)

SGT_FREE_MOD_HASH = bytes32(sgt_free_inner_mod().get_tree_hash())
SGT_LOCKED_MOD_HASH = bytes32(sgt_locked_inner_mod().get_tree_hash())
TRACKER_MOD_HASH = bytes32(proposal_tracker_mod().get_tree_hash())

QUORUM_BPS = 5000        # 50%
VOTING_WINDOW = 300      # 5 min
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000  # 1% of supply, anti-spam

VOTER_INNER_PUZHASH = bytes32(b"\x77" * 32)
PROPERTY_ID = bytes32(b"\x71" * 32)
PROPERTY_REGISTRY_PUZHASH = bytes32(b"\x72" * 32)

# Tracker self identity at the time of a spend
TRACKER_AMOUNT = 1


# ── Helpers ──────────────────────────────────────────────────────────────────
def mint_bill(deed_full_puzhash: bytes32) -> Program:
    return build_mint_bill(deed_full_puzhash, PROPERTY_ID, PROPERTY_REGISTRY_PUZHASH)


def _curry_tracker(
    proposal_hash: int = 0,
    bill_op: int = 0,
    vote_tally: int = 0,
    voting_deadline: int = 0,
) -> Program:
    return proposal_tracker_inner_puzzle(
        TRACKER_STRUCT,
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH,
        SGT_TAIL_HASH,
        DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        SGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        proposal_hash=proposal_hash,
        bill_operation=bill_op,
        vote_tally=vote_tally,
        voting_deadline=voting_deadline,
    )


def _tracker_my_id_and_ph(curried: Program) -> tuple[bytes32, bytes32]:
    """Compute matching my_id / my_inner_puzhash for the curried tracker.

    For CLVM-only tests we don't need a real coin id; we just need a
    self-consistent set of values that satisfy the identity_conditions
    asserts.  We use the inner puzzle hash and synthesize a coin id.
    """
    inner_ph = bytes32(curried.get_tree_hash())
    # Manufacture a coin id: any value works for the PUZZLEHASH assert as long
    # as the my_inner_puzzlehash and singleton_full_puzhash match.
    fake_parent = bytes32(b"\x00" * 32)
    full_ph = _full_singleton_ph(inner_ph)
    my_id = bytes32(
        hashlib.sha256(fake_parent + full_ph + bytes([TRACKER_AMOUNT])).digest()
    )
    return my_id, inner_ph


def _full_singleton_ph(inner_ph: bytes32) -> bytes32:
    """Compute the full singleton puzzle hash for the tracker."""
    from chia.wallet.util.curry_and_treehash import (
        calculate_hash_of_quoted_mod_hash,
        curry_and_treehash,
    )

    def quoted_atom_hash(value: bytes) -> bytes32:
        return bytes32(
            hashlib.sha256(
                b"\x02"
                + hashlib.sha256(b"\x01\x01").digest()
                + hashlib.sha256(b"\x01" + value).digest()
            ).digest()
        )

    def quoted_program_hash(tree_hash: bytes32) -> bytes32:
        return bytes32(
            hashlib.sha256(
                b"\x02"
                + hashlib.sha256(b"\x01\x01").digest()
                + tree_hash
            ).digest()
        )

    quoted_mod = calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH)
    # singleton structure curry: (singleton_top_layer.curry SINGLETON_STRUCT inner)
    # singleton_full = curry(SINGLETON_MOD, SINGLETON_STRUCT, inner_ph)
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            quoted_program_hash(bytes32(TRACKER_STRUCT.get_tree_hash())),
            quoted_program_hash(inner_ph),
        )
    )


def _conds_to_list(result: Program) -> list:
    return [list(item.as_iter()) for item in result.as_iter()]


def _atom_int(prog: Program) -> int:
    return int.from_bytes(prog.atom, "big") if prog.atom else 0


def _atom_bytes(prog: Program) -> bytes:
    return bytes(prog.atom) if prog.atom is not None else b""


def _expected_lock_announcement_id(
    voter_inner_puzhash: bytes32,
    proposal_hash: bytes32,
    amount: int,
    voting_deadline: int,
) -> bytes32:
    """Compute the LOCK announcement id the tracker expects."""
    sender_ph = cat_sgt_free_puzzle_hash(
        TRACKER_STRUCT,
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH,
        SGT_TAIL_HASH,
        voter_inner_puzhash,
    )
    LOCK_TAG = b"LOCK"
    msg_body = Program.to([LOCK_TAG, proposal_hash, amount, voting_deadline]).get_tree_hash()
    msg = b"\x53" + msg_body  # PROTOCOL_PREFIX + sha256tree(...)
    return bytes32(hashlib.sha256(sender_ph + msg).digest())


# ─────────────────────────────────────────────────────────────────────────────
#                              PROPOSE tests
# ─────────────────────────────────────────────────────────────────────────────
class TestPropose:
    def test_propose_emits_lock_announcement_and_recurries_to_open_state(self):
        """Tracker is idle → PROPOSE opens it.  Verify the puzzle:
        - asserts SGT lock announcement covering first_vote_amount
        - creates a child tracker with proposal_hash / bill / tally / deadline
        - asserts now is within the voting window
        - DOES NOT assert any DID PROP announcement (legacy gate removed in fix C-1)
        """
        deed_full_ph = bytes32(b"\x33" * 32)
        bill = mint_bill(deed_full_ph)
        proposal_hash = proposal_hash_from_bill(bill)
        first_vote = 600_000  # 60% of 1M = above quorum, also ≫ MIN_PROPOSAL_STAKE
        # Pick a future deadline.
        voting_deadline = 2_000_000_000

        curried = _curry_tracker()  # idle
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [proposal_hash, bill, VOTER_INNER_PUZHASH, first_vote, voting_deadline],
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        codes = [_atom_int(c[0]) for c in conds]

        # Check the structure
        assert CREATE_COIN in codes              # next tracker state
        assert ASSERT_PUZZLE_ANNOUNCEMENT in codes  # SGT lock only (DID gate removed)
        assert ASSERT_BEFORE_SECONDS_ABSOLUTE in codes
        assert ASSERT_SECONDS_ABSOLUTE in codes  # lower bound
        assert REMARK in codes

        # Exactly one ASSERT_PUZZLE_ANNOUNCEMENT — the SGT lock
        assertions = [c for c in conds if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT]
        assert len(assertions) == 1, (
            f"Expected only the SGT-lock assertion (DID PROP gate dropped); "
            f"got {len(assertions)} ASSERT_PUZZLE_ANNOUNCEMENT entries."
        )

        # The lock announcement id should match what we compute off-chain.
        expected_lock_id = _expected_lock_announcement_id(
            VOTER_INNER_PUZHASH, proposal_hash, first_vote, voting_deadline
        )
        assert _atom_bytes(assertions[0][1]) == expected_lock_id

    def test_propose_rejects_when_already_open(self):
        """Tracker has an active proposal → PROPOSE must fail."""
        curried = _curry_tracker(
            proposal_hash=bytes32(b"\xee" * 32),
            bill_op=mint_bill(bytes32(b"\x33" * 32)),
            vote_tally=100,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [bytes32(b"\xff" * 32), mint_bill(bytes32(b"\x44" * 32)),
             VOTER_INNER_PUZHASH, 100, 2_100_000_000],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_propose_rejects_proposal_hash_not_matching_bill(self):
        """proposal_hash must equal sha256tree(bill_op)."""
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        bill = mint_bill(bytes32(b"\x33" * 32))
        wrong_hash = bytes32(b"\xab" * 32)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [wrong_hash, bill, VOTER_INNER_PUZHASH, 1, 2_000_000_000],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_propose_rejects_unknown_bill_tag(self):
        """PA3: malformed bills must not enter the open governance state."""
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        bill = Program.to([b"X", bytes32(b"\x33" * 32), 0])
        ph = proposal_hash_from_bill(bill)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [ph, bill, VOTER_INNER_PUZHASH, MIN_PROPOSAL_STAKE, 2_000_000_000],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_propose_rejects_zero_first_vote(self):
        """Zero stake fails the MIN_PROPOSAL_STAKE check."""
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        bill = mint_bill(bytes32(b"\x33" * 32))
        ph = proposal_hash_from_bill(bill)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [ph, bill, VOTER_INNER_PUZHASH, 0, 2_000_000_000],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_propose_rejects_below_min_stake(self):
        """Stake just below MIN_PROPOSAL_STAKE fails (anti-spam)."""
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        bill = mint_bill(bytes32(b"\x33" * 32))
        ph = proposal_hash_from_bill(bill)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [ph, bill, VOTER_INNER_PUZHASH, MIN_PROPOSAL_STAKE - 1, 2_000_000_000],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_propose_accepted_at_min_stake_boundary(self):
        """Stake exactly at MIN_PROPOSAL_STAKE is accepted (boundary inclusive)."""
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        bill = mint_bill(bytes32(b"\x33" * 32))
        ph = proposal_hash_from_bill(bill)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [ph, bill, VOTER_INNER_PUZHASH, MIN_PROPOSAL_STAKE, 2_000_000_000],
        ])
        # Should not raise.
        out = curried.run(sol)
        conds = _conds_to_list(out)
        # Sanity: state recreation captured the boundary stake as initial tally.
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)
        expected_next = proposal_tracker_inner_puzzle(
            TRACKER_STRUCT, SGT_FREE_MOD_HASH, SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH, SGT_TAIL_HASH, DID_PUZHASH, POOL_STRUCT,
            QUORUM_BPS, VOTING_WINDOW, SGT_TOTAL_SUPPLY, MIN_PROPOSAL_STAKE,
            proposal_hash=ph, bill_operation=bill,
            vote_tally=MIN_PROPOSAL_STAKE, voting_deadline=2_000_000_000,
        ).get_tree_hash()
        assert _atom_bytes(cc[1]) == expected_next


# ─────────────────────────────────────────────────────────────────────────────
#                               VOTE tests
# ─────────────────────────────────────────────────────────────────────────────
class TestVote:
    def test_vote_increments_tally_and_emits_lock_assertion(self):
        bill = mint_bill(bytes32(b"\x33" * 32))
        proposal_hash = proposal_hash_from_bill(bill)
        deadline = 2_000_000_000
        existing_tally = 100_000
        added = 250_000

        curried = _curry_tracker(
            proposal_hash=proposal_hash,
            bill_op=bill,
            vote_tally=existing_tally,
            voting_deadline=deadline,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_VOTE,
            [VOTER_INNER_PUZHASH, added],
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        codes = [_atom_int(c[0]) for c in conds]

        assert CREATE_COIN in codes
        assert ASSERT_PUZZLE_ANNOUNCEMENT in codes
        assert ASSERT_BEFORE_SECONDS_ABSOLUTE in codes

        # The lock announcement id matches the one we'd compute off-chain
        # for (proposal_hash, added, deadline).
        expected = _expected_lock_announcement_id(
            VOTER_INNER_PUZHASH, proposal_hash, added, deadline
        )
        assertions = [c for c in conds if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT]
        assert _atom_bytes(assertions[0][1]) == expected

    def test_vote_rejected_when_tracker_is_idle(self):
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_VOTE,
            [VOTER_INNER_PUZHASH, 1000],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_vote_rejected_with_zero_amount(self):
        bill = mint_bill(bytes32(b"\x33" * 32))
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=1000,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_VOTE,
            [VOTER_INNER_PUZHASH, 0],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
#                              EXECUTE tests
# ─────────────────────────────────────────────────────────────────────────────
class TestExecute:
    def test_execute_extended_mint_bill_uses_unchanged_dispatch(self):
        """Trailing metadata commitments are hashed but ignored by RC16 dispatch."""
        deed_full_ph = bytes32(b"\x33" * 32)
        bill = Program.to(
            [
                BILL_MINT,
                deed_full_ph,
                PROPERTY_ID,
                PROPERTY_REGISTRY_PUZHASH,
                bytes32(b"\x44" * 32),
                bytes32(b"\x55" * 32),
            ]
        )
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=SGT_TOTAL_SUPPLY,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        out = curried.run(
            Program.to([my_id, my_ph, TRACKER_AMOUNT, TRK_EXECUTE, 0])
        )
        conds = _conds_to_list(out)
        sends = [c for c in conds if _atom_int(c[0]) == SEND_MESSAGE]
        assertions = [
            c for c in conds if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        ]
        assert len(sends) == 1
        assert len(assertions) == 2
        assert _atom_bytes(sends[0][2]) == b"\x53" + Program.to(
            [b"MINT", deed_full_ph]
        ).get_tree_hash()

    def test_execute_mint_sends_message_to_did(self):
        """MINT EXECUTE must:
        - SEND_MESSAGE with mode 0x10 (matches DID's RECEIVE_MESSAGE 0x10 per CHIP-25)
        - ASSERT_PUZZLE_ANNOUNCEMENT(DID_full_ph || deed_full_ph)
          (the same announcement the launcher asserts → atomicity bind)
        - reset state to IDLE and emit EXEC release announcement
        """
        deed_full_ph = bytes32(b"\x33" * 32)
        bill = mint_bill(deed_full_ph)
        proposal_hash = proposal_hash_from_bill(bill)
        deadline = 2_000_000_000
        # Quorum reached: 600_000 SGT > 50% of 1M
        tally = 600_000

        curried = _curry_tracker(
            proposal_hash=proposal_hash,
            bill_op=bill,
            vote_tally=tally,
            voting_deadline=deadline,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXECUTE,
            0,  # EXECUTE takes no params now (mode 0x10 doesn't need recipient ph)
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        codes = [_atom_int(c[0]) for c in conds]

        # State machine + EXEC release
        assert CREATE_COIN in codes
        assert ASSERT_SECONDS_ABSOLUTE in codes
        assert CREATE_PUZZLE_ANNOUNCEMENT in codes

        # SEND_MESSAGE with mode 0x10 (one entry, the MINT bill)
        sends = [c for c in conds if _atom_int(c[0]) == SEND_MESSAGE]
        assert len(sends) == 1, f"Expected exactly 1 SEND_MESSAGE for MINT, got {len(sends)}"
        send_mode = _atom_int(sends[0][1])
        assert send_mode == 0x10, (
            f"MINT SEND_MESSAGE must use mode 0x10 to pair with DID's "
            f"RECEIVE_MESSAGE 0x10 (CHIP-25); got 0x{send_mode:x}"
        )
        # mode 0x10 SEND has no var_args (sender-puzzle implicit, receiver-none)
        # so the SEND_MESSAGE has exactly (op, mode, message) = 3 elements
        assert len(sends[0]) == 3, (
            f"mode 0x10 SEND_MESSAGE must have no var_args; got {len(sends[0])} fields"
        )

        # Defense-in-depth: gov asserts DID's puzzle announcement of the deed.
        # Announcement id = sha256(did_ph || deed_full_ph)
        expected_did_announce_id = bytes32(
            hashlib.sha256(DID_PUZHASH + deed_full_ph).digest()
        )
        expected_registry_announce_id = bytes32(
            hashlib.sha256(
                PROPERTY_REGISTRY_PUZHASH + b"\x53" + PROPERTY_ID
            ).digest()
        )
        asserts = [c for c in conds if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT]
        assert len(asserts) == 2, (
            "MINT EXECUTE must assert both DID and property-registry announcements; "
            f"got {len(asserts)} asserts"
        )
        assert {_atom_bytes(condition[1]) for condition in asserts} == {
            expected_did_announce_id,
            expected_registry_announce_id,
        }

    def test_execute_rejects_below_quorum(self):
        bill = mint_bill(bytes32(b"\x33" * 32))
        # 49% — below 50% quorum
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=490_000,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXECUTE,
            [bytes32(b"\xdd" * 32)],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_execute_freeze_sends_message_to_pool(self):
        """FREEZE EXECUTE: mode 0x10 SEND_MESSAGE only (no DID assertion needed;
        the SEND/RECEIVE pairing alone enforces gov↔pool atomicity)."""
        bill = bill_freeze(0)  # FROZEN
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=SGT_TOTAL_SUPPLY,  # 100% > quorum
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXECUTE,
            0,
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        sends = [c for c in conds if _atom_int(c[0]) == SEND_MESSAGE]
        assert len(sends) == 1
        assert _atom_int(sends[0][1]) == 0x10
        assert len(sends[0]) == 3  # no var_args for mode 0x10
        # FREEZE has no DID assertion (pool handles routing alone)
        asserts = [c for c in conds if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT]
        assert len(asserts) == 0

    def test_execute_settle_sends_message_to_pool(self):
        """SETTLE EXECUTE: same pattern as FREEZE — mode 0x10, no extra asserts."""
        splitxch_root = bytes32(b"\xab" * 32)
        releases = [
            [
                bytes32(b"\x11" * 32),
                bytes32(b"\x22" * 32),
                bytes32(b"\x23" * 32),
                bytes32(b"\x24" * 32),
            ],
            [
                bytes32(b"\x33" * 32),
                bytes32(b"\x44" * 32),
                bytes32(b"\x45" * 32),
                bytes32(b"\x46" * 32),
            ],
        ]
        releases_hash = deed_releases_hash(releases)
        bill = bill_settle(splitxch_root, 1_000_000, len(releases), releases_hash)
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=SGT_TOTAL_SUPPLY,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXECUTE,
            0,
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        sends = [c for c in conds if _atom_int(c[0]) == SEND_MESSAGE]
        assert len(sends) == 1
        assert _atom_int(sends[0][1]) == 0x10
        assert len(sends[0]) == 3
        expected_message = b"\x53" + Program.to([
            b"SETT",
            splitxch_root,
            1_000_000,
            len(releases),
            releases_hash,
        ]).get_tree_hash()
        assert _atom_bytes(sends[0][2]) == expected_message
        asserts = [c for c in conds if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT]
        assert len(asserts) == 0


# ─────────────────────────────────────────────────────────────────────────────
#                              EXPIRE tests
# ─────────────────────────────────────────────────────────────────────────────
class TestExpire:
    def test_expire_clears_failed_proposal(self):
        bill = mint_bill(bytes32(b"\x33" * 32))
        # Below quorum
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=400_000,  # 40%
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXPIRE,
            [],
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        codes = [_atom_int(c[0]) for c in conds]

        assert CREATE_COIN in codes
        assert ASSERT_SECONDS_ABSOLUTE in codes
        assert CREATE_PUZZLE_ANNOUNCEMENT in codes  # EXEC announcement so SGTs can release

    def test_expire_rejected_when_quorum_reached(self):
        bill = mint_bill(bytes32(b"\x33" * 32))
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=600_000,  # above quorum
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXPIRE,
            [],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_expire_rejected_when_idle(self):
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_EXPIRE,
            [],
        ])
        with pytest.raises(PuzzleError):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
#                          dispatch & invariants
# ─────────────────────────────────────────────────────────────────────────────
class TestDispatch:
    def test_unknown_spend_case_fails(self):
        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, TRACKER_AMOUNT, 99, []])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_state_recreation_recurries_into_self(self):
        """The CREATE_COIN destination on PROPOSE must equal the next tracker
        inner puzhash computed via Python's curry helper — ensures puzzle and
        driver use the same state-encoding."""
        bill = mint_bill(bytes32(b"\x33" * 32))
        ph = proposal_hash_from_bill(bill)
        deadline = 2_000_000_000

        curried = _curry_tracker()
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [ph, bill, VOTER_INNER_PUZHASH, 100_000, deadline],
        ])
        out = curried.run(sol)
        conds = _conds_to_list(out)
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)

        expected_next = proposal_tracker_inner_puzzle(
            TRACKER_STRUCT,
            SGT_FREE_MOD_HASH,
            SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH,
            SGT_TAIL_HASH,
            DID_PUZHASH,
            POOL_STRUCT,
            QUORUM_BPS,
            VOTING_WINDOW,
            SGT_TOTAL_SUPPLY,
            MIN_PROPOSAL_STAKE,
            proposal_hash=ph,
            bill_operation=bill,
            vote_tally=100_000,
            voting_deadline=deadline,
        ).get_tree_hash()

        assert _atom_bytes(cc[1]) == expected_next


# ─────────────────────────────────────────────────────────────────────────────
#                       EXECUTE — vault-version bill (Brick 3.5a)
# ─────────────────────────────────────────────────────────────────────────────
class TestExecuteVaultVersion:
    """The vault-version bill is governance's ROUTINE-path authorizer for
    ``vault_version_registry`` CODE changes.  On EXECUTE the tracker must emit
    the exact ``CREATE_PUZZLE_ANNOUNCEMENT`` the registry's SPEND_CODE_ROUTINE
    asserts — bound byte-for-byte to ``vault_version_registry_driver``.
    """

    NEW_CODE = bytes32(b"\x10" * 32)
    NEW_PARAMS = bytes32(b"\x20" * 32)
    NEW_VERSION = 7

    def _bill(self):
        bill = bill_vault_version(self.NEW_CODE, self.NEW_PARAMS, self.NEW_VERSION)
        return bill, proposal_hash_from_bill(bill)

    def test_execute_emits_routine_approval_announcement(self):
        bill, ph = self._bill()
        curried = _curry_tracker(
            proposal_hash=ph,
            bill_op=bill,
            vote_tally=600_000,  # 60% > 50% quorum
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, TRACKER_AMOUNT, TRK_EXECUTE, 0])

        out = curried.run(sol)
        conds = _conds_to_list(out)
        codes = [_atom_int(c[0]) for c in conds]

        # State machine: reset to IDLE + deadline passed.
        assert CREATE_COIN in codes
        assert ASSERT_SECONDS_ABSOLUTE in codes
        # Vault-version dispatches via a puzzle announcement, NOT a message,
        # and asserts nothing (registry is the asserter, gov the announcer).
        assert SEND_MESSAGE not in codes
        assert ASSERT_PUZZLE_ANNOUNCEMENT not in codes

        # The governance driver and the registry driver must agree on the
        # routine approval message byte-for-byte.
        expected_msg = vault_version_approval_message(
            self.NEW_CODE, self.NEW_PARAMS, self.NEW_VERSION
        )
        registry_msg = vvr.compute_approval_message(
            path_tag=vvr.TAG_ROUTINE,
            vault_inner_mod_hash=self.NEW_CODE,
            canonical_params_hash=self.NEW_PARAMS,
            vault_version=self.NEW_VERSION,
        )
        assert expected_msg == registry_msg

        # EXECUTE emits two announcements: the EXEC release (locked SGT) and the
        # routine approval.  The registry asserts the latter.
        announcements = [
            _atom_bytes(c[1])
            for c in conds
            if _atom_int(c[0]) == CREATE_PUZZLE_ANNOUNCEMENT
        ]
        assert expected_msg in announcements

        # The content_hash carried in the message equals both drivers'.
        assert expected_msg == b"\x53" + b"\x52\x54" + bytes(
            vvr.compute_content_hash(self.NEW_CODE, self.NEW_PARAMS, self.NEW_VERSION)
        )
        assert expected_msg[3:] == bytes(
            vault_version_content_hash(self.NEW_CODE, self.NEW_PARAMS, self.NEW_VERSION)
        )

        # State resets to IDLE — the registry publish is the only side effect.
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)
        expected_idle = proposal_tracker_inner_puzzle(
            TRACKER_STRUCT, SGT_FREE_MOD_HASH, SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH, SGT_TAIL_HASH, DID_PUZHASH, POOL_STRUCT,
            QUORUM_BPS, VOTING_WINDOW, SGT_TOTAL_SUPPLY, MIN_PROPOSAL_STAKE,
            proposal_hash=0, bill_operation=0, vote_tally=0, voting_deadline=0,
        ).get_tree_hash()
        assert _atom_bytes(cc[1]) == expected_idle

    def test_execute_rejected_below_quorum(self):
        bill, ph = self._bill()
        curried = _curry_tracker(
            proposal_hash=ph,
            bill_op=bill,
            vote_tally=490_000,  # 49% < 50% quorum
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, TRACKER_AMOUNT, TRK_EXECUTE, 0])
        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_propose_accepts_vault_version_bill(self):
        """PROPOSE opens with a vault-version bill (schema: ph == sha256tree(bill))."""
        bill, ph = self._bill()
        curried = _curry_tracker()  # idle
        my_id, my_ph = _tracker_my_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, TRACKER_AMOUNT,
            TRK_PROPOSE,
            [ph, bill, VOTER_INNER_PUZHASH, MIN_PROPOSAL_STAKE, 2_000_000_000],
        ])
        out = curried.run(sol)
        conds = _conds_to_list(out)
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)
        expected_next = proposal_tracker_inner_puzzle(
            TRACKER_STRUCT, SGT_FREE_MOD_HASH, SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH, SGT_TAIL_HASH, DID_PUZHASH, POOL_STRUCT,
            QUORUM_BPS, VOTING_WINDOW, SGT_TOTAL_SUPPLY, MIN_PROPOSAL_STAKE,
            proposal_hash=ph, bill_operation=bill,
            vote_tally=MIN_PROPOSAL_STAKE, voting_deadline=2_000_000_000,
        ).get_tree_hash()
        assert _atom_bytes(cc[1]) == expected_next

    def test_bill_layout_field_extraction(self):
        """(V code params version) layout — guards the puzzle's f/r field walk."""
        bill, _ = self._bill()
        assert _atom_bytes(bill.first()) == BILL_VAULT_VERSION
        rest = bill.rest()
        assert _atom_bytes(rest.first()) == self.NEW_CODE
        assert _atom_bytes(rest.rest().first()) == self.NEW_PARAMS
        assert _atom_int(rest.rest().rest().first()) == self.NEW_VERSION
