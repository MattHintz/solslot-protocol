"""Unit tests for sgt_free_inner.clsp and sgt_locked_inner.clsp.

These two puzzles together implement the SGT governance state machine:

  PROTOCOL TRANSITION (free) ──┬──> free, protocol-selected owner
                    └──> LOCK ──> LOCKED ──┬──> RELEASE_DEADLINE ──> TRANSFER
                                            └──> RELEASE_EXEC     ──> TRANSFER

Each test runs the relevant curried puzzle directly with a synthetic solution
and asserts the emitted condition list.  Full CAT2-wrapped integration is
exercised by tests/test_e2e_simulation.py once the proposal tracker (Step C)
is in place.
"""
from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.sgt_driver import (
    SGT_LOCK,
    SGT_RELEASE_DEADLINE,
    SGT_RELEASE_EXEC,
    SGT_TRANSFER,
    SINGLETON_LAUNCHER_HASH,
    make_proposal_tracker_struct,
    sgt_free_inner_hash,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_hash,
    sgt_locked_inner_mod,
    sgt_locked_inner_puzzle,
)


PuzzleError = ValueError  # chia raises ValueError("clvm raise", ...) on (x)


# ── Condition codes (match condition_codes.clib) ─────────────────────────────
CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
SEND_MESSAGE = 66
RECEIVE_MESSAGE = 67
ASSERT_MY_AMOUNT = 73
ASSERT_SECONDS_ABSOLUTE = 81
ASSERT_BEFORE_SECONDS_ABSOLUTE = 85  # not used in these puzzles
REMARK = 1
PROTOCOL_PREFIX = b"\x53"
SGT_PROTOCOL_TRANSITION_TAG = b"SGTP"


# ── Common fixtures ──────────────────────────────────────────────────────────
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
TRACKER_LAUNCHER_ID = bytes32(b"\xbb" * 32)
PROPOSAL_TRACKER_STRUCT = make_proposal_tracker_struct(
    SINGLETON_MOD_HASH, TRACKER_LAUNCHER_ID
)

OWNER_INNER_PUZHASH = bytes32(b"\xaa" * 32)
NEW_OWNER_INNER_PUZHASH = bytes32(b"\xcc" * 32)

# Mod hashes computed once
SGT_FREE_MOD_HASH = bytes32(sgt_free_inner_mod().get_tree_hash())
SGT_LOCKED_MOD_HASH = bytes32(sgt_locked_inner_mod().get_tree_hash())

# Locking parameters
PROPOSAL_HASH = bytes32(b"\xee" * 32)
LOCK_DEADLINE = 1_700_000_300
SGT_AMOUNT = 100_000


# ── Helpers ──────────────────────────────────────────────────────────────────
# The identity puzzle: `Program.to(1)` returns its solution verbatim.  This is
# the "anyone can spend" test stand-in used throughout the chia/solslot test
# suites.  Its tree hash is stable (= sha256(0x01, 0x01)) so we can compute
# downstream curried hashes without circular dependency on the inner content.
IDENTITY_INNER = Program.to(1)
IDENTITY_INNER_HASH = bytes32(IDENTITY_INNER.get_tree_hash())


def _trivial_inner_puzzle_emitting(conditions: list) -> Program:
    """Build a constant-output puzzle whose run yields ``conditions`` verbatim.

    A `(mod () (q . CONDITIONS))` puzzle is the simplest stand-in for a real
    user p2 puzzle when we only need to test the wrapping semantics AND the
    conditions don't depend on the inner's own tree hash.
    """
    return Program.to((1, conditions))


def _free_curried(inner_puz: Program | None = None,
                  inner_hash: bytes32 = OWNER_INNER_PUZHASH) -> Program:
    """Curry sgt_free_inner with the test-fixture proposal tracker."""
    return sgt_free_inner_puzzle(
        SGT_LOCKED_MOD_HASH, PROPOSAL_TRACKER_STRUCT, inner_hash
    )


def _expected_locked_puzhash(proposal_hash: bytes32, deadline: int,
                              owner_hash: bytes32 = OWNER_INNER_PUZHASH) -> bytes32:
    return sgt_locked_inner_hash(
        SGT_FREE_MOD_HASH, PROPOSAL_TRACKER_STRUCT, owner_hash, proposal_hash, deadline
    )


def _expected_free_puzhash_for(new_inner_hash: bytes32) -> bytes32:
    return sgt_free_inner_hash(
        SGT_LOCKED_MOD_HASH, PROPOSAL_TRACKER_STRUCT, new_inner_hash
    )


def _conds_to_list(result: Program) -> list:
    """Convert a CLVM run-result Program to a Python list of conditions."""
    return [list(item.as_iter()) for item in result.as_iter()]


def _atom_int(prog: Program) -> int:
    """Extract a CLVM integer atom value as a Python int.

    `int.from_bytes(prog, ...)` reads the serialized form (with its length
    prefix), not the atom value.  We must use Program.atom or as_int.
    """
    if prog.atom is None:
        raise ValueError(f"Expected atom Program, got pair: {prog}")
    return int.from_bytes(prog.atom, "big") if prog.atom else 0


def _atom_bytes(prog: Program) -> bytes:
    """Extract the raw atom bytes from a Program."""
    if prog.atom is None:
        raise ValueError(f"Expected atom Program, got pair: {prog}")
    return bytes(prog.atom)


# ─────────────────────────────────────────────────────────────────────────────
#                    sgt_free_inner — TRANSFER spend case
# ─────────────────────────────────────────────────────────────────────────────
class TestFreeTransfer:
    def test_protocol_transition_rewraps_create_coin(self):
        inner = _trivial_inner_puzzle_emitting([
            [REMARK, PROTOCOL_PREFIX, SGT_PROTOCOL_TRANSITION_TAG],
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        out = curried.run(sol)
        conds = _conds_to_list(out)

        assert len(conds) == 2
        cond = next(cond for cond in conds if _atom_int(cond[0]) == CREATE_COIN)
        assert _atom_int(cond[0]) == CREATE_COIN
        # destination is rewrapped into sgt_free_inner curried with NEW_OWNER
        assert _atom_bytes(cond[1]) == _expected_free_puzhash_for(NEW_OWNER_INNER_PUZHASH)
        # amount preserved
        assert _atom_int(cond[2]) == SGT_AMOUNT
        # memo hint = original target (NEW_OWNER) so wallets can index it
        memo_list = list(cond[3].as_iter())
        assert _atom_bytes(memo_list[0]) == NEW_OWNER_INNER_PUZHASH

    def test_transfer_rewraps_every_split_output(self):
        inner = _trivial_inner_puzzle_emitting([
            [REMARK, PROTOCOL_PREFIX, SGT_PROTOCOL_TRANSITION_TAG],
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, 50_000],
            [CREATE_COIN, OWNER_INNER_PUZHASH, 50_000],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        conds = _conds_to_list(curried.run(sol))
        creates = [
            cond for cond in conds if _atom_int(cond[0]) == CREATE_COIN
        ]
        assert len(creates) == 2
        assert {_atom_bytes(cond[1]) for cond in creates} == {
            _expected_free_puzhash_for(NEW_OWNER_INNER_PUZHASH),
            _expected_free_puzhash_for(OWNER_INNER_PUZHASH),
        }
        assert sum(_atom_int(cond[2]) for cond in creates) == SGT_AMOUNT

    def test_transfer_rejects_zero_create_coins(self):
        """No CREATE_COIN at all means the SGT would vanish — disallowed."""
        inner = _trivial_inner_puzzle_emitting([
            [REMARK, b"hello"],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_transfer_rejects_protocol_prefix_remark(self):
        """Inner cannot spoof a solslot governance REMARK."""
        inner = _trivial_inner_puzzle_emitting([
            [REMARK, PROTOCOL_PREFIX, SGT_PROTOCOL_TRANSITION_TAG],
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
            [REMARK, b"\x53", b"forged-payload"],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_transfer_rejects_protocol_prefix_send_message(self):
        inner = _trivial_inner_puzzle_emitting([
            [REMARK, PROTOCOL_PREFIX, SGT_PROTOCOL_TRANSITION_TAG],
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
            [SEND_MESSAGE, 0x10, b"\x53forged", bytes32(b"\xff" * 32)],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_transfer_passes_through_innocuous_conditions(self):
        """ASSERT_MY_AMOUNT and friends should pass through untouched."""
        inner = _trivial_inner_puzzle_emitting([
            [REMARK, PROTOCOL_PREFIX, SGT_PROTOCOL_TRANSITION_TAG],
            [ASSERT_MY_AMOUNT, SGT_AMOUNT],
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        out = curried.run(sol)
        conds = _conds_to_list(out)

        assert len(conds) == 3
        codes = [_atom_int(c[0]) for c in conds]
        assert ASSERT_MY_AMOUNT in codes
        assert CREATE_COIN in codes

    def test_vault_style_transfer_without_protocol_marker_is_rejected(self):
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())

        with pytest.raises(PuzzleError):
            curried.run(Program.to([SGT_TRANSFER, inner, 0, 0]))

    def test_transfer_rejects_wrong_inner_reveal(self):
        """The reveal must hash to INNER_PUZZLE_HASH — otherwise the spend fails."""
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
        ])
        curried = _free_curried(inner_hash=bytes32(b"\xff" * 32))  # mismatch
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(PuzzleError):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
#                       sgt_free_inner — LOCK spend case
# ─────────────────────────────────────────────────────────────────────────────
class TestFreeLock:
    """LOCK uses the identity inner puzzle (Program.to(1)) so the inner's
    tree hash is stable and well-known.  The CREATE_COIN that locks the SGT
    must target sgt_locked_inner curried with this identity hash; we compute
    that destination once and pass it through the inner's solution."""

    def test_lock_emits_announcement_and_recurries_to_locked(self):
        # Owner-side: identity puzzle.  Its hash is INNER_PUZZLE_HASH.
        expected_locked = _expected_locked_puzhash(
            PROPOSAL_HASH, LOCK_DEADLINE, owner_hash=IDENTITY_INNER_HASH
        )
        curried = _free_curried(inner_hash=IDENTITY_INNER_HASH)
        # inner's solution is the conditions list it should emit.
        inner_solution = [[CREATE_COIN, expected_locked, SGT_AMOUNT]]
        sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [PROPOSAL_HASH, LOCK_DEADLINE, SGT_AMOUNT],
        ])

        out = curried.run(sol)
        conds = _conds_to_list(out)

        codes = [_atom_int(c[0]) for c in conds]
        # Must emit: lock announcement, before-deadline assert, and CREATE_COIN
        assert CREATE_PUZZLE_ANNOUNCEMENT in codes
        assert ASSERT_BEFORE_SECONDS_ABSOLUTE in codes
        assert CREATE_COIN in codes

        # Verify the create_coin destination is exactly the locked puzhash.
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)
        assert _atom_bytes(cc[1]) == expected_locked

    def test_lock_rejects_create_coin_to_wrong_destination(self):
        """If user's inner emits CREATE_COIN to anywhere other than the
        canonical locked puzhash, the lock fails."""
        wrong_dest = bytes32(b"\x99" * 32)
        curried = _free_curried(inner_hash=IDENTITY_INNER_HASH)
        inner_solution = [[CREATE_COIN, wrong_dest, SGT_AMOUNT]]
        sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [PROPOSAL_HASH, LOCK_DEADLINE, SGT_AMOUNT],
        ])

        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_lock_rejects_amount_mismatch(self):
        """If the user's inner CREATE_COIN amount doesn't match my_amount,
        the lock fails."""
        expected_locked = _expected_locked_puzhash(
            PROPOSAL_HASH, LOCK_DEADLINE, owner_hash=IDENTITY_INNER_HASH
        )
        curried = _free_curried(inner_hash=IDENTITY_INNER_HASH)
        inner_solution = [[CREATE_COIN, expected_locked, SGT_AMOUNT - 1]]
        sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [PROPOSAL_HASH, LOCK_DEADLINE, SGT_AMOUNT],
        ])

        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_lock_rejects_invalid_proposal_hash(self):
        """proposal_hash must be exactly 32 bytes."""
        curried = _free_curried(inner_hash=IDENTITY_INNER_HASH)
        inner_solution = [[CREATE_COIN, bytes32(b"\xab" * 32), SGT_AMOUNT]]
        sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [b"too-short", LOCK_DEADLINE, SGT_AMOUNT],
        ])

        with pytest.raises(PuzzleError):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
#                            spend-case dispatch
# ─────────────────────────────────────────────────────────────────────────────
class TestFreeDispatch:
    def test_unknown_spend_case_fails(self):
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_INNER_PUZHASH, SGT_AMOUNT],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([99, inner, 0, 0])

        with pytest.raises(PuzzleError):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
#                  sgt_locked_inner — RELEASE_DEADLINE
# ─────────────────────────────────────────────────────────────────────────────
class TestLockedReleaseDeadline:
    def test_release_after_deadline_emits_seconds_assert_and_recreate(self):
        curried = sgt_locked_inner_puzzle(
            SGT_FREE_MOD_HASH,
            PROPOSAL_TRACKER_STRUCT,
            OWNER_INNER_PUZHASH,
            PROPOSAL_HASH,
            LOCK_DEADLINE,
        )
        sol = Program.to([SGT_RELEASE_DEADLINE, 0, SGT_AMOUNT])

        out = curried.run(sol)
        conds = _conds_to_list(out)

        codes = [_atom_int(c[0]) for c in conds]
        assert ASSERT_SECONDS_ABSOLUTE in codes
        assert ASSERT_MY_AMOUNT in codes
        assert CREATE_COIN in codes

        # Seconds-absolute must be exactly LOCK_DEADLINE.
        sec = next(c for c in conds if _atom_int(c[0]) == ASSERT_SECONDS_ABSOLUTE)
        assert _atom_int(sec[1]) == LOCK_DEADLINE

        # CREATE_COIN destination is sgt_free_inner curried for the same owner.
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)
        assert _atom_bytes(cc[1]) == _expected_free_puzhash_for(OWNER_INNER_PUZHASH)
        assert _atom_int(cc[2]) == SGT_AMOUNT


# ─────────────────────────────────────────────────────────────────────────────
#                  sgt_locked_inner — RELEASE_EXEC
# ─────────────────────────────────────────────────────────────────────────────
class TestLockedReleaseExec:
    def test_release_via_exec_emits_announcement_assertion(self):
        tracker_inner_ph = bytes32(b"\x77" * 32)
        curried = sgt_locked_inner_puzzle(
            SGT_FREE_MOD_HASH,
            PROPOSAL_TRACKER_STRUCT,
            OWNER_INNER_PUZHASH,
            PROPOSAL_HASH,
            LOCK_DEADLINE,
        )
        sol = Program.to([SGT_RELEASE_EXEC, tracker_inner_ph, SGT_AMOUNT])

        out = curried.run(sol)
        conds = _conds_to_list(out)

        codes = [_atom_int(c[0]) for c in conds]
        assert ASSERT_PUZZLE_ANNOUNCEMENT in codes
        assert ASSERT_MY_AMOUNT in codes
        assert CREATE_COIN in codes

        # The CREATE_COIN must again be the free puzhash for the same owner.
        cc = next(c for c in conds if _atom_int(c[0]) == CREATE_COIN)
        assert _atom_bytes(cc[1]) == _expected_free_puzhash_for(OWNER_INNER_PUZHASH)

    def test_release_via_exec_rejects_non_b32_tracker_hash(self):
        curried = sgt_locked_inner_puzzle(
            SGT_FREE_MOD_HASH,
            PROPOSAL_TRACKER_STRUCT,
            OWNER_INNER_PUZHASH,
            PROPOSAL_HASH,
            LOCK_DEADLINE,
        )
        sol = Program.to([SGT_RELEASE_EXEC, b"too-short", SGT_AMOUNT])

        with pytest.raises(PuzzleError):
            curried.run(sol)

    def test_unknown_release_mode_fails(self):
        curried = sgt_locked_inner_puzzle(
            SGT_FREE_MOD_HASH,
            PROPOSAL_TRACKER_STRUCT,
            OWNER_INNER_PUZHASH,
            PROPOSAL_HASH,
            LOCK_DEADLINE,
        )
        sol = Program.to([99, 0, SGT_AMOUNT])

        with pytest.raises(PuzzleError):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
#                          Hashing / determinism sanity
# ─────────────────────────────────────────────────────────────────────────────
class TestSgtInnerHashing:
    def test_free_hash_is_deterministic(self):
        a = sgt_free_inner_hash(
            SGT_LOCKED_MOD_HASH, PROPOSAL_TRACKER_STRUCT, OWNER_INNER_PUZHASH
        )
        b = sgt_free_inner_hash(
            SGT_LOCKED_MOD_HASH, PROPOSAL_TRACKER_STRUCT, OWNER_INNER_PUZHASH
        )
        assert a == b
        assert isinstance(a, bytes) and len(a) == 32

    def test_free_hash_changes_with_owner(self):
        a = sgt_free_inner_hash(
            SGT_LOCKED_MOD_HASH, PROPOSAL_TRACKER_STRUCT, OWNER_INNER_PUZHASH
        )
        b = sgt_free_inner_hash(
            SGT_LOCKED_MOD_HASH, PROPOSAL_TRACKER_STRUCT, NEW_OWNER_INNER_PUZHASH
        )
        assert a != b

    def test_locked_hash_changes_with_proposal(self):
        a = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH, PROPOSAL_TRACKER_STRUCT, OWNER_INNER_PUZHASH,
            PROPOSAL_HASH, LOCK_DEADLINE
        )
        b = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH, PROPOSAL_TRACKER_STRUCT, OWNER_INNER_PUZHASH,
            bytes32(b"\xee" * 32) if PROPOSAL_HASH != bytes32(b"\xee" * 32)
                else bytes32(b"\xdd" * 32),
            LOCK_DEADLINE
        )
        # PROPOSAL_HASH constant is \xee*32, so b uses \xdd*32 — must differ
        assert a != b
