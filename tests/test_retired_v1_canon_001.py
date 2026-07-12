"""Regression tests for V1-CANON-001 (CRITICAL).

Audit reference: ``research/CANON_CHIA_PROJECT_AUDIT_2026_04_26.md``.

Bug summary (pre-fix):
    ``sgt_free_inner.clsp`` filtered user inner-puzzle conditions in TRANSFER
    mode but only rejected ``REMARK`` (with PROTOCOL_PREFIX), ``SEND_MESSAGE``,
    and ``RECEIVE_MESSAGE``.  It did NOT reject ``CREATE_PUZZLE_ANNOUNCEMENT``
    or ``CREATE_COIN_ANNOUNCEMENT`` carrying the protocol prefix.  An attacker
    could spend a SGT in TRANSFER mode (SGT remains free), emit one valid
    CREATE_COIN, AND emit a forged CREATE_PUZZLE_ANNOUNCEMENT carrying:

        PROTOCOL_PREFIX || sha256tree(LOCK_TAG, proposal_hash, amount, deadline)

    The proposal tracker accepts that announcement as SGT vote weight via
    ASSERT_PUZZLE_ANNOUNCEMENT.  Repeat → inflate VOTE_TALLY past quorum →
    EXECUTE arbitrary governance bills (mint, freeze, settle).  This
    completely defeats CRITICAL-3's SGT-CAT conservation invariant.

Fix (this commit):
    ``check_no_protocol_prefix_abuse`` now rejects ALL inner-emitted
    ``CREATE_PUZZLE_ANNOUNCEMENT`` and ``CREATE_COIN_ANNOUNCEMENT``.  The
    SGT wrapper retains exclusive authority to emit the LOCK announcement
    in LOCK mode; inner puzzles cannot forge any announcement.

Test scope:
    1. TRANSFER rejects inner-emitted CREATE_PUZZLE_ANNOUNCEMENT (any content)
    2. TRANSFER rejects inner-emitted CREATE_COIN_ANNOUNCEMENT (any content)
    3. TRANSFER rejects the EXACT spoof attack (protocol-prefixed LOCK content)
    4. LOCK rejects additional inner-emitted CREATE_PUZZLE_ANNOUNCEMENT
       (the wrapper emits the LOCK announcement; inner cannot add more)
    5. LOCK still produces exactly the wrapper-emitted LOCK announcement
       (regression: legitimate flow still works after the filter tightening)
"""
from __future__ import annotations

import hashlib

import pytest
from chia_rs.sized_bytes import bytes32
from clvm.casts import int_to_bytes
from clvm.SExp import SExp

from chia_puzzles_py.programs import P2_CONDITIONS  # not used; placeholder import safety
from chia.types.blockchain_format.program import Program

from solslot_puzzles.sgt_driver import (
    SGT_TRANSFER,
    SGT_LOCK,
    sgt_free_inner_puzzle,
    sgt_locked_inner_hash,
    sgt_free_inner_mod,
    sgt_locked_inner_mod,
    make_proposal_tracker_struct,
)


# ── Condition codes (keep in sync with condition_codes.clib) ─────────────────
CREATE_COIN = 51
CREATE_COIN_ANNOUNCEMENT = 60
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63

# PROTOCOL_PREFIX from utility_macros.clib (literal 0x53 = 'S')
PROTOCOL_PREFIX = b"\x53"

# LOCK_TAG from sgt_free_inner.clsp (4 ASCII bytes "LOCK")
LOCK_TAG = b"\x4c\x4f\x43\x4b"


# ── Fixtures ─────────────────────────────────────────────────────────────────
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
TRACKER_LAUNCHER_ID = bytes32(b"\xbb" * 32)
TRACKER_STRUCT = make_proposal_tracker_struct(SINGLETON_MOD_HASH, TRACKER_LAUNCHER_ID)

SGT_FREE_MOD_HASH = bytes32(sgt_free_inner_mod().get_tree_hash())
SGT_LOCKED_MOD_HASH = bytes32(sgt_locked_inner_mod().get_tree_hash())

OWNER_HASH = bytes32(b"\xaa" * 32)
NEW_OWNER_HASH = bytes32(b"\xcc" * 32)

# Realistic attack params
PROPOSAL_HASH = bytes32(b"\xee" * 32)
DEADLINE = 1_700_000_300
SGT_AMOUNT = 100_000


# ── Helpers ──────────────────────────────────────────────────────────────────
def _trivial_inner_puzzle_emitting(conditions: list) -> Program:
    """`(mod () (q . CONDITIONS))` — emits the given conditions verbatim.

    Used for tests where the conditions can be hard-coded into the puzzle
    (TRANSFER mode tests; the destination doesn't depend on the inner hash).
    """
    return Program.to((1, conditions))


def _free_curried(inner_hash: bytes32 = OWNER_HASH) -> Program:
    return sgt_free_inner_puzzle(SGT_LOCKED_MOD_HASH, TRACKER_STRUCT, inner_hash)


# Identity inner: `Program.to(1)` returns its solution verbatim.  Stable hash
# (= sha256(0x01, 0x01)).  Used for LOCK-mode tests where the destination
# (= locked-state puzhash) DEPENDS on the owner's inner hash, so we need a
# fixed-hash inner whose conditions can be supplied via solution rather than
# curried in.  This is the same pattern used in test_governance_v2_lifecycle.py.
IDENTITY_INNER = Program.to(1)
IDENTITY_HASH = bytes32(IDENTITY_INNER.get_tree_hash())


def _forged_lock_content(proposal_hash: bytes32, amount: int, deadline: int) -> bytes:
    """Build the exact announcement content that the proposal tracker accepts
    as SGT vote weight in PROPOSE/VOTE.  Pre-fix this could be forged from
    inner conditions; post-fix the inner cannot emit any announcement."""
    body = Program.to([LOCK_TAG, proposal_hash, amount, deadline])
    return PROTOCOL_PREFIX + bytes(body.get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────────
# 1-3 — TRANSFER rejects all inner-emitted CREATE_*_ANNOUNCEMENT
# ─────────────────────────────────────────────────────────────────────────────
class TestTransferRejectsAnnouncements:
    """The exact attack from V1-CANON-001 plus generalizations."""

    def test_transfer_rejects_protocol_prefixed_create_puzzle_announcement(self):
        """The exact bug from V1-CANON-001 / poc_sgt_lock_announcement_spoof.py."""
        forged = _forged_lock_content(PROPOSAL_HASH, SGT_AMOUNT, DEADLINE)
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_HASH, SGT_AMOUNT],     # legitimate transfer
            [CREATE_PUZZLE_ANNOUNCEMENT, forged],          # forged LOCK announcement
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(Exception):  # PuzzleError / EvalError
            curried.run(sol)

    def test_transfer_rejects_arbitrary_create_puzzle_announcement(self):
        """Even non-protocol-prefixed announcements are rejected — wrapper has
        exclusive authority over all CREATE_*_ANNOUNCEMENT in SGT context."""
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_HASH, SGT_AMOUNT],
            [CREATE_PUZZLE_ANNOUNCEMENT, b"hello world"],  # arbitrary content
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(Exception):
            curried.run(sol)

    def test_transfer_rejects_protocol_prefixed_create_coin_announcement(self):
        """Coin announcements are also rejected (defense in depth)."""
        forged = _forged_lock_content(PROPOSAL_HASH, SGT_AMOUNT, DEADLINE)
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_HASH, SGT_AMOUNT],
            [CREATE_COIN_ANNOUNCEMENT, forged],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(Exception):
            curried.run(sol)

    def test_transfer_rejects_arbitrary_create_coin_announcement(self):
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_HASH, SGT_AMOUNT],
            [CREATE_COIN_ANNOUNCEMENT, b"some data"],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        with pytest.raises(Exception):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
# 4 — LOCK rejects additional inner-emitted CREATE_PUZZLE_ANNOUNCEMENT
# ─────────────────────────────────────────────────────────────────────────────
class TestLockRejectsExtraAnnouncements:
    """The wrapper itself emits exactly one LOCK announcement; inner puzzles
    must not be able to emit additional CREATE_*_ANNOUNCEMENT in LOCK mode."""

    def test_lock_rejects_inner_emitted_extra_announcement(self):
        """Inner emits legit lock CREATE_COIN PLUS extra announcement → reject."""
        expected_locked = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH, TRACKER_STRUCT, IDENTITY_HASH, PROPOSAL_HASH, DEADLINE
        )
        curried = _free_curried(inner_hash=IDENTITY_HASH)
        # Identity puzzle returns its solution; solution carries the conditions list.
        inner_solution = [
            [CREATE_COIN, expected_locked, SGT_AMOUNT],
            [CREATE_PUZZLE_ANNOUNCEMENT, b"\x53extra-protocol-data"],
        ]
        sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [PROPOSAL_HASH, DEADLINE, SGT_AMOUNT],
        ])

        with pytest.raises(Exception):
            curried.run(sol)


# ─────────────────────────────────────────────────────────────────────────────
# 5 — Legitimate LOCK still works (regression)
# ─────────────────────────────────────────────────────────────────────────────
class TestLegitimateLockStillWorks:
    """Tighten the filter without breaking the happy path."""

    def test_legit_lock_emits_exactly_one_protocol_announcement(self):
        """Wrapper emits the LOCK announcement; inner emits only CREATE_COIN
        to the locked-state puzhash.  Nothing else."""
        expected_locked = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH, TRACKER_STRUCT, IDENTITY_HASH, PROPOSAL_HASH, DEADLINE
        )
        curried = _free_curried(inner_hash=IDENTITY_HASH)
        inner_solution = [[CREATE_COIN, expected_locked, SGT_AMOUNT]]
        sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [PROPOSAL_HASH, DEADLINE, SGT_AMOUNT],
        ])
        out = curried.run(sol)
        conds = list(out.as_iter())

        # Count CREATE_PUZZLE_ANNOUNCEMENT — must be exactly 1 (wrapper-emitted).
        ann = [
            c for c in conds
            if int.from_bytes(bytes(list(c.as_iter())[0].atom or b""), "big")
            == CREATE_PUZZLE_ANNOUNCEMENT
        ]
        assert len(ann) == 1, f"expected exactly 1 CREATE_PUZZLE_ANNOUNCEMENT, got {len(ann)}"

        # The single announcement must carry the protocol prefix.
        ann_content = bytes(list(ann[0].as_iter())[1].atom or b"")
        assert ann_content[:1] == PROTOCOL_PREFIX, (
            f"wrapper-emitted lock announcement must start with PROTOCOL_PREFIX, "
            f"got {ann_content[:1]!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# 6 — The PoC stays as a vulnerability witness; verify it now FAILS to forge
# ─────────────────────────────────────────────────────────────────────────────
class TestPocNowFailsToForge:
    """Reproduce the exact attack from poc_sgt_lock_announcement_spoof.py.
    Pre-fix: PuzzleError NOT raised, forged announcement emitted alongside
    legit CREATE_COIN.  Post-fix: PuzzleError raised, attack rejected."""

    def test_poc_attack_now_rejected(self):
        forged_content = _forged_lock_content(PROPOSAL_HASH, SGT_AMOUNT, DEADLINE)
        inner = _trivial_inner_puzzle_emitting([
            [CREATE_COIN, NEW_OWNER_HASH, SGT_AMOUNT],
            [CREATE_PUZZLE_ANNOUNCEMENT, forged_content],
        ])
        curried = _free_curried(inner_hash=inner.get_tree_hash())
        sol = Program.to([SGT_TRANSFER, inner, 0, 0])

        # The fix MUST cause this to raise.  Pre-fix this returned conditions
        # including the forged announcement (see tests/poc_sgt_lock_announcement_spoof.py).
        with pytest.raises(Exception) as exc_info:
            curried.run(sol)

        # Sanity: the failure should originate in the filter (raise via `(x)`).
        # We don't assert exact error strings since CLVM error formats differ.
        assert exc_info.value is not None
