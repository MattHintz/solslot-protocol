"""End-to-end governance v2 lifecycle test.

Wires the full SGT-backed governance flow together:

    SGT free coin (LOCK)  ──► tracker (PROPOSE)  ──► tracker (EXECUTE)  ──► DID/pool

This is the integration counterpart to ``test_governance.py`` (unit-level)
and ``test_sgt_governance.py`` (SGT inner unit-level).  Together they cover
the CRITICAL-3 fix end-to-end:

  - Tracker PROPOSE asserts a LOCK announcement whose id is computable only
    by spending a real SGT free coin (CAT2 conservation gate)
  - Tracker EXECUTE checks vote_tally vs SGT_TOTAL_SUPPLY × QUORUM_BPS
  - EXECUTE emits the same on-the-wire SEND_MESSAGE as the legacy v1 puzzle
    (so DID and pool RECEIVE_MESSAGE handlers stay unchanged)

These tests run each puzzle directly with synthetic inputs, then verify
that the announcements / messages each side emits and asserts line up.
A full chia-sim simulator run is reserved for Milestone 2 testnet deploy.
"""
from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.sgt_driver import (
    SGT_LOCK,
    SINGLETON_LAUNCHER_HASH,
    TRK_EXECUTE,
    TRK_PROPOSE,
    bill_freeze,
    bill_mint as build_mint_bill,
    cat_sgt_free_puzzle_hash,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_hash,
    sgt_locked_inner_mod,
    proposal_hash_from_bill,
    proposal_tracker_inner_puzzle,
    proposal_tracker_mod,
)


# ── Compiled puzzles for cross-side verification ─────────────────────────────
QUORUM_DID_MOD = load_clvm(
    "quorum_did_inner.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)


# ── Condition codes ──────────────────────────────────────────────────────────
CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
SEND_MESSAGE = 66
RECEIVE_MESSAGE = 67


# ── Protocol-wide fixtures ───────────────────────────────────────────────────
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
MIN_PROPOSAL_STAKE = 10_000  # 1% anti-spam stake

# Identity puzzle: stable hash, returns its solution as conditions
IDENTITY_INNER = Program.to(1)
IDENTITY_HASH = bytes32(IDENTITY_INNER.get_tree_hash())
PROPERTY_ID = bytes32(b"\x71" * 32)
PROPERTY_REGISTRY_PUZHASH = bytes32(b"\x72" * 32)


# ── Helpers ──────────────────────────────────────────────────────────────────
def mint_bill(deed_full_puzhash: bytes32) -> Program:
    return build_mint_bill(deed_full_puzhash, PROPERTY_ID, PROPERTY_REGISTRY_PUZHASH)


def _conds(prog: Program) -> list:
    return [list(item.as_iter()) for item in prog.as_iter()]


def _atom_int(prog: Program) -> int:
    return int.from_bytes(prog.atom, "big") if prog.atom else 0


def _atom_bytes(prog: Program) -> bytes:
    return bytes(prog.atom) if prog.atom is not None else b""


def _full_singleton_ph(struct: Program, inner_ph: bytes32) -> bytes32:
    """Compute curry(SINGLETON_MOD, struct, inner_ph).get_tree_hash()."""
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
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            quoted_program_hash(bytes32(struct.get_tree_hash())),
            quoted_program_hash(inner_ph),
        )
    )


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


def _tracker_id_and_ph(curried: Program) -> tuple[bytes32, bytes32]:
    inner_ph = bytes32(curried.get_tree_hash())
    full_ph = _full_singleton_ph(TRACKER_STRUCT, inner_ph)
    fake_parent = bytes32(b"\x00" * 32)
    my_id = bytes32(hashlib.sha256(fake_parent + full_ph + bytes([1])).digest())
    return my_id, inner_ph


# ─────────────────────────────────────────────────────────────────────────────
#                          SGT lock ↔ tracker propose
# ─────────────────────────────────────────────────────────────────────────────
class TestLockProposeIntegration:
    def test_sgt_lock_announcement_id_matches_tracker_assertion(self):
        """The SGT free coin emits a CREATE_PUZZLE_ANNOUNCEMENT on LOCK; the
        tracker's PROPOSE emits an ASSERT_PUZZLE_ANNOUNCEMENT.  Their
        announcement ids must match for the bundle to be valid."""
        bill = mint_bill(bytes32(b"\x33" * 32))
        proposal_hash = proposal_hash_from_bill(bill)
        first_vote = 600_000
        deadline = 2_000_000_000

        # ── Side 1: SGT free coin emits LOCK ─────────────────────────────
        sgt_free = sgt_free_inner_puzzle(
            SGT_LOCKED_MOD_HASH, TRACKER_STRUCT, IDENTITY_HASH
        )
        # Identity inner returns its solution as conditions; we hand-craft
        # the create_coin to land in the locked-state puzhash.
        expected_locked = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH, TRACKER_STRUCT, IDENTITY_HASH, proposal_hash, deadline
        )
        inner_solution = [[CREATE_COIN, expected_locked, first_vote]]
        sgt_sol = Program.to([
            SGT_LOCK,
            IDENTITY_INNER,
            inner_solution,
            [proposal_hash, deadline, first_vote],
        ])
        sgt_conds = _conds(sgt_free.run(sgt_sol))

        # Locate the CREATE_PUZZLE_ANNOUNCEMENT
        announce = next(
            c for c in sgt_conds if _atom_int(c[0]) == CREATE_PUZZLE_ANNOUNCEMENT
        )
        announcement_content = _atom_bytes(announce[1])

        # The SGT coin's full puzzle hash (CAT-wrapped) is the announcement sender
        sender_ph = cat_sgt_free_puzzle_hash(
            TRACKER_STRUCT,
            SGT_FREE_MOD_HASH,
            SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH,
            SGT_TAIL_HASH,
            IDENTITY_HASH,
        )
        announcement_id = bytes32(
            hashlib.sha256(sender_ph + announcement_content).digest()
        )

        # ── Side 2: Tracker PROPOSE asserts the same announcement id ─────
        curried = _curry_tracker()
        my_id, my_ph = _tracker_id_and_ph(curried)
        sol = Program.to([
            my_id, my_ph, 1,
            TRK_PROPOSE,
            [proposal_hash, bill, IDENTITY_HASH, first_vote, deadline],
        ])
        trk_conds = _conds(curried.run(sol))

        # Find the assertion ids
        assertions = [
            _atom_bytes(c[1])
            for c in trk_conds
            if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        ]

        # The SGT-emitted announcement id must be one of the tracker's asserts.
        assert announcement_id in assertions, (
            f"SGT lock announcement id {announcement_id.hex()} not asserted by tracker. "
            f"Tracker asserted: {[a.hex() for a in assertions]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
#                       Tracker execute ↔ DID receive
# ─────────────────────────────────────────────────────────────────────────────
class TestExecuteDIDIntegration:
    def test_tracker_execute_mint_message_matches_did_receive(self):
        """Tracker EXECUTE for a MINT bill must emit:
        - SEND_MESSAGE 0x10 to DID (mode matches DID's RECEIVE_MESSAGE 0x10
          per CHIP-25 — both modes must be identical for the message to pair)
        - ASSERT_PUZZLE_ANNOUNCEMENT(DID_full_ph || deed_full_ph) — the SAME
          announcement the DID emits via its CREATE_PUZZLE_ANNOUNCEMENT and
          the launcher asserts.  This atomicity bind guarantees gov+DID+launcher
          all commit-or-fail together.
        """
        deed_full_ph = bytes32(b"\x33" * 32)
        bill = mint_bill(deed_full_ph)
        proposal_hash = proposal_hash_from_bill(bill)
        deadline = 2_000_000_000

        # Tracker at quorum
        curried = _curry_tracker(
            proposal_hash=proposal_hash,
            bill_op=bill,
            vote_tally=SGT_TOTAL_SUPPLY,  # 100% > 50% quorum
            voting_deadline=deadline,
        )
        my_id, my_ph = _tracker_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, 1, TRK_EXECUTE, 0])
        trk_conds = _conds(curried.run(sol))

        # ── Side 1: tracker's SEND_MESSAGE (must be mode 0x10) ───────────
        send = next(c for c in trk_conds if _atom_int(c[0]) == SEND_MESSAGE)
        send_mode = _atom_int(send[1])
        msg_content = _atom_bytes(send[2])
        assert send_mode == 0x10, (
            f"Gov MINT send must use mode 0x10 to pair with DID's RECEIVE 0x10; "
            f"got 0x{send_mode:x}"
        )
        assert len(send) == 3, "mode 0x10 SEND has no var_args"

        # ── Side 2: DID's RECEIVE_MESSAGE (also mode 0x10) ───────────────
        did_inner = QUORUM_DID_MOD.curry(
            bytes32(QUORUM_DID_MOD.get_tree_hash()),
            TRACKER_STRUCT,
        )
        did_sol = Program.to([1, deed_full_ph, my_ph])
        did_conds = _conds(did_inner.run(did_sol))
        recv = next(c for c in did_conds if _atom_int(c[0]) == RECEIVE_MESSAGE)
        recv_mode = _atom_int(recv[1])
        recv_content = _atom_bytes(recv[2])
        assert recv_mode == 0x10, f"DID RECEIVE mode must be 0x10; got 0x{recv_mode:x}"

        # Modes match → message can pair on-chain.
        assert send_mode == recv_mode, "Gov SEND mode must equal DID RECEIVE mode"
        # Content matches → routing succeeds.
        assert msg_content == recv_content

        # ── Side 3: gov's defense-in-depth DID-announcement assertion ─────
        # The DID emits CREATE_PUZZLE_ANNOUNCEMENT(deed_full_ph).
        # The on-chain announcement id is sha256(DID_full_ph || deed_full_ph).
        # Gov asserts this same id; launcher asserts it too → atomic mint.
        did_announce = next(
            c for c in did_conds
            if _atom_int(c[0]) == 62  # CREATE_PUZZLE_ANNOUNCEMENT
        )
        assert _atom_bytes(did_announce[1]) == deed_full_ph

        gov_assertion = next(
            c for c in trk_conds
            if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT
        )
        expected_announce_id = bytes32(
            hashlib.sha256(DID_PUZHASH + deed_full_ph).digest()
        )
        assert _atom_bytes(gov_assertion[1]) == expected_announce_id, (
            "Gov MINT must assert sha256(DID_full_ph || deed_full_ph) — the "
            "same announcement the launcher asserts."
        )

    def test_tracker_execute_freeze_message_matches_pool_receive_format(self):
        """Tracker EXECUTE for FREEZE bill emits SEND_MESSAGE in the same
        format the legacy pool's GOVERNANCE case expects.  We don't run
        pool here (its mod hash is curried in tracker), but we verify the
        message body shape is the documented "GOV " + status tuple."""
        bill = bill_freeze(0)  # FROZEN
        proposal_hash = proposal_hash_from_bill(bill)
        deadline = 2_000_000_000

        curried = _curry_tracker(
            proposal_hash=proposal_hash,
            bill_op=bill,
            vote_tally=SGT_TOTAL_SUPPLY,
            voting_deadline=deadline,
        )
        my_id, my_ph = _tracker_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, 1, TRK_EXECUTE, 0])
        conds = _conds(curried.run(sol))

        send = next(c for c in conds if _atom_int(c[0]) == SEND_MESSAGE)
        send_mode = _atom_int(send[1])
        msg_content = _atom_bytes(send[2])

        # FREEZE uses mode 0x10 (matches pool RECEIVE_MESSAGE 0x10)
        assert send_mode == 0x10, f"FREEZE send mode must be 0x10; got 0x{send_mode:x}"
        assert len(send) == 3  # no var_args

        # Expected: PROTOCOL_PREFIX || sha256tree(("GOV ", 0))
        expected_body = Program.to([b"GOV ", 0]).get_tree_hash()
        expected_msg = b"\x53" + bytes(expected_body)
        assert msg_content == expected_msg


# ─────────────────────────────────────────────────────────────────────────────
#                      Quorum boundary (CRITICAL-3 closure)
# ─────────────────────────────────────────────────────────────────────────────
class TestQuorumBoundary:
    """The whole point of the v2 refactor: vote_tally is bounded by the sum
    of SGT amounts that emitted matching LOCK announcements.  These tests
    verify the puzzle-side quorum check is exact."""

    def test_execute_at_exact_quorum_boundary_passes(self):
        """vote_tally * 10000 == quorum * total_supply → boundary is allowed."""
        bill = mint_bill(bytes32(b"\x33" * 32))
        # 50% of 1M = 500_000. quorum=5000 (50%). 500_000 * 10000 == 5000 * 1_000_000.
        proposal_hash = proposal_hash_from_bill(bill)  # noqa: F841 (sanity)
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=500_000,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, 1, TRK_EXECUTE, [bytes32(b"\xdd" * 32)]])
        # Should not raise.
        _ = curried.run(sol)

    def test_execute_one_below_quorum_fails(self):
        """vote_tally that's exactly 1 below the boundary must fail."""
        bill = mint_bill(bytes32(b"\x33" * 32))
        # 499_999 * 10000 = 4_999_990_000 < 5_000_000_000
        curried = _curry_tracker(
            proposal_hash=proposal_hash_from_bill(bill),
            bill_op=bill,
            vote_tally=499_999,
            voting_deadline=2_000_000_000,
        )
        my_id, my_ph = _tracker_id_and_ph(curried)
        sol = Program.to([my_id, my_ph, 1, TRK_EXECUTE, [bytes32(b"\xdd" * 32)]])
        with pytest.raises(ValueError):
            curried.run(sol)
