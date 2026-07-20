"""Unit tests for ``build_sgt_lock_coin_spend`` and ``build_tracker_vote_coin_spend``.

Both builders are the canonical Python source-of-truth for the portal's TS
spend-builder port (Phase 3b).  These tests verify:

  * The two CoinSpends pair cryptographically — the SGT lock's
    ``CREATE_PUZZLE_ANNOUNCEMENT`` id equals the tracker VOTE's
    ``ASSERT_PUZZLE_ANNOUNCEMENT`` id.
  * The SGT lock's puzzle_reveal hashes to ``cat_sgt_free_puzzle_hash(...)``
    for the same ``(struct, free_mod_h, locked_mod_h, cat_mod_h, tail_h,
    voter_ph)`` tuple.
  * The tracker VOTE's puzzle_reveal hashes to
    ``puzzle_for_singleton(launcher_id, tracker_inner).get_tree_hash()``.
  * Each CoinSpend round-trips through bytes (so the TS port has stable
    fixtures to cross-validate against).
  * Defensive input validation rejects malformed args.
"""
from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia_rs import CoinSpend
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.sgt_driver import (
    SGT_LOCK,
    TEST_KOS_MINT_EXECUTE_PUBKEY,
    TRK_VOTE,
    bill_mint,
    build_sgt_lock_coin_spend,
    build_tracker_vote_coin_spend,
    cat_sgt_free_puzzle_hash,
    sgt_free_inner_mod,
    sgt_locked_inner_mod,
    sgt_tail_hash,
    proposal_hash_from_bill,
    proposal_tracker_inner_puzzle,
)


# ── Condition codes (avoid pulling in chia.types just for opcodes) ──────────
CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
ASSERT_BEFORE_SECONDS_ABSOLUTE = 85
PROTOCOL_PREFIX = bytes.fromhex("53")  # "P"
LOCK_TAG = 0x4C4F434B


# ── Test fixtures ────────────────────────────────────────────────────────────
TRACKER_LAUNCHER_ID = bytes32(b"\xb0" * 32)
TRACKER_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (TRACKER_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
POOL_LAUNCHER_ID = bytes32(b"\xc0" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
DID_PUZHASH = bytes32(b"\xd0" * 32)

# Use the real CAT_MOD_HASH because the on-chain SGT free coin is CAT2-wrapped
# and the builder constructs the puzzle reveal via the real CAT2 mod.  The
# tracker's curried CAT_MOD_HASH must match what the SGT spend actually uses.
CAT_MOD_HASH_B32 = bytes32(CAT_MOD_HASH)

# Real SGT TAIL with a fake genesis coin id (so cat_sgt_free_puzhash math
# uses a stable, deterministic tail hash).
SGT_TAIL_GENESIS_COIN_ID = bytes32(b"\xa0" * 32)
SGT_TAIL_HASH = sgt_tail_hash(SGT_TAIL_GENESIS_COIN_ID)

SGT_FREE_MOD_HASH = bytes32(sgt_free_inner_mod().get_tree_hash())
SGT_LOCKED_MOD_HASH = bytes32(sgt_locked_inner_mod().get_tree_hash())

QUORUM_BPS = 5000
VOTING_WINDOW = 300
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000

# Identity puzzle: Program.to(1) returns its solution as conditions
IDENTITY_INNER = Program.to(1)
IDENTITY_HASH = bytes32(IDENTITY_INNER.get_tree_hash())


def _curry_open_tracker(
    *,
    proposal_hash: bytes32,
    bill: Program,
    vote_tally: int,
    voting_deadline: int,
) -> Program:
    """Curry the tracker singleton inner into an OPEN state ready for VOTE.

    ``proposal_hash`` MUST be passed as the raw 32-byte value (not converted
    to int) so CLVM treats it as a 32-byte atom in the curried env.  The
    puzzle's ``(sha256 1 PROPOSAL_HASH)`` only matches the on-chain spend if
    the atom width is the same on both sides.
    """
    return proposal_tracker_inner_puzzle(
        TRACKER_STRUCT,
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH_B32,
        SGT_TAIL_HASH,
        DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        SGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        TEST_KOS_MINT_EXECUTE_PUBKEY,
        proposal_hash=proposal_hash,
        bill_operation=bill,
        vote_tally=vote_tally,
        voting_deadline=voting_deadline,
    )


def _make_fake_coin(
    *, parent: bytes32 = bytes32(b"\xfe" * 32), puzzle_hash: bytes32, amount: int
) -> Coin:
    """Construct a Coin with deterministic parent so tests are reproducible."""
    return Coin(parent, puzzle_hash, uint64(amount))


def _run_inner(inner_puzzle: Program, inner_solution: Program) -> list[list[Program]]:
    """Run the inner puzzle (sgt_free_inner or proposal_tracker_inner) against
    its inner solution and return the conditions list.

    The CoinSpend stores the FULL CAT2/singleton-wrapped puzzle reveal, but
    those outer wrappers require real lineage proofs (and CAT2 ring closure)
    that our synthetic-coin unit tests can't satisfy.  The outer wrappers are
    already exhaustively tested by chia; what matters for sgt_driver builder
    correctness is that the inner emits/asserts the right protocol-level
    conditions (announcement pairing, recurry, deadline), which we verify by
    running the inner directly.
    """
    out = inner_puzzle.run(inner_solution)
    return [list(item.as_iter()) for item in out.as_iter()]


def _extract_cat_inner_solution(coin_spend: CoinSpend) -> Program:
    """Extract the CAT2-inner solution from a CAT2-wrapped CoinSpend.

    ``unsigned_spend_bundle_for_spendable_cats`` packs the inner solution at
    position 0 of the CAT2 outer solution: ``(inner_solution, lineage_proof,
    prev_id, my_info, next_info, subtotal, extra_delta)``.
    """
    full_sol = Program.from_bytes(bytes(coin_spend.solution))
    return full_sol.first()


def _extract_singleton_inner_solution(coin_spend: CoinSpend) -> Program:
    """Extract the inner solution from a singleton_top_layer_v1_1 CoinSpend.

    ``solution_for_singleton`` packs solution as ``(lineage_proof, my_amount,
    inner_solution)`` — inner is at index 2.
    """
    full_sol = Program.from_bytes(bytes(coin_spend.solution))
    return full_sol.rest().rest().first()


def _find_cond(conds: list[list[Program]], opcode: int) -> list[Program] | None:
    """Return the first condition whose first atom equals ``opcode``, or None."""
    for c in conds:
        if not c:
            continue
        head = c[0]
        if head.atom and int.from_bytes(head.atom, "big") == opcode:
            return c
    return None


def _find_all_conds(
    conds: list[list[Program]], opcode: int
) -> list[list[Program]]:
    out = []
    for c in conds:
        if not c:
            continue
        head = c[0]
        if head.atom and int.from_bytes(head.atom, "big") == opcode:
            out.append(c)
    return out


# ─────────────────────────────────────────────────────────────────────────────
#                       build_sgt_lock_coin_spend
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildSgtLockCoinSpend:
    """The SGT lock builder produces a CAT2-wrapped sgt_free_inner LOCK
    CoinSpend that emits the canonical LOCK announcement and conserves
    CAT2 supply (single-coin full-amount lock)."""

    bill = bill_mint(
        bytes32(b"\x33" * 32),
        bytes32(b"\x71" * 32),
        bytes32(b"\x72" * 32),
    )
    proposal_hash = proposal_hash_from_bill(bill)
    vote_amount = 600_000
    deadline = 2_000_000_000

    def _build(self, *, amount: int = vote_amount) -> tuple[CoinSpend, bytes32, Program]:
        """Helper: build a SGT lock CoinSpend using IDENTITY_INNER as voter,
        returning (coin_spend, expected_puzzle_hash, free_inner_puzzle).

        ``free_inner_puzzle`` is the curried ``sgt_free_inner.clsp`` — used
        by tests to run the inner directly (bypassing the CAT2 outer's
        lineage-proof requirement which our synthetic coins cannot satisfy).
        """
        voter_ph = IDENTITY_HASH
        expected_puzzle_hash = cat_sgt_free_puzzle_hash(
            TRACKER_STRUCT,
            SGT_FREE_MOD_HASH,
            SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH_B32,
            SGT_TAIL_HASH,
            voter_ph,
        )
        sgt_coin = _make_fake_coin(puzzle_hash=expected_puzzle_hash, amount=amount)
        # Identity inner: solution IS the conditions list.  Emit one
        # CREATE_COIN to the canonical locked puzhash with amount = coin.amount.
        from solslot_puzzles.sgt_driver import (
            sgt_free_inner_puzzle,
            sgt_locked_inner_hash,
        )

        locked_ph = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH,
            TRACKER_STRUCT,
            voter_ph,
            self.proposal_hash,
            self.deadline,
        )
        voter_solution = Program.to([[CREATE_COIN, locked_ph, amount]])
        coin_spend = build_sgt_lock_coin_spend(
            sgt_coin=sgt_coin,
            voter_inner_puzzle=IDENTITY_INNER,
            voter_inner_solution=voter_solution,
            proposal_tracker_struct=TRACKER_STRUCT,
            sgt_tail_hash=SGT_TAIL_HASH,
            lineage_proof=LineageProof(),
            proposal_hash=self.proposal_hash,
            deadline=self.deadline,
        )
        free_inner = sgt_free_inner_puzzle(
            SGT_LOCKED_MOD_HASH, TRACKER_STRUCT, voter_ph
        )
        return coin_spend, expected_puzzle_hash, free_inner

    def test_puzzle_reveal_hashes_to_cat_sgt_free_puzhash(self):
        """The full puzzle reveal of the CAT-wrapped SGT free coin must
        hash to the same value as ``cat_sgt_free_puzzle_hash(...)`` —
        otherwise the spend would land on the wrong coin id."""
        coin_spend, expected_ph, _ = self._build()
        actual_ph = bytes32(coin_spend.puzzle_reveal.get_tree_hash())
        assert actual_ph == expected_ph

    def test_spend_targets_supplied_coin(self):
        """The CoinSpend's `coin` field must equal the input SGT coin."""
        coin_spend, expected_ph, _ = self._build()
        assert coin_spend.coin.puzzle_hash == expected_ph
        assert coin_spend.coin.amount == self.vote_amount

    def test_running_spend_emits_lock_announcement(self):
        """Running the SGT lock spend yields exactly one
        ``CREATE_PUZZLE_ANNOUNCEMENT`` with the canonical LOCK message."""
        coin_spend, _, free_inner = self._build()
        inner_sol = _extract_cat_inner_solution(coin_spend)
        conds = _run_inner(free_inner, inner_sol)
        announces = _find_all_conds(conds, CREATE_PUZZLE_ANNOUNCEMENT)
        assert len(announces) == 1, (
            f"expected exactly 1 CREATE_PUZZLE_ANNOUNCEMENT, got {len(announces)}"
        )
        msg = bytes(announces[0][1].atom)
        assert msg.startswith(PROTOCOL_PREFIX), (
            f"announcement must carry protocol prefix; got {msg.hex()}"
        )
        # The body is sha256tree(LOCK_TAG proposal_hash amount deadline).
        body = msg[len(PROTOCOL_PREFIX):]
        expected_body = Program.to(
            [LOCK_TAG, self.proposal_hash, self.vote_amount, self.deadline]
        ).get_tree_hash()
        assert body == bytes(expected_body)

    def test_running_spend_asserts_lock_deadline(self):
        """The SGT lock spend must assert
        ``ASSERT_BEFORE_SECONDS_ABSOLUTE deadline``."""
        coin_spend, _, free_inner = self._build()
        inner_sol = _extract_cat_inner_solution(coin_spend)
        conds = _run_inner(free_inner, inner_sol)
        a = _find_cond(conds, ASSERT_BEFORE_SECONDS_ABSOLUTE)
        assert a is not None
        assert int.from_bytes(a[1].atom, "big") == self.deadline

    def test_coin_spend_serialises_round_trip(self):
        """The CoinSpend serialises to bytes and back losslessly — required
        so the TS port can cross-validate against a fixed byte fixture."""
        coin_spend, _, _ = self._build()
        raw = bytes(coin_spend)
        rehydrated = CoinSpend.from_bytes(raw)
        assert rehydrated == coin_spend

    def test_rejects_non_bytes32_proposal_hash(self):
        with pytest.raises(ValueError, match="proposal_hash must be 32 bytes"):
            build_sgt_lock_coin_spend(
                sgt_coin=_make_fake_coin(puzzle_hash=bytes32(b"\x00" * 32), amount=1),
                voter_inner_puzzle=IDENTITY_INNER,
                voter_inner_solution=Program.to([]),
                proposal_tracker_struct=TRACKER_STRUCT,
                sgt_tail_hash=SGT_TAIL_HASH,
                lineage_proof=LineageProof(),
                proposal_hash=b"short",  # type: ignore[arg-type]
                deadline=1_000,
            )

    def test_rejects_out_of_range_deadline(self):
        with pytest.raises(ValueError, match="deadline must be a uint64"):
            build_sgt_lock_coin_spend(
                sgt_coin=_make_fake_coin(puzzle_hash=bytes32(b"\x00" * 32), amount=1),
                voter_inner_puzzle=IDENTITY_INNER,
                voter_inner_solution=Program.to([]),
                proposal_tracker_struct=TRACKER_STRUCT,
                sgt_tail_hash=SGT_TAIL_HASH,
                lineage_proof=LineageProof(),
                proposal_hash=bytes32(b"\x11" * 32),
                deadline=-1,
            )


# ─────────────────────────────────────────────────────────────────────────────
#                       build_tracker_vote_coin_spend
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildTrackerVoteCoinSpend:
    """The tracker VOTE builder produces a singleton-wrapped TRK_VOTE
    CoinSpend that recreates the tracker singleton with increased tally
    and asserts the canonical LOCK announcement id of the voter."""

    bill = bill_mint(
        bytes32(b"\x44" * 32),
        bytes32(b"\x71" * 32),
        bytes32(b"\x72" * 32),
    )
    proposal_hash = proposal_hash_from_bill(bill)
    initial_tally = 200_000
    additional_vote = 400_000
    deadline = 2_000_000_000

    def _build(self) -> tuple[CoinSpend, Program, bytes32]:
        """Helper: build a tracker VOTE CoinSpend for an OPEN tracker."""
        tracker_inner = _curry_open_tracker(
            proposal_hash=self.proposal_hash,
            bill=self.bill,
            vote_tally=self.initial_tally,
            voting_deadline=self.deadline,
        )
        inner_ph = bytes32(tracker_inner.get_tree_hash())
        full_puzzle = puzzle_for_singleton(TRACKER_LAUNCHER_ID, tracker_inner)
        full_ph = bytes32(full_puzzle.get_tree_hash())
        tracker_coin = _make_fake_coin(puzzle_hash=full_ph, amount=1)
        coin_spend = build_tracker_vote_coin_spend(
            tracker_coin=tracker_coin,
            tracker_inner_puzzle=tracker_inner,
            tracker_launcher_id=TRACKER_LAUNCHER_ID,
            lineage_proof=LineageProof(
                parent_name=bytes32(b"\xaa" * 32),
                inner_puzzle_hash=inner_ph,
                amount=uint64(1),
            ),
            voter_inner_puzzle_hash=IDENTITY_HASH,
            additional_vote_amount=self.additional_vote,
        )
        return coin_spend, tracker_inner, full_ph

    def test_puzzle_reveal_hashes_to_full_singleton_puzhash(self):
        """The full puzzle reveal must hash to
        ``puzzle_for_singleton(launcher_id, tracker_inner).get_tree_hash()``."""
        coin_spend, _, expected_ph = self._build()
        actual_ph = bytes32(coin_spend.puzzle_reveal.get_tree_hash())
        assert actual_ph == expected_ph

    def test_running_spend_emits_create_coin_with_increased_tally(self):
        """VOTE recreates the singleton with the same proposal_hash/bill/
        deadline but an increased tally."""
        coin_spend, tracker_inner, _ = self._build()
        inner_sol = _extract_singleton_inner_solution(coin_spend)
        conds = _run_inner(tracker_inner, inner_sol)
        create_coins = _find_all_conds(conds, CREATE_COIN)
        assert len(create_coins) >= 1
        next_inner = _curry_open_tracker(
            proposal_hash=self.proposal_hash,
            bill=self.bill,
            vote_tally=self.initial_tally + self.additional_vote,
            voting_deadline=self.deadline,
        )
        expected_next_inner_ph = bytes32(next_inner.get_tree_hash())
        # The CREATE_COIN we care about is the one whose puzhash matches
        # the recurried singleton's full puzhash.  (Singletons wrap their
        # children in another singleton layer; we check the inner-layer
        # hash by stripping the wrapper using the tracker's inner output.)
        # The singleton top layer's inner output is the inner ph directly.
        inner_recurry_seen = any(
            bytes(c[1].atom) == bytes(expected_next_inner_ph) for c in create_coins
        )
        assert inner_recurry_seen, (
            f"VOTE did not recurry to expected next-inner ph "
            f"{expected_next_inner_ph.hex()}; saw "
            f"{[bytes(c[1].atom).hex() for c in create_coins]}"
        )

    def test_running_spend_asserts_voter_lock_announcement(self):
        """VOTE asserts ``ASSERT_PUZZLE_ANNOUNCEMENT(lock_announcement_id(...))``
        for the voter's SGT coin sender and the canonical message body."""
        coin_spend, tracker_inner, _ = self._build()
        inner_sol = _extract_singleton_inner_solution(coin_spend)
        conds = _run_inner(tracker_inner, inner_sol)
        asserts = _find_all_conds(conds, ASSERT_PUZZLE_ANNOUNCEMENT)
        # Compute the expected lock announcement id directly:
        sender_ph = cat_sgt_free_puzzle_hash(
            TRACKER_STRUCT,
            SGT_FREE_MOD_HASH,
            SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH_B32,
            SGT_TAIL_HASH,
            IDENTITY_HASH,
        )
        msg_body = Program.to(
            [LOCK_TAG, self.proposal_hash, self.additional_vote, self.deadline]
        ).get_tree_hash()
        expected_announcement_id = bytes32(
            hashlib.sha256(
                bytes(sender_ph) + PROTOCOL_PREFIX + bytes(msg_body)
            ).digest()
        )
        assertion_ids = [bytes(a[1].atom) for a in asserts]
        assert bytes(expected_announcement_id) in assertion_ids, (
            f"VOTE did not assert expected LOCK announcement id "
            f"{expected_announcement_id.hex()}; asserted: "
            f"{[a.hex() for a in assertion_ids]}"
        )

    def test_coin_spend_serialises_round_trip(self):
        coin_spend, _, _ = self._build()
        raw = bytes(coin_spend)
        assert CoinSpend.from_bytes(raw) == coin_spend

    def test_rejects_non_bytes32_voter_inner_puzzle_hash(self):
        tracker_inner = _curry_open_tracker(
            proposal_hash=self.proposal_hash,
            bill=self.bill,
            vote_tally=self.initial_tally,
            voting_deadline=self.deadline,
        )
        with pytest.raises(ValueError, match="voter_inner_puzzle_hash"):
            build_tracker_vote_coin_spend(
                tracker_coin=_make_fake_coin(
                    puzzle_hash=bytes32(b"\x00" * 32), amount=1
                ),
                tracker_inner_puzzle=tracker_inner,
                tracker_launcher_id=TRACKER_LAUNCHER_ID,
                lineage_proof=LineageProof(),
                voter_inner_puzzle_hash=b"short",  # type: ignore[arg-type]
                additional_vote_amount=100,
            )

    def test_rejects_non_positive_additional_vote_amount(self):
        tracker_inner = _curry_open_tracker(
            proposal_hash=self.proposal_hash,
            bill=self.bill,
            vote_tally=self.initial_tally,
            voting_deadline=self.deadline,
        )
        with pytest.raises(ValueError, match="additional_vote_amount must be > 0"):
            build_tracker_vote_coin_spend(
                tracker_coin=_make_fake_coin(
                    puzzle_hash=bytes32(b"\x00" * 32), amount=1
                ),
                tracker_inner_puzzle=tracker_inner,
                tracker_launcher_id=TRACKER_LAUNCHER_ID,
                lineage_proof=LineageProof(),
                voter_inner_puzzle_hash=IDENTITY_HASH,
                additional_vote_amount=0,
            )


# ─────────────────────────────────────────────────────────────────────────────
#                Pair-wise integration: lock ↔ tracker VOTE bundle
# ─────────────────────────────────────────────────────────────────────────────
class TestLockVotePairing:
    """The whole point of the two builders is that their on-chain conditions
    pair up: the SGT lock spend emits a ``CREATE_PUZZLE_ANNOUNCEMENT`` whose
    id is exactly what the tracker VOTE spend asserts.  Without this
    pairing the bundle would be rejected by the mempool."""

    def test_lock_emits_id_that_tracker_asserts(self):
        bill = bill_mint(
            bytes32(b"\x55" * 32),
            bytes32(b"\x71" * 32),
            bytes32(b"\x72" * 32),
        )
        proposal_hash = proposal_hash_from_bill(bill)
        vote_amount = 250_000
        deadline = 1_900_000_000

        # ── SGT lock spend ──
        voter_ph = IDENTITY_HASH
        from solslot_puzzles.sgt_driver import sgt_locked_inner_hash

        locked_ph = sgt_locked_inner_hash(
            SGT_FREE_MOD_HASH, TRACKER_STRUCT, voter_ph, proposal_hash, deadline
        )
        voter_solution = Program.to([[CREATE_COIN, locked_ph, vote_amount]])
        sgt_ph = cat_sgt_free_puzzle_hash(
            TRACKER_STRUCT,
            SGT_FREE_MOD_HASH,
            SGT_LOCKED_MOD_HASH,
            CAT_MOD_HASH_B32,
            SGT_TAIL_HASH,
            voter_ph,
        )
        sgt_coin = _make_fake_coin(puzzle_hash=sgt_ph, amount=vote_amount)
        from solslot_puzzles.sgt_driver import sgt_free_inner_puzzle as _pfp

        lock_spend = build_sgt_lock_coin_spend(
            sgt_coin=sgt_coin,
            voter_inner_puzzle=IDENTITY_INNER,
            voter_inner_solution=voter_solution,
            proposal_tracker_struct=TRACKER_STRUCT,
            sgt_tail_hash=SGT_TAIL_HASH,
            lineage_proof=LineageProof(),
            proposal_hash=proposal_hash,
            deadline=deadline,
        )
        free_inner = _pfp(SGT_LOCKED_MOD_HASH, TRACKER_STRUCT, voter_ph)
        lock_inner_sol = _extract_cat_inner_solution(lock_spend)
        lock_conds = _run_inner(free_inner, lock_inner_sol)
        emitted = _find_cond(lock_conds, CREATE_PUZZLE_ANNOUNCEMENT)
        assert emitted is not None
        emitted_msg = bytes(emitted[1].atom)
        # The id asserted on the tracker side is sha256(sender_ph || msg).
        emitted_id = bytes32(hashlib.sha256(bytes(sgt_ph) + emitted_msg).digest())

        # ── Tracker VOTE spend ──
        tracker_inner = _curry_open_tracker(
            proposal_hash=proposal_hash,
            bill=bill,
            vote_tally=100_000,
            voting_deadline=deadline,
        )
        full_puzzle = puzzle_for_singleton(TRACKER_LAUNCHER_ID, tracker_inner)
        tracker_coin = _make_fake_coin(
            puzzle_hash=bytes32(full_puzzle.get_tree_hash()), amount=1
        )
        vote_spend = build_tracker_vote_coin_spend(
            tracker_coin=tracker_coin,
            tracker_inner_puzzle=tracker_inner,
            tracker_launcher_id=TRACKER_LAUNCHER_ID,
            lineage_proof=LineageProof(
                parent_name=bytes32(b"\xaa" * 32),
                inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
                amount=uint64(1),
            ),
            voter_inner_puzzle_hash=voter_ph,
            additional_vote_amount=vote_amount,
        )
        vote_inner_sol = _extract_singleton_inner_solution(vote_spend)
        vote_conds = _run_inner(tracker_inner, vote_inner_sol)
        asserts = _find_all_conds(vote_conds, ASSERT_PUZZLE_ANNOUNCEMENT)
        assert any(bytes(a[1].atom) == bytes(emitted_id) for a in asserts), (
            f"Tracker VOTE did not assert SGT-emitted announcement id "
            f"{emitted_id.hex()}; asserted: "
            f"{[bytes(a[1].atom).hex() for a in asserts]}"
        )
