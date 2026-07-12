"""Unit tests for pgt_tail.clsp — the Populis Governance Token CAT2 TAIL.

The TAIL is the standard chia genesis-by-coin-id pattern: it admits a CAT
spend only when delta == 0 AND the spent coin's parent matches the curried
GENESIS_COIN_ID.  Total PGT supply is therefore fixed at whatever is minted
in the single bundle that spends the genesis coin (a Chia consensus rule
forbids respending the genesis coin, so no further issuance is possible).

These tests exercise the TAIL directly with synthetic CAT2 Truths.  Full
issuance lifecycle is verified later by the e2e governance v2 simulator
test (Milestone 1, Step D).
"""
from __future__ import annotations

import pytest

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.pgt_driver import (
    make_cat_truths,
    pgt_tail_hash,
    pgt_tail_puzzle,
)


# CLVM `(x)` raises bubble up as a ValueError("clvm raise", "<atom>") in
# chia-blockchain's Program.run; capture both to stay forward-compatible.
PuzzleError = ValueError


# Stable test fixtures (32-byte placeholders)
GENESIS_COIN_ID = bytes32(b"\xa0" * 32)
WRONG_PARENT_ID = bytes32(b"\xb0" * 32)
INNER_PUZHASH = bytes32(b"\x11" * 32)
CAT_MOD_HASH = bytes32(b"\x22" * 32)
CAT_MOD_HASH_HASH = bytes32(b"\x33" * 32)
MY_ID = bytes32(b"\x44" * 32)
MY_FULL_PUZHASH = bytes32(b"\x55" * 32)
MY_AMOUNT = 1_000_000


def _truths(parent: bytes32, tail_hash: bytes32) -> Program:
    return make_cat_truths(
        inner_puzzle_hash=INNER_PUZHASH,
        cat_mod_hash=CAT_MOD_HASH,
        cat_mod_hash_hash=CAT_MOD_HASH_HASH,
        tail_hash=tail_hash,
        my_id=MY_ID,
        my_parent_info=parent,
        my_full_puzzle_hash=MY_FULL_PUZHASH,
        my_amount=MY_AMOUNT,
    )


def _run_tail(curried: Program, truths: Program, delta: int = 0) -> Program:
    """Invoke the curried PGT TAIL with the standard chia TAIL solution shape.

    Solution: (Truths parent_is_cat lineage_proof delta inner_conditions tail_solution)
    """
    solution = Program.to([truths, 0, 0, delta, [], 0])
    return curried.run(solution)


class TestPgtTailGenesisIssuance:
    def test_genesis_match_delta_zero_returns_empty(self):
        """Genesis spend (parent matches, delta == 0) succeeds with no extra conditions."""
        curried = pgt_tail_puzzle(GENESIS_COIN_ID)
        tail_h = curried.get_tree_hash()
        truths = _truths(GENESIS_COIN_ID, tail_h)

        result = _run_tail(curried, truths, delta=0)

        # TAIL returns nil () when the genesis check passes.
        assert result.as_python() == b""

    def test_wrong_parent_rejected(self):
        """A CAT coin not descended from the curried genesis cannot pass the TAIL."""
        curried = pgt_tail_puzzle(GENESIS_COIN_ID)
        tail_h = curried.get_tree_hash()
        truths = _truths(WRONG_PARENT_ID, tail_h)

        with pytest.raises(PuzzleError):
            _run_tail(curried, truths, delta=0)


class TestPgtTailFixedSupply:
    @pytest.mark.parametrize("delta", [1, -1, 100, -100, 1_000_000])
    def test_nonzero_delta_always_rejected(self, delta: int):
        """Any non-zero delta (mint or melt) fails — supply is permanently capped."""
        curried = pgt_tail_puzzle(GENESIS_COIN_ID)
        tail_h = curried.get_tree_hash()
        truths = _truths(GENESIS_COIN_ID, tail_h)

        with pytest.raises(PuzzleError):
            _run_tail(curried, truths, delta=delta)

    def test_nonzero_delta_rejected_even_with_wrong_parent(self):
        """The non-zero-delta guard runs first; parent check is moot."""
        curried = pgt_tail_puzzle(GENESIS_COIN_ID)
        tail_h = curried.get_tree_hash()
        truths = _truths(WRONG_PARENT_ID, tail_h)

        with pytest.raises(PuzzleError):
            _run_tail(curried, truths, delta=42)


class TestPgtTailHashing:
    def test_tail_hash_is_deterministic(self):
        """Two callers currying the same genesis coin id must derive the same tail hash."""
        a = pgt_tail_hash(GENESIS_COIN_ID)
        b = pgt_tail_hash(GENESIS_COIN_ID)
        assert a == b
        assert isinstance(a, bytes) and len(a) == 32

    def test_tail_hash_changes_with_genesis(self):
        """Different genesis coins produce distinct PGT instances (separate currencies)."""
        a = pgt_tail_hash(GENESIS_COIN_ID)
        b = pgt_tail_hash(WRONG_PARENT_ID)
        assert a != b

    def test_genesis_coin_id_must_be_32_bytes(self):
        with pytest.raises(ValueError):
            pgt_tail_puzzle(b"\x00" * 31)
        with pytest.raises(ValueError):
            pgt_tail_puzzle(b"\x00" * 33)
