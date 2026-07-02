"""Unit tests for pool_token_tail.clsp — the CAT tail for ungated pool tokens.

Tests verify:
  1. Mint case requires pool singleton announcement (with protocol prefix)
  2. Melt case requires pool singleton announcement (with protocol prefix)
  3. Transfer case returns empty conditions (ungated)
"""
import hashlib

import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

POOL_TOKEN_TAIL_MOD: Program = load_clvm(
    "pool_token_tail.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# Test constants
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)


def curry_tail() -> Program:
    return POOL_TOKEN_TAIL_MOD.curry(
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


def _full_cat_conditions(mint_or_melt: int, token_amount: int, input_amount: int, output_amount: int):
    tail = curry_tail()
    inner_puzzle = Program.to(1)
    inner_puzzle_hash = inner_puzzle.get_tree_hash()
    cat_puzzle = construct_cat_puzzle(CAT_MOD, tail.get_tree_hash(), inner_puzzle)
    token_coin = Coin(
        bytes32(b"\xe1" * 32),
        cat_puzzle.get_tree_hash(),
        uint64(input_amount),
    )
    pool_inner_puzhash = bytes32(b"\xcc" * 32)
    pool_full_puzhash = bytes32(b"\x44" * 32)
    pool_coin_id = bytes32(b"\x22" * 32)
    tail_solution = Program.to(
        [
            pool_full_puzhash,
            pool_inner_puzhash,
            pool_coin_id,
            token_coin.name(),
            mint_or_melt,
            token_amount,
        ]
    )
    inner_solution = Program.to(
        [
            [51, inner_puzzle_hash, output_amount],
            [51, 0, -113, tail, tail_solution],
        ]
    )
    spendable = SpendableCAT(
        coin=token_coin,
        limitations_program_hash=tail.get_tree_hash(),
        inner_puzzle=inner_puzzle,
        inner_solution=inner_solution,
        limitations_solution=tail_solution,
        lineage_proof=LineageProof(),
        extra_delta=token_amount if mint_or_melt > 0 else -token_amount,
        limitations_program_reveal=tail,
    )
    bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [spendable])
    assert len(bundle.coin_spends) == 1
    spend = bundle.coin_spends[0]
    return conditions_dict_for_solution(spend.puzzle_reveal, spend.solution, 11_000_000_000)


class TestPoolTokenTailMint:
    """Test mint case (mint_or_melt = 1)."""

    def test_mint_returns_conditions(self):
        curried = curry_tail()
        pool_full_puzhash = bytes32(b"\x44" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)
        amount = 100000

        sol = Program.to([pool_full_puzhash, pool_inner_puzhash, pool_coin_id, my_coin_id, 1, amount])
        result = curried.run(sol)
        conditions = result.as_python()

        # Mint: 2 conditions — ASSERT_MY_COIN_ID + ASSERT_PUZZLE_ANNOUNCEMENT
        assert len(conditions) == 2
        assert conditions[0][0] == bytes([70])  # ASSERT_MY_COIN_ID
        assert conditions[0][1] == my_coin_id
        assert conditions[1][0] == bytes([63])  # ASSERT_PUZZLE_ANNOUNCEMENT

    def test_mint_v2_solution_binds_pool_full_puzzle_hash(self):
        curried = curry_tail()
        pool_full_puzhash = bytes32(b"\x44" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)
        amount = 100000

        sol = Program.to([
            pool_full_puzhash,
            pool_inner_puzhash,
            pool_coin_id,
            my_coin_id,
            1,
            amount,
        ])
        result = curried.run(sol)
        conditions = result.as_python()

        expected_message = b"P" + Program.to([1, my_coin_id, amount]).get_tree_hash()
        expected_announcement_id = hashlib.sha256(pool_full_puzhash + expected_message).digest()
        assert conditions[1][0] == bytes([63])  # ASSERT_PUZZLE_ANNOUNCEMENT
        assert conditions[1][1] == expected_announcement_id


class TestPoolTokenTailMelt:
    """Test melt case (mint_or_melt = -1)."""

    def test_melt_returns_conditions(self):
        curried = curry_tail()
        pool_full_puzhash = bytes32(b"\x44" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)
        amount = 50000

        sol = Program.to([pool_full_puzhash, pool_inner_puzhash, pool_coin_id, my_coin_id, -1, amount])
        result = curried.run(sol)
        conditions = result.as_python()

        assert len(conditions) == 2
        assert conditions[0][0] == bytes([70])  # ASSERT_MY_COIN_ID
        assert conditions[1][0] == bytes([63])  # ASSERT_PUZZLE_ANNOUNCEMENT


class TestPoolTokenTailTransfer:
    """Test transfer case (mint_or_melt = 0) — ungated."""

    def test_transfer_returns_empty(self):
        curried = curry_tail()
        pool_full_puzhash = bytes32(b"\x44" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)

        sol = Program.to([pool_full_puzhash, pool_inner_puzhash, pool_coin_id, my_coin_id, 0, 0])
        result = curried.run(sol)
        conditions = result.as_python()

        # Transfer: nil — no restrictions (Chialisp () = b'')
        assert conditions == b""


class TestPoolTokenTailCatInvocation:
    """Verify the TAIL works through Chia's real CAT2 wrapper."""

    def test_mint_replays_inside_cat_wrapper(self):
        conditions = _full_cat_conditions(
            mint_or_melt=1,
            token_amount=100,
            input_amount=7,
            output_amount=107,
        )

        assert ConditionOpcode.ASSERT_MY_COIN_ID in conditions
        assert ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT in conditions

    def test_melt_replays_inside_cat_wrapper(self):
        conditions = _full_cat_conditions(
            mint_or_melt=-1,
            token_amount=100,
            input_amount=107,
            output_amount=7,
        )

        assert ConditionOpcode.ASSERT_MY_COIN_ID in conditions
        assert ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT in conditions
