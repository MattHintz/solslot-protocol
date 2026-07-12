"""Unit tests for smart_deed_inner_v2.clsp — the gated RWA NFT contract.

Tests run the curried puzzle directly via Program.run() to verify:
  1. Pool deposit case ('d') produces correct conditions
  2. Pool redeem case ('r') produces correct conditions
  3. Invalid spend case raises (no free transfer)
  4. Input validation rejects bad inputs
"""
import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.util.curry_and_treehash import (
    calculate_hash_of_quoted_mod_hash,
    curry_and_treehash,
)
from chia_rs.sized_bytes import bytes32

# Load the compiled smart deed inner puzzle
SMART_DEED_INNER_MOD: Program = load_clvm(
    "smart_deed_inner_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

# p2_pool must be loaded so the test can compute the *exact* bare p2_pool inner
# puzhash the deposit path should target.
P2_POOL_MOD: Program = load_clvm(
    "p2_pool_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

# ── Test constants ──
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)
DEED_LAUNCHER_ID = bytes32(b"\xaa" * 32)
TEST_SINGLETON_STRUCT = Program.to((SINGLETON_MOD_HASH, (DEED_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH)))
PROTOCOL_DID_PUZHASH = bytes32(b"\x03" * 32)
PAR_VALUE = 100000
ASSET_CLASS = 1
PROPERTY_ID = bytes32(b"\x08" * 32)
COLLECTION_ID_CANON = bytes32(b"\x09" * 32)
SHARE_PPM = 750_000
JURISDICTION = b"US-CA"
ROYALTY_PUZHASH = bytes32(b"\x04" * 32)
ROYALTY_BPS = 200
POOL_SINGLETON_MOD_HASH = SINGLETON_MOD_HASH  # same mod hash, different launcher
P2_POOL_MOD_HASH = P2_POOL_MOD.get_tree_hash()
P2_VAULT_MOD_HASH = bytes32(b"\x07" * 32)

# Spend case constants (must match smart_deed_inner_v2.clsp)
# Settlement exits deeds via p2_pool (pool batch release), not via this puzzle.
DEED_SPEND_POOL_DEPOSIT = 0x64
DEED_SPEND_POOL_REDEEM = 0x72

# Protocol prefix (must match utility_macros.clib PROTOCOL_PREFIX = 0x53 = "S")
PROTOCOL_PREFIX = b"\x53"


def curry_deed() -> Program:
    """Curry smart_deed_inner with test parameters."""
    return SMART_DEED_INNER_MOD.curry(
        TEST_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        PAR_VALUE,
        ASSET_CLASS,
        PROPERTY_ID,
        COLLECTION_ID_CANON,
        SHARE_PPM,
        JURISDICTION,
        ROYALTY_PUZHASH,
        ROYALTY_BPS,
        POOL_SINGLETON_MOD_HASH,
        P2_POOL_MOD_HASH,
        P2_VAULT_MOD_HASH,
    )


def _computed_bare_p2_pool_ph(pool_launcher_id: bytes32) -> bytes32:
    """Recompute the p2_pool *inner* puzhash the way the deed does internally.

    This is the pre-morph target; singleton_top_layer will wrap it into
    singleton.curry(deed_struct, p2_pool_inner) when the deed coin is spent.
    """
    quoted_mod = calculate_hash_of_quoted_mod_hash(P2_POOL_MOD_HASH)
    deed_commitment = Program.to(
        [
            DEED_LAUNCHER_ID,
            PAR_VALUE,
            ASSET_CLASS,
            PROPERTY_ID,
            COLLECTION_ID_CANON,
            SHARE_PPM,
        ]
    ).get_tree_hash()
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            hashlib.sha256(b"\x01" + bytes(P2_POOL_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(POOL_SINGLETON_MOD_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(pool_launcher_id)).digest(),
            hashlib.sha256(b"\x01" + bytes(LAUNCHER_PUZZLE_HASH)).digest(),
            hashlib.sha256(b"\x01" + bytes(deed_commitment)).digest(),
        )
    )


def make_solution(my_id, my_inner_puzhash, my_amount, spend_case, params_list):
    """Build the solution program for a deed spend."""
    return Program.to([
        my_id,
        my_inner_puzhash,
        my_amount,
        spend_case,
        params_list,
    ])


class TestSmartDeedCompile:
    """Verify the deed puzzle compiles and curries correctly."""

    def test_mod_loads(self):
        assert SMART_DEED_INNER_MOD is not None
        assert SMART_DEED_INNER_MOD.get_tree_hash() is not None

    def test_curry_produces_program(self):
        curried = curry_deed()
        assert curried is not None
        assert curried.get_tree_hash() is not None
        # Curried hash must differ from uncurried
        assert curried.get_tree_hash() != SMART_DEED_INNER_MOD.get_tree_hash()


class TestSmartDeedDeposit:
    """Test SPEND CASE 'd' — Pool Deposit."""

    def test_deposit_returns_conditions(self):
        curried = curry_deed()
        my_id = bytes32(b"\xdd" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        pool_launcher_id = bytes32(b"\xbb" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)

        sol = make_solution(
            my_id, my_inner_puzhash, my_amount,
            DEED_SPEND_POOL_DEPOSIT,
            [pool_launcher_id, pool_inner_puzhash, LAUNCHER_PUZZLE_HASH],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions: CREATE_COIN, CREATE_COIN_ANNOUNCEMENT, RECEIVE_MESSAGE,
        #               ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 6

        # Verify CREATE_COIN (sends deed to p2_pool escrow)
        assert conditions[0][0] == bytes([51])  # CREATE_COIN
        assert conditions[0][2] == bytes([my_amount])
        # Verify CREATE_COIN_ANNOUNCEMENT (prefixed)
        assert conditions[1][0] == bytes([60])  # CREATE_COIN_ANNOUNCEMENT
        assert conditions[1][1][:1] == PROTOCOL_PREFIX  # protocol prefix
        # Verify RECEIVE_MESSAGE 0x10 (CHIP-25 message from pool)
        assert conditions[2][0] == bytes([67])  # RECEIVE_MESSAGE
        assert conditions[2][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        # Verify ASSERT_MY_COIN_ID
        assert conditions[3][0] == bytes([70])
        assert conditions[3][1] == my_id
        # Verify ASSERT_MY_AMOUNT
        assert conditions[4][0] == bytes([73])
        # Verify ASSERT_MY_PUZZLEHASH (P0 enhancement)
        assert conditions[5][0] == bytes([72])

    def test_deposit_destination_is_computed_bare_p2_pool(self):
        """Regression for CRIT-1: deposit CREATE_COIN must target the *bare*
        p2_pool inner puzhash so singleton_top_layer's morph wraps it into
        singleton.curry(deed_struct, p2_pool_inner). Before the fix the target
        was the pool singleton's FULL puzhash, which is meaningless as an
        inner puzzle and caused deposited deeds to be burnt.
        """
        curried = curry_deed()
        my_id = bytes32(b"\xdd" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        pool_launcher_id = bytes32(b"\xbb" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)

        sol = make_solution(
            my_id, my_inner_puzhash, my_amount,
            DEED_SPEND_POOL_DEPOSIT,
            [pool_launcher_id, pool_inner_puzhash, LAUNCHER_PUZZLE_HASH],
        )
        conditions = curried.run(sol).as_python()
        create_coin = [c for c in conditions if c[0] == bytes([51])][0]
        deed_dest = bytes32(create_coin[1])

        expected = _computed_bare_p2_pool_ph(pool_launcher_id)
        assert deed_dest == expected, (
            f"Deposit destination mismatch \u2014 deed burn bug regressed!\n"
            f"  Deed sends to:       {deed_dest.hex()}\n"
            f"  Expected bare p2_pool: {expected.hex()}"
        )

        # Defensive: explicitly reject the old (buggy) target shape where the
        # deed was sent to the pool singleton's full puzhash.
        quoted_singleton = calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH)
        pool_struct = Program.to(
            (POOL_SINGLETON_MOD_HASH, (pool_launcher_id, LAUNCHER_PUZZLE_HASH))
        )
        buggy_pool_full_ph = bytes32(
            curry_and_treehash(
                quoted_singleton,
                pool_struct.get_tree_hash(),
                pool_inner_puzhash,
            )
        )
        assert deed_dest != buggy_pool_full_ph, (
            "Deposit destination regressed to the pre-fix buggy value "
            "(pool singleton's full puzhash)"
        )


class TestSmartDeedRedeem:
    """Test SPEND CASE 'r' — Pool Redeem."""

    def test_redeem_returns_conditions(self):
        curried = curry_deed()
        my_id = bytes32(b"\xdd" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        pool_launcher_id = bytes32(b"\xbb" * 32)
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        vault_launcher_id = bytes32(b"\xee" * 32)

        sol = make_solution(
            my_id, my_inner_puzhash, my_amount,
            DEED_SPEND_POOL_REDEEM,
            [pool_launcher_id, pool_inner_puzhash, LAUNCHER_PUZZLE_HASH, vault_launcher_id],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions
        assert len(conditions) == 6

        # CREATE_COIN should send deed to computed p2_vault (not a free param)
        assert conditions[0][0] == bytes([51])  # CREATE_COIN
        # Destination is a 32-byte hash (computed p2_vault puzzle hash)
        assert len(conditions[0][1]) == 32
        assert conditions[0][2] == bytes([my_amount])
        # CREATE_COIN_ANNOUNCEMENT prefixed
        assert conditions[1][0] == bytes([60])
        assert conditions[1][1][:1] == PROTOCOL_PREFIX
        # RECEIVE_MESSAGE 0x10 (CHIP-25 message from pool)
        assert conditions[2][0] == bytes([67])  # RECEIVE_MESSAGE
        assert conditions[2][1] == bytes([0x10])


class TestSmartDeedGating:
    """Test that invalid spend cases fail — proving gated architecture."""

    def test_invalid_spend_case_fails(self):
        curried = curry_deed()
        my_id = bytes32(b"\xdd" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        # Attempt free transfer (spend_case = 0x74 = 't') — MUST FAIL
        sol = make_solution(
            my_id, my_inner_puzhash, my_amount,
            0x74,  # 't' for transfer — NOT a valid spend case
            [bytes32(b"\xff" * 32)],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_zero_spend_case_fails(self):
        curried = curry_deed()
        my_id = bytes32(b"\xdd" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        sol = make_solution(
            my_id, my_inner_puzhash, my_amount,
            0,  # invalid
            [],
        )
        with pytest.raises(ValueError):
            curried.run(sol)
