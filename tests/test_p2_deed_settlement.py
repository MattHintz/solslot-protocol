"""Focused tests for the p2_deed_settlement settlement leaf."""
from __future__ import annotations

import hashlib
import inspect

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from populis_puzzles.settlement_splitxch import (
    CANONICAL_DEED_BURN_INNER_PUZHASH,
    compute_settlement_targets,
    curry_p2_deed_settlement,
    p2_deed_settlement_mod,
)


PROTOCOL_PREFIX = b"\x50"

ASSERT_COIN_ANNOUNCEMENT = 61
CREATE_COIN = 51
CREATE_COIN_ANNOUNCEMENT = 60
ASSERT_MY_AMOUNT = 73
ASSERT_SECONDS_RELATIVE = 80

DEED_LAUNCHER_ID = bytes32(b"\x11" * 32)
DEED_COIN_ID = bytes32(b"\x22" * 32)
POOL_COIN_ID = bytes32(b"\x33" * 32)
TARGET_PUZZLE_HASH = bytes32(b"\x44" * 32)
DELAYED_PUZZLE_HASH = bytes32(b"\x55" * 32)
OTHER_DEED_LAUNCHER_ID = bytes32(b"\x66" * 32)
SECONDS_DELAY = 86_400
SETTLEMENT_AMOUNT = 123_456


def settlement_leaf(deed_launcher_id: bytes32 = DEED_LAUNCHER_ID) -> Program:
    return curry_p2_deed_settlement(
        singleton_mod_hash=bytes32(SINGLETON_MOD_HASH),
        deed_launcher_id=deed_launcher_id,
        launcher_puzzle_hash=bytes32(SINGLETON_LAUNCHER_HASH),
        seconds_delay=SECONDS_DELAY,
        delayed_puzzle_hash=DELAYED_PUZZLE_HASH,
    )


def opcode(condition: list) -> int:
    value = condition[0]
    return int.from_bytes(value, "big") if isinstance(value, bytes) else int(value)


def atom_to_int(value: bytes | int) -> int:
    return value if isinstance(value, int) else int.from_bytes(value, "big")


def expected_burn_announcement_id() -> bytes:
    release_body = hashlib.sha256(
        bytes(POOL_COIN_ID)
        + bytes(DEED_LAUNCHER_ID)
        + bytes(CANONICAL_DEED_BURN_INNER_PUZHASH)
    ).digest()
    return hashlib.sha256(
        bytes(DEED_COIN_ID) + PROTOCOL_PREFIX + release_body
    ).digest()


def test_canonical_curry_surface_has_no_burn_parameter():
    sig = inspect.signature(curry_p2_deed_settlement)
    assert "burn_inner_puzhash" not in sig.parameters
    assert CANONICAL_DEED_BURN_INNER_PUZHASH == bytes32(b"\x00" * 32)
    assert settlement_leaf().get_tree_hash() == p2_deed_settlement_mod().curry(
        bytes32(SINGLETON_MOD_HASH),
        DEED_LAUNCHER_ID,
        bytes32(SINGLETON_LAUNCHER_HASH),
        SECONDS_DELAY,
        DELAYED_PUZZLE_HASH,
    ).get_tree_hash()


def test_claim_asserts_deed_release_to_canonical_burn_destination():
    conditions = settlement_leaf().run(
        Program.to([
            TARGET_PUZZLE_HASH,
            SETTLEMENT_AMOUNT,
            DEED_COIN_ID,
            POOL_COIN_ID,
        ])
    ).as_python()

    assert [opcode(condition) for condition in conditions] == [
        ASSERT_COIN_ANNOUNCEMENT,
        CREATE_COIN,
        CREATE_COIN_ANNOUNCEMENT,
        ASSERT_MY_AMOUNT,
    ]
    assert conditions[0][1] == expected_burn_announcement_id()
    assert conditions[1][1] == TARGET_PUZZLE_HASH
    assert atom_to_int(conditions[1][2]) == SETTLEMENT_AMOUNT
    assert conditions[1][3] == [TARGET_PUZZLE_HASH]
    assert atom_to_int(conditions[3][1]) == SETTLEMENT_AMOUNT


def test_delayed_escape_ignores_claim_target_and_pays_delayed_destination():
    ignored_target = TARGET_PUZZLE_HASH
    conditions = settlement_leaf().run(
        Program.to([ignored_target, SETTLEMENT_AMOUNT])
    ).as_python()

    assert [opcode(condition) for condition in conditions] == [
        ASSERT_SECONDS_RELATIVE,
        CREATE_COIN,
        ASSERT_MY_AMOUNT,
    ]
    assert atom_to_int(conditions[0][1]) == SECONDS_DELAY
    assert conditions[1][1] == DELAYED_PUZZLE_HASH
    assert atom_to_int(conditions[1][2]) == SETTLEMENT_AMOUNT
    assert atom_to_int(conditions[2][1]) == SETTLEMENT_AMOUNT


def test_settlement_targets_use_canonical_leaf_hashes():
    targets = compute_settlement_targets(
        total_amount=101,
        deed_launcher_ids=[DEED_LAUNCHER_ID, OTHER_DEED_LAUNCHER_ID],
        p2_settlement_curry_fn=settlement_leaf,
    )

    assert targets[0].puzzle_hash == bytes32(settlement_leaf(DEED_LAUNCHER_ID).get_tree_hash())
    assert targets[0].amount == 50
    assert targets[1].puzzle_hash == bytes32(settlement_leaf(OTHER_DEED_LAUNCHER_ID).get_tree_hash())
    assert targets[1].amount == 51
