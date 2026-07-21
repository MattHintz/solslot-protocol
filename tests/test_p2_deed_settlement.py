"""Focused tests for the p2_deed_settlement settlement leaf."""
from __future__ import annotations

import hashlib
import inspect

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.settlement_splitxch import (
    CANONICAL_DEED_BURN_INNER_PUZHASH,
    compute_settlement_targets,
    curry_p2_deed_settlement,
    p2_deed_settlement_mod,
)


PROTOCOL_PREFIX = b"\x53"

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
DEED_COMMITMENT = bytes32(b"\x77" * 32)
SECONDS_DELAY = 86_400
SETTLEMENT_AMOUNT = 123_456
DEED_SPEND_POOL_REDEEM = 0x72
SETTLEMENT_CLAIM_AUTH = 0x53434C4D


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
    release_body = PROTOCOL_PREFIX + bytes(
        Program.to([
            DEED_SPEND_POOL_REDEEM,
            DEED_COMMITMENT,
            CANONICAL_DEED_BURN_INNER_PUZHASH,
        ]).get_tree_hash()
    )
    return hashlib.sha256(bytes(DEED_COIN_ID) + release_body).digest()


def expected_pool_claim_announcement_id(
    target_puzzle_hash: bytes32 = TARGET_PUZZLE_HASH,
) -> bytes:
    target_auth_body = PROTOCOL_PREFIX + bytes(
        Program.to([
            SETTLEMENT_CLAIM_AUTH,
            DEED_COIN_ID,
            DEED_COMMITMENT,
            CANONICAL_DEED_BURN_INNER_PUZHASH,
            target_puzzle_hash,
        ]).get_tree_hash()
    )
    return hashlib.sha256(bytes(POOL_COIN_ID) + target_auth_body).digest()


def claim_conditions(target_puzzle_hash: bytes32 = TARGET_PUZZLE_HASH) -> list:
    return settlement_leaf().run(
        Program.to([
            target_puzzle_hash,
            SETTLEMENT_AMOUNT,
            DEED_COIN_ID,
            POOL_COIN_ID,
            DEED_COMMITMENT,
        ])
    ).as_python()


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
    conditions = claim_conditions()

    assert [opcode(condition) for condition in conditions] == [
        ASSERT_COIN_ANNOUNCEMENT,
        ASSERT_COIN_ANNOUNCEMENT,
        CREATE_COIN,
        CREATE_COIN_ANNOUNCEMENT,
        ASSERT_MY_AMOUNT,
    ]
    assert conditions[0][1] == expected_burn_announcement_id()
    assert conditions[1][1] == expected_pool_claim_announcement_id()
    assert conditions[2][1] == TARGET_PUZZLE_HASH
    assert atom_to_int(conditions[2][2]) == SETTLEMENT_AMOUNT
    assert conditions[2][3] == [TARGET_PUZZLE_HASH]
    assert atom_to_int(conditions[4][1]) == SETTLEMENT_AMOUNT


def test_claim_target_must_match_pool_authorization_announcement():
    attacker_target = bytes32(b"\xaa" * 32)
    conditions = claim_conditions(attacker_target)

    assert conditions[1][1] == expected_pool_claim_announcement_id(attacker_target)
    assert conditions[1][1] != expected_pool_claim_announcement_id(TARGET_PUZZLE_HASH)
    assert conditions[2][1] == attacker_target


def test_claim_rejects_legacy_burn_only_shape_without_deed_commitment():
    with pytest.raises(Exception):
        settlement_leaf().run(
            Program.to([
                TARGET_PUZZLE_HASH,
                SETTLEMENT_AMOUNT,
                DEED_COIN_ID,
                POOL_COIN_ID,
            ])
        ).as_python()


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
