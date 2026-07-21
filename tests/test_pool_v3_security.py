"""Consensus regressions for V1-CANON-041 and V1-CANON-042."""
from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.collection_nav_registry_driver import (
    collection_nav_registry_inner_mod_hash,
)
from solslot_puzzles.protocol_deployment import singleton_full_puzzle_hash


POOL_V3 = load_clvm(
    "pool_singleton_inner_v3.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
SMART_DEED_V2 = load_clvm(
    "smart_deed_inner_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
P2_POOL_V2 = load_clvm(
    "p2_pool_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

POOL_LAUNCHER_ID = bytes32(b"\x10" * 32)
GOVERNANCE_LAUNCHER_ID = bytes32(b"\x20" * 32)
FORGED_GOVERNANCE_LAUNCHER_ID = bytes32(b"\x21" * 32)
DEED_LAUNCHER_ID = bytes32(b"\x30" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
GOVERNANCE_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (GOVERNANCE_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
FORGED_GOVERNANCE_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (FORGED_GOVERNANCE_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)

PROTOCOL_DID_PUZZLE_HASH = bytes32(b"\x40" * 32)
TOKEN_TAIL_HASH = bytes32(b"\x41" * 32)
CAT_MOD_HASH = bytes32(b"\x42" * 32)
OFFER_MOD_HASH = bytes32(b"\x43" * 32)
P2_VAULT_MOD_HASH = bytes32(b"\x44" * 32)
VAULT_INNER_MOD_HASH = bytes32(b"\x4b" * 32)
NAV_REGISTRY_MOD_HASH = collection_nav_registry_inner_mod_hash()
NAV_REGISTRY_GOV_PUBKEY = b"\x45" * 48
NAV_REGISTRY_LAUNCHER_ID = bytes32(b"\x46" * 32)
TREASURY_RESERVE_HASH = bytes32(b"\x47" * 32)
PROTOCOL_TREASURY_HASH = bytes32(b"\x48" * 32)
GOVERNANCE_REWARDS_HASH = bytes32(b"\x49" * 32)
GOVERNANCE_REWARDS_ROOT = bytes32(b"\x4a" * 32)
TRUSTED_ZKPASSPORT_BRIDGE_POLICY_HASH = bytes32(b"\x4c" * 32)

CREATE_COIN = 51
CREATE_COIN_ANNOUNCEMENT = 60
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
RECEIVE_MESSAGE = 67
SETTLEMENT_CLAIM_AUTH = 0x53434C4D


def _atom_int(value: bytes | int) -> int:
    return int.from_bytes(value, "big") if isinstance(value, bytes) else value


def _curry_pool(
    mod: Program,
    *,
    governance_struct: Program | None = None,
    status: int = 1,
    tvl: int = 100_000,
    deed_count: int = 1,
    supply: int = 100_000,
    reserve: int = 0,
) -> Program:
    immutable = [
        mod.get_tree_hash(),
        POOL_STRUCT,
    ]
    if governance_struct is not None:
        immutable.append(governance_struct)
    immutable.extend(
        [
            PROTOCOL_DID_PUZZLE_HASH,
            TOKEN_TAIL_HASH,
            CAT_MOD_HASH,
            OFFER_MOD_HASH,
            P2_VAULT_MOD_HASH,
            VAULT_INNER_MOD_HASH,
            NAV_REGISTRY_MOD_HASH,
            NAV_REGISTRY_GOV_PUBKEY,
            NAV_REGISTRY_LAUNCHER_ID,
            1,
            TREASURY_RESERVE_HASH,
            PROTOCOL_TREASURY_HASH,
            GOVERNANCE_REWARDS_HASH,
            GOVERNANCE_REWARDS_ROOT,
            TRUSTED_ZKPASSPORT_BRIDGE_POLICY_HASH,
            1000,
            status,
            tvl,
            deed_count,
            supply,
            reserve,
        ]
    )
    return mod.curry(*immutable)


def _solution(curried: Program, spend_case: int, params: list[object]) -> Program:
    return Program.to(
        [bytes32(b"\x51" * 32), bytes32(curried.get_tree_hash()), 1, spend_case, params]
    )


@pytest.mark.parametrize(
    ("spend_case", "params"),
    [
        (
            2,
            [
                bytes32(b"\x61" * 32),
                1,
                bytes32(b"\x62" * 32),
                SINGLETON_LAUNCHER_HASH,
                bytes32(b"\x63" * 32),
            ],
        ),
        (
            5,
            [
                bytes32(b"\x61" * 32),
                1,
                bytes32(b"\x62" * 32),
                SINGLETON_LAUNCHER_HASH,
            ],
        ),
    ],
)
def test_v1_canon_041_poc_is_rejected_by_hardened_pool(
    spend_case: int, params: list[object]
) -> None:
    hardened = _curry_pool(POOL_V3, governance_struct=GOVERNANCE_STRUCT)
    with pytest.raises(ValueError):
        hardened.run(_solution(hardened, spend_case, params))


def test_governance_freeze_uses_only_curried_singleton_identity() -> None:
    pool = _curry_pool(POOL_V3, governance_struct=GOVERNANCE_STRUCT)
    governance_inner_hash = bytes32(b"\x70" * 32)
    conditions = pool.run(
        _solution(pool, 4, [0, governance_inner_hash, FORGED_GOVERNANCE_STRUCT])
    ).as_python()

    receive = next(c for c in conditions if _atom_int(c[0]) == RECEIVE_MESSAGE)
    assert receive[3] == singleton_full_puzzle_hash(
        GOVERNANCE_LAUNCHER_ID, governance_inner_hash
    )
    assert receive[3] != singleton_full_puzzle_hash(
        FORGED_GOVERNANCE_LAUNCHER_ID, governance_inner_hash
    )

    expected_successor = _curry_pool(
        POOL_V3,
        governance_struct=GOVERNANCE_STRUCT,
        status=0,
    )
    create = next(c for c in conditions if _atom_int(c[0]) == CREATE_COIN)
    assert create[1] == expected_successor.get_tree_hash()


def test_settlement_uses_curried_governance_and_binds_each_deed() -> None:
    pool = _curry_pool(POOL_V3, governance_struct=GOVERNANCE_STRUCT)
    deed_coin_id = bytes32(b"\x71" * 32)
    commitment = bytes32(b"\x72" * 32)
    destination = bytes32(b"\x73" * 32)
    claim_target = bytes32(b"\x76" * 32)
    governance_inner_hash = bytes32(b"\x74" * 32)
    releases = [[deed_coin_id, commitment, destination, claim_target]]
    conditions = pool.run(
        _solution(
            pool,
            3,
            [
                bytes32(b"\x75" * 32),
                10,
                releases,
                governance_inner_hash,
                FORGED_GOVERNANCE_STRUCT,
            ],
        )
    ).as_python()

    receive = next(c for c in conditions if _atom_int(c[0]) == RECEIVE_MESSAGE)
    assert receive[3] == singleton_full_puzzle_hash(
        GOVERNANCE_LAUNCHER_ID, governance_inner_hash
    )
    assert any(_atom_int(c[0]) == CREATE_PUZZLE_ANNOUNCEMENT for c in conditions)
    expected_deed_announcement = hashlib.sha256(
        bytes(deed_coin_id)
        + b"\x53"
        + bytes(Program.to([0x72, commitment, destination]).get_tree_hash())
    ).digest()
    assert [bytes([61]), expected_deed_announcement] in conditions
    expected_claim_authorization = b"\x53" + bytes(
        Program.to([
            SETTLEMENT_CLAIM_AUTH,
            deed_coin_id,
            commitment,
            destination,
            claim_target,
        ]).get_tree_hash()
    )
    assert [bytes([CREATE_COIN_ANNOUNCEMENT]), expected_claim_authorization] in conditions


def test_smart_deed_deposit_curries_immutable_commitment_into_escrow() -> None:
    deed_struct = Program.to(
        (SINGLETON_MOD_HASH, (DEED_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
    )
    par_value = 100_000
    asset_class = 2
    property_id = bytes32(b"\x81" * 32)
    collection_id = bytes32(b"\x82" * 32)
    share_ppm = 250_000
    smart_deed = SMART_DEED_V2.curry(
        deed_struct,
        PROTOCOL_DID_PUZZLE_HASH,
        par_value,
        asset_class,
        property_id,
        collection_id,
        share_ppm,
        b"US-TN",
        bytes32(b"\x83" * 32),
        100,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
        P2_POOL_V2.get_tree_hash(),
        P2_VAULT_MOD_HASH,
    )
    deed_coin_id = bytes32(b"\x84" * 32)
    pool_inner_hash = bytes32(b"\x85" * 32)
    conditions = smart_deed.run(
        Program.to(
            [
                deed_coin_id,
                smart_deed.get_tree_hash(),
                1,
                0x64,
                [pool_inner_hash],
            ]
        )
    ).as_python()

    commitment = bytes32(
        Program.to(
            [
                DEED_LAUNCHER_ID,
                par_value,
                asset_class,
                property_id,
                collection_id,
                share_ppm,
            ]
        ).get_tree_hash()
    )
    expected_escrow = P2_POOL_V2.curry(
        P2_POOL_V2.get_tree_hash(),
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
        commitment,
    )
    create = next(c for c in conditions if _atom_int(c[0]) == CREATE_COIN)
    assert create[1] == expected_escrow.get_tree_hash()

    changed_property_commitment = bytes32(
        Program.to(
            [
                DEED_LAUNCHER_ID,
                par_value,
                asset_class,
                bytes32(b"\x86" * 32),
                collection_id,
                share_ppm,
            ]
        ).get_tree_hash()
    )
    changed_escrow = P2_POOL_V2.curry(
        P2_POOL_V2.get_tree_hash(),
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        SINGLETON_LAUNCHER_HASH,
        changed_property_commitment,
    )
    assert changed_escrow.get_tree_hash() != expected_escrow.get_tree_hash()


def test_p2_pool_release_announcement_changes_with_commitment() -> None:
    commitment_a = bytes32(b"\x91" * 32)
    commitment_b = bytes32(b"\x92" * 32)
    destination = bytes32(b"\x93" * 32)
    common_solution = [
        bytes32(b"\x94" * 32),
        bytes32(b"\x95" * 32),
        bytes32(b"\x96" * 32),
        DEED_LAUNCHER_ID,
        1,
        destination,
    ]

    def conditions_for(commitment: bytes32) -> list[list[bytes]]:
        escrow = P2_POOL_V2.curry(
            P2_POOL_V2.get_tree_hash(),
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            SINGLETON_LAUNCHER_HASH,
            commitment,
        )
        return escrow.run(Program.to(common_solution)).as_python()

    conditions_a = conditions_for(commitment_a)
    conditions_b = conditions_for(commitment_b)
    assert next(
        c for c in conditions_a if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT
    ) != next(
        c for c in conditions_b if _atom_int(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT
    )
    assert next(
        c for c in conditions_a if _atom_int(c[0]) == CREATE_COIN_ANNOUNCEMENT
    ) != next(
        c for c in conditions_b if _atom_int(c[0]) == CREATE_COIN_ANNOUNCEMENT
    )
