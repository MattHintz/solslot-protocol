"""Cross-contract Solslot V2 condition pairing for the active pool exits."""

from __future__ import annotations

import hashlib

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.pool_economics_v2 import (
    CollectionNavEvidence,
    PoolEconomicState,
    build_reserve_acquisition_spec,
    build_true_redemption_spec,
)
from solslot_puzzles.protocol_deployment import singleton_full_puzzle_hash
from tests.test_pool import (
    DEED_ASSET_CLASS,
    DEED_LAUNCHER_ID,
    DEED_PAR_VALUE,
    DEED_PROPERTY_ID,
    LAUNCHER_PUZZLE_HASH,
    MIN_NAV_REGISTRY_VERSION,
    POOL_ACTIVE,
    POOL_LAUNCHER_ID,
    POOL_SPEND_V2_RESERVE_ACQUISITION,
    POOL_SPEND_V2_TRUE_REDEMPTION,
    PROTOCOL_PREFIX,
    computed_nav_registry_puzzle_hash,
    computed_p2_vault_ph,
    curry_pool,
    make_pool_solution,
)


P2_POOL_V2 = load_clvm(
    "p2_pool_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
POOL_TOKEN_TAIL = load_clvm(
    "pool_token_tail.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
SMART_DEED_V2 = load_clvm(
    "smart_deed_inner_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

CREATE_COIN_ANNOUNCEMENT = 60
ASSERT_COIN_ANNOUNCEMENT = 61
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
TOKEN_MELT = -1


def _opcode(condition: list[object]) -> int:
    value = condition[0]
    return int.from_bytes(value, "big") if isinstance(value, bytes) else int(value)


def _conditions_with(conditions: list[list[object]], opcode: int) -> list[list[object]]:
    return [condition for condition in conditions if _opcode(condition) == opcode]


def _evidence(
    *,
    collection_id: bytes32,
    nav_root: bytes32,
    nav_value: int,
) -> CollectionNavEvidence:
    registry_coin_id = bytes32(b"\xc1" * 32)
    registry_puzzle_hash = computed_nav_registry_puzzle_hash(
        nav_root, MIN_NAV_REGISTRY_VERSION
    )
    return CollectionNavEvidence(
        registry_coin_id=registry_coin_id,
        registry_puzzle_hash=registry_puzzle_hash,
        collection_id_canon=collection_id,
        nav_value_mojos=nav_value,
        collection_nav_root=nav_root,
        registry_version=MIN_NAV_REGISTRY_VERSION,
    )


def test_true_redemption_pairs_pool_escrow_and_token_tail() -> None:
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    pool = curry_pool(
        tvl=state.total_nav_locked_mojos,
        deed_count=state.deed_count,
        total_pool_token_supply=state.total_pool_token_supply,
        treasury_reserve_tokens=state.treasury_reserve_tokens,
    )
    pool_coin_id = bytes32(b"\x11" * 32)
    deed_coin_id = bytes32(b"\xd1" * 32)
    collection_id = bytes32(b"\xa1" * 32)
    nav = _evidence(
        collection_id=collection_id,
        nav_root=bytes32(b"\xc3" * 32),
        nav_value=1_000_000_000,
    )
    vault_launcher_id = bytes32(b"\xee" * 32)
    p2_vault = computed_p2_vault_ph(vault_launcher_id)
    token_coin_id = bytes32(b"\xe1" * 32)
    spec = build_true_redemption_spec(
        state,
        deed_id=deed_coin_id,
        deed_launcher_id=DEED_LAUNCHER_ID,
        par_value_mojos=DEED_PAR_VALUE,
        asset_class=DEED_ASSET_CLASS,
        property_id_canon=DEED_PROPERTY_ID,
        p2_vault_puzzle_hash=p2_vault,
        collection_id_canon=collection_id,
        share_ppm=250_000,
        nav_evidence=nav,
        token_coin_id=token_coin_id,
    )
    pool_conditions = pool.run(
        make_pool_solution(
            pool_coin_id,
            pool.get_tree_hash(),
            1,
            POOL_SPEND_V2_TRUE_REDEMPTION,
            [
                deed_coin_id,
                DEED_LAUNCHER_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                DEED_PROPERTY_ID,
                collection_id,
                250_000,
                nav.nav_value_mojos,
                nav.collection_nav_root,
                nav.registry_version,
                nav.registry_coin_id,
                nav.registry_puzzle_hash,
                vault_launcher_id,
                LAUNCHER_PUZZLE_HASH,
                token_coin_id,
            ],
        )
    ).as_python()

    escrow = P2_POOL_V2.curry(
        P2_POOL_V2.get_tree_hash(),
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
        spec.deed_commitment,
    )
    escrow_conditions = escrow.run(
        Program.to(
            [
                pool.get_tree_hash(),
                pool_coin_id,
                deed_coin_id,
                DEED_LAUNCHER_ID,
                1,
                p2_vault,
            ]
        )
    ).as_python()

    escrow_coin_message = _conditions_with(
        escrow_conditions, CREATE_COIN_ANNOUNCEMENT
    )[0][1]
    pool_deed_assertion = _conditions_with(
        pool_conditions, ASSERT_COIN_ANNOUNCEMENT
    )[0][1]
    assert pool_deed_assertion == hashlib.sha256(
        bytes(deed_coin_id) + escrow_coin_message
    ).digest()

    pool_release_message = next(
        condition[1]
        for condition in _conditions_with(pool_conditions, CREATE_PUZZLE_ANNOUNCEMENT)
        if condition[1]
        == PROTOCOL_PREFIX
        + Program.to(
            [pool_coin_id, deed_coin_id, spec.deed_commitment, p2_vault]
        ).get_tree_hash()
    )
    escrow_pool_assertion = _conditions_with(
        escrow_conditions, ASSERT_PUZZLE_ANNOUNCEMENT
    )[0][1]
    current_pool_full_hash = singleton_full_puzzle_hash(
        POOL_LAUNCHER_ID, pool.get_tree_hash()
    )
    assert escrow_pool_assertion == hashlib.sha256(
        bytes(current_pool_full_hash) + pool_release_message
    ).digest()

    tail = POOL_TOKEN_TAIL.curry(
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )
    tail_conditions = tail.run(
        Program.to(
            [
                current_pool_full_hash,
                pool.get_tree_hash(),
                pool_coin_id,
                token_coin_id,
                TOKEN_MELT,
                spec.quote.principal_tokens,
            ]
        )
    ).as_python()
    token_message = spec.token_authorizations[0].announcement_message
    assert _conditions_with(tail_conditions, ASSERT_PUZZLE_ANNOUNCEMENT)[0][1] == hashlib.sha256(
        bytes(current_pool_full_hash) + token_message
    ).digest()


def test_reserve_acquisition_pairs_smart_deed_commitment() -> None:
    state = PoolEconomicState(
        total_nav_locked_mojos=1_000_000_000,
        deed_count=10,
        total_pool_token_supply=800_000_000,
        treasury_reserve_tokens=200_000_000,
    )
    pool = curry_pool(
        tvl=state.total_nav_locked_mojos,
        deed_count=state.deed_count,
        total_pool_token_supply=state.total_pool_token_supply,
        treasury_reserve_tokens=state.treasury_reserve_tokens,
    )
    pool_coin_id = bytes32(b"\x11" * 32)
    deed_coin_id = bytes32(b"\xd1" * 32)
    collection_id = bytes32(b"\xa1" * 32)
    nav = _evidence(
        collection_id=collection_id,
        nav_root=bytes32(b"\xc3" * 32),
        nav_value=400_000_000,
    )
    seller = bytes32(b"\xb1" * 32)
    spec = build_reserve_acquisition_spec(
        state,
        deed_id=deed_coin_id,
        deed_launcher_id=DEED_LAUNCHER_ID,
        property_id_canon=DEED_PROPERTY_ID,
        par_value_mojos=DEED_PAR_VALUE,
        asset_class=DEED_ASSET_CLASS,
        collection_id_canon=collection_id,
        share_ppm=500_000,
        nav_evidence=nav,
        seller_puzhash=seller,
        seller_token_price=200_000_000,
        mint_token_coin_id=None,
    )
    pool_conditions = pool.run(
        make_pool_solution(
            pool_coin_id,
            pool.get_tree_hash(),
            1,
            POOL_SPEND_V2_RESERVE_ACQUISITION,
            [
                deed_coin_id,
                DEED_LAUNCHER_ID,
                DEED_PROPERTY_ID,
                DEED_PAR_VALUE,
                DEED_ASSET_CLASS,
                collection_id,
                500_000,
                nav.nav_value_mojos,
                nav.collection_nav_root,
                nav.registry_version,
                nav.registry_coin_id,
                nav.registry_puzzle_hash,
                seller,
                200_000_000,
                None,
            ],
        )
    ).as_python()
    pool_deed_assertion = _conditions_with(
        pool_conditions, ASSERT_COIN_ANNOUNCEMENT
    )[0][1]
    assert pool_deed_assertion == hashlib.sha256(
        bytes(deed_coin_id) + spec.deed_message
    ).digest()
