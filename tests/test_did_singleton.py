"""SpendSim tests: DID-approved singleton launch via singleton_launcher_with_did.clsp.

Adapted from Solslot test_lineage_singleton.py.
Proves at consensus level:
  - Singleton launch WITH DID co-spend announcement → succeeds
  - Singleton launch WITHOUT DID co-spend announcement → fails (AssertionError)
"""
from contextlib import nullcontext
from pathlib import Path
from typing import AsyncGenerator, List, Optional, Tuple

import pytest
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.condition_opcodes import ConditionOpcode
from chia.util.hash import std_hash
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    launch_conditions_and_coinsol,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, CoinSpend, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

# Load our forked launcher from the populis package
SINGLETON_APPROVAL_LAUNCHER_MOD: Program = load_clvm(
    "singleton_launcher_with_did.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)


def launch_conditions_and_solution_with_did(
    origin_coin: Coin,
    inner_puzzle: Program,
    comment: List[Tuple[str, str]],
    amount: uint64,
    did_singleton_struct: Program,
    did_inner_puzzle_hash: bytes32,
) -> Tuple[List[Program], CoinSpend]:
    """Build launch conditions + CoinSpend for a DID-approved singleton."""
    if (amount % 2) == 0:
        raise ValueError("Coin amount cannot be even.")
    launcher_mod = SINGLETON_APPROVAL_LAUNCHER_MOD.curry(did_singleton_struct)
    launcher_coin: Coin = Coin(origin_coin.name(), launcher_mod.get_tree_hash(), amount)
    singleton_launcher_hash = launcher_mod.get_tree_hash()
    curried_singleton: Program = SINGLETON_MOD.curry(
        (SINGLETON_MOD_HASH, (launcher_coin.name(), singleton_launcher_hash)),
        inner_puzzle,
    )

    launcher_solution = Program.to(
        [
            did_inner_puzzle_hash,
            curried_singleton.get_tree_hash(),
            amount,
            comment,
        ]
    )
    create_launcher = Program.to(
        [
            ConditionOpcode.CREATE_COIN,
            singleton_launcher_hash,
            amount,
        ],
    )
    assert_launcher_announcement = Program.to(
        [
            ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT,
            std_hash(launcher_coin.name() + launcher_solution.get_tree_hash()),
        ],
    )
    conditions = [create_launcher, assert_launcher_announcement]
    if launcher_coin.amount > amount:
        conditions.append(
            Program.to(
                [
                    ConditionOpcode.CREATE_COIN,
                    launcher_coin.puzzle_hash,
                    launcher_coin.amount - amount,
                ],
            )
        )

    launcher_coin_spend = make_spend(
        launcher_coin,
        launcher_mod,
        launcher_solution,
    )

    return conditions, launcher_coin_spend


does_not_raise = nullcontext


@pytest.mark.asyncio
@pytest.fixture()
async def sim_chain(
    db_path: Optional[Path] = None,
    defaults=DEFAULT_CONSTANTS,
    pass_prefarm: bool = True,
) -> AsyncGenerator[Tuple[SpendSim, SimClient], None]:
    async with SpendSim.managed(db_path, defaults=defaults) as sim:
        client: SimClient = SimClient(sim)
        if pass_prefarm:
            await sim.farm_block()
        yield sim, client


@pytest.mark.parametrize(
    "announce, expectation",
    [
        pytest.param(
            False,
            pytest.raises(AssertionError),
            id="mint_without_DID_announcement_FAIL",
        ),
        pytest.param(
            True,
            does_not_raise(),
            id="mint_with_DID_announcement_PASS",
        ),
    ],
)
async def test_did_approved_singleton(
    announce: bool, expectation, sim_chain: Tuple[SpendSim, SimClient]
):
    """Core gating proof: singleton can ONLY launch if DID co-spends with correct announcement."""
    sim, client = sim_chain

    # ACS (Anyone Can Spend) — trivial inner puzzle for testing
    acs = Program.to(1)
    acs_ph = acs.get_tree_hash()

    # Farm a block to get coins
    await sim.farm_block(acs_ph)
    coin_records = await client.get_coin_records_by_puzzle_hash(acs_ph)
    origin_coin = coin_records[0].coin
    singleton_inner_puzzle = acs

    # Step 1: Launch a DID singleton (standard launcher)
    did_launcher_conditions, did_launcher_spend = launch_conditions_and_coinsol(
        origin_coin,
        singleton_inner_puzzle,
        [],
        uint64(1),
    )
    did_eve_coin = compute_additions(did_launcher_spend)[0]
    launcher_coin = did_launcher_spend.coin
    did_launcher_id: bytes32 = launcher_coin.name()
    did_eve_puzzle_reveal: Program = puzzle_for_singleton(
        did_launcher_id,
        singleton_inner_puzzle,
    )
    assert did_eve_puzzle_reveal.get_tree_hash() == did_eve_coin.puzzle_hash

    # Change coin from origin
    change_amount = origin_coin.amount - did_eve_coin.amount
    did_launcher_conditions.append(
        Program.to([ConditionOpcode.CREATE_COIN, acs_ph, change_amount])
    )
    origin_coin_spend = make_spend(
        origin_coin, acs, Program.to(did_launcher_conditions)
    )

    # DID singleton struct
    did_singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (did_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )

    did_lineage_proof: LineageProof = lineage_proof_for_coinsol(did_launcher_spend)

    # Step 2: Launch a property singleton with DID approval
    property_origin_coin = Coin(origin_coin.name(), acs_ph, change_amount)
    property_launcher_conditions, property_launcher_spend = (
        launch_conditions_and_solution_with_did(
            property_origin_coin,
            singleton_inner_puzzle,
            [],
            uint64(1),
            did_singleton_struct,
            singleton_inner_puzzle.get_tree_hash(),
        )
    )
    property_launcher_coin = property_launcher_spend.coin
    property_origin_spend = make_spend(
        property_origin_coin, acs, Program.to(property_launcher_conditions)
    )
    property_eve_coin = compute_additions(property_launcher_spend)[0]
    property_full_puzzle_hash = property_eve_coin.puzzle_hash

    prop_lineage_proof = LineageProof(
        property_launcher_spend.coin.parent_coin_info, None, 1
    )
    property_eve_full_solution: Program = solution_for_singleton(
        prop_lineage_proof,
        uint64(did_eve_coin.amount),
        Program.to([[ConditionOpcode.CREATE_COIN, acs_ph, 1]]),
    )
    property_eve_puzzle_reveal: Program = puzzle_for_singleton(
        property_launcher_coin.name(),
        singleton_inner_puzzle,
        SINGLETON_APPROVAL_LAUNCHER_MOD.curry(did_singleton_struct).get_tree_hash(),
    )
    property_eve_spend = make_spend(
        property_eve_coin,
        property_eve_puzzle_reveal,
        property_eve_full_solution,
    )

    # Step 3: DID eve spend — announce (or not) the property creation
    with expectation:
        ann_value = property_full_puzzle_hash if announce else b"blah"
        did_eve_full_solution: Program = solution_for_singleton(
            did_lineage_proof,
            uint64(did_eve_coin.amount),
            Program.to(
                [
                    [ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT, ann_value],
                    [ConditionOpcode.CREATE_COIN, acs_ph, 1],
                ]
            ),
        )
        did_eve_spend = make_spend(
            did_eve_coin,
            did_eve_puzzle_reveal,
            did_eve_full_solution,
        )

        final_bundle = SpendBundle(
            [
                origin_coin_spend,
                did_launcher_spend,
                did_eve_spend,
                property_origin_spend,
                property_launcher_spend,
                property_eve_spend,
            ],
            G2Element(),
        )
        status, err = await client.push_tx(final_bundle)
        assert not err
