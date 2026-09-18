"""Consensus acceptance and immutable funding authorization for RC23 genesis."""
from __future__ import annotations

import pytest
from chia._tests.util.coin_store import add_coin_records_to_db
from chia._tests.util.spend_sim import sim_and_client
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH, get_innerpuzzle_from_puzzle
from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.genesis_ceremony_rc23 import (
    build_rc23_genesis_ceremony_bundle, build_rc23_sgt_issuance,
)
from tests.test_genesis_ceremony_rc23 import ceremony_plan, funding_coins
from tests.test_protocol_deployment import _FakeFaucet


def candidate():
    faucet = _FakeFaucet()
    funding = funding_coins(faucet)
    plan = ceremony_plan(faucet, funding)
    bundle = build_rc23_genesis_ceremony_bundle(
        plan=plan, faucet=faucet, funding_coins=funding,
    ).spend_bundle
    return faucet, funding, plan, bundle


def launcher_ids(plan):
    return [plan.protocol.pool_launcher_id, plan.protocol.did_launcher_id,
        plan.protocol.governance_launcher_id, plan.statutes.launcher_id,
        plan.protocol_config.launcher_id, plan.vault_version_registry.launcher_id,
        plan.property_registry.launcher_id, plan.admin_authority.launcher_id,
        *(identity.launcher_id for identity in plan.admin_authority_v3.identity_vaults)]


@pytest.mark.anyio
async def test_sgt_issuance_preserves_supply_and_establishes_cat_parent():
    faucet, funding, plan, bundle = candidate()
    issuance = build_rc23_sgt_issuance(plan)
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(faucet.agg_sig_me_data))
    async with sim_and_client(defaults=constants) as (sim, client):
        await add_coin_records_to_db(sim.coin_store, [sim.new_coin_record(c) for c in funding.values()])
        status, error = await client.push_tx(bundle)
        assert status is MempoolInclusionStatus.SUCCESS, error
        await sim.farm_block()
        eve = await client.get_coin_record_by_name(issuance.eve_coin.name())
        reserve = await client.get_coin_record_by_name(issuance.reserve_coin.name())
        assert eve and eve.spent
        assert reserve and not reserve.spent
        assert reserve.coin.parent_coin_info == eve.coin.name()
        assert reserve.coin.amount == eve.coin.amount == plan.protocol.permanent_rules.sgt_total_supply
        assert reserve.coin.puzzle_hash == plan.protocol.sgt_full_puzzle_hash
        parent = await client.get_puzzle_and_solution(eve.coin.name(), eve.spent_block_index)
        puzzle = Program.from_bytes(bytes(parent.puzzle_reveal))
        assert puzzle.uncurry()[0].get_tree_hash() == CAT_MOD_HASH
        assert get_innerpuzzle_from_puzzle(puzzle).get_tree_hash()
        assert len({c.name() for c in funding.values()}) == 9


@pytest.mark.anyio
@pytest.mark.parametrize('index', range(11))
@pytest.mark.parametrize('mutation', ['destination', 'amount', 'omitted'])
async def test_unsigned_launcher_changes_cannot_reuse_funding_authorization(index, mutation):
    faucet, funding, plan, bundle = candidate()
    selected = launcher_ids(plan)[index]
    spends = []
    for spend in bundle.coin_spends:
        if spend.coin.name() != selected:
            spends.append(spend)
        elif mutation != 'omitted':
            values = list(Program.from_bytes(bytes(spend.solution)).as_iter())
            if mutation == 'destination':
                values[0] = Program.to(bytes32(b'\xfa' * 32))
            else:
                values[1] = Program.to(values[1].as_int() + 2)
            spends.append(make_spend(spend.coin, Program.from_bytes(bytes(spend.puzzle_reveal)), Program.to(values)))
    changed = SpendBundle(spends, bundle.aggregated_signature)
    constants = DEFAULT_CONSTANTS.replace(AGG_SIG_ME_ADDITIONAL_DATA=bytes32(faucet.agg_sig_me_data))
    async with sim_and_client(defaults=constants) as (sim, client):
        await add_coin_records_to_db(sim.coin_store, [sim.new_coin_record(c) for c in funding.values()])
        status, error = await client.push_tx(changed)
        assert status is MempoolInclusionStatus.FAILED
        assert error is not None
