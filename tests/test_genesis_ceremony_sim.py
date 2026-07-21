from __future__ import annotations

import pytest
from chia._tests.util.coin_store import add_coin_records_to_db
from chia._tests.util.spend_sim import sim_and_client
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.genesis_ceremony import build_genesis_ceremony_bundle
from tests.test_genesis_ceremony import ceremony_plan, funding_coins
from tests.test_protocol_deployment import _FakeFaucet


@pytest.mark.anyio
async def test_complete_genesis_bundle_passes_testnet11_consensus() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    plan = ceremony_plan(faucet, coins)
    bundle = build_genesis_ceremony_bundle(
        plan=plan,
        faucet=faucet,
        funding_coins=coins,
    ).spend_bundle

    constants = DEFAULT_CONSTANTS.replace(
        AGG_SIG_ME_ADDITIONAL_DATA=bytes32(faucet.agg_sig_me_data),
    )
    async with sim_and_client(defaults=constants) as (sim, client):
        await add_coin_records_to_db(
            sim.coin_store,
            [sim.new_coin_record(coin) for coin in coins.values()],
        )

        status, error = await client.push_tx(bundle)

        assert status is MempoolInclusionStatus.SUCCESS, error
        assert error is None
