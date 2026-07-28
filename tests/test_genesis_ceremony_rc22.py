from __future__ import annotations

from dataclasses import replace

import pytest
from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.util.compute_additions import compute_additions
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.genesis_ceremony_rc22 import (
    RC22_BRIDGE_BATCH_FUNDING_AMOUNT,
    RC22_BRIDGE_PARENT_TOTAL,
    RC22_GENESIS_PLAN_SCHEMA,
    RC22_PROPERTY_REGISTRY_LAUNCHER_AMOUNT,
    RC22GenesisFundingCoins,
    build_rc22_genesis_ceremony_bundle,
    build_rc22_genesis_ceremony_plan,
    verify_rc22_genesis_ceremony_plan,
)
from solslot_puzzles.sgt_driver import TEST_KOS_MINT_EXECUTE_PUBKEY
from tests.test_genesis_ceremony import (
    ADMIN_KEYS,
    EVM_ADDRESSES,
    SOURCE_SHAS,
    VALIDATOR_KEYS,
)
from tests.test_protocol_deployment import _FakeFaucet


def funding_coins(faucet: _FakeFaucet) -> RC22GenesisFundingCoins:
    amounts = (
        1_000_100,
        100,
        100,
        100,
        100,
        100,
        100,
        100,
        RC22_BRIDGE_BATCH_FUNDING_AMOUNT,
    )
    return RC22GenesisFundingCoins(
        *(
            Coin(
                bytes32(bytes([index]) * 32),
                faucet.address_puzzle_hash,
                uint64(amount),
            )
            for index, amount in enumerate(amounts, start=1)
        )
    )


def ceremony_plan(
    faucet: _FakeFaucet,
    coins: RC22GenesisFundingCoins,
):
    return build_rc22_genesis_ceremony_plan(
        ceremony_id=bytes32(b"\xA1" * 32),
        expires_at=1_800_000_000,
        source_shas=SOURCE_SHAS,
        evm_addresses=EVM_ADDRESSES,
        funding=coins.ids(),
        faucet_puzzle_hash=faucet.address_puzzle_hash,
        governance_bls_pubkey=b"\x51" * 48,
        kos_mint_execute_pubkey=TEST_KOS_MINT_EXECUTE_PUBKEY,
        admin_compressed_pubkeys=ADMIN_KEYS,
        validator_pubkeys=VALIDATOR_KEYS,
        trusted_treasury_reserve_puzzle_hash=bytes32(b"\x61" * 32),
        trusted_protocol_treasury_puzzle_hash=bytes32(b"\x62" * 32),
        trusted_governance_rewards_puzzle_hash=bytes32(b"\x63" * 32),
        trusted_governance_rewards_root=bytes32(b"\x64" * 32),
        retired_coordinates=(bytes32(b"\x71" * 32),),
    )


def test_rc22_plan_replaces_nav_registry_with_statutes() -> None:
    faucet = _FakeFaucet()
    plan = ceremony_plan(faucet, funding_coins(faucet))
    verify_rc22_genesis_ceremony_plan(plan)
    payload = plan.canonical_payload()
    assert payload["schema"] == RC22_GENESIS_PLAN_SCHEMA
    assert "statutes" in payload["launcherIds"]
    assert "navRegistry" not in payload["launcherIds"]
    assert "statutes" in payload["fundingCoinIds"]
    assert "nav_registry" not in payload["fundingCoinIds"]
    assert payload["bridgeBatch"]["fundingAmount"] == 529
    assert set(payload["state"]["statutesRoots"]) == {
        "parameters",
        "collections",
        "oracles",
        "bridgeRoutes",
        "liquidityVenues",
        "pauses",
    }
    assert payload["state"]["statutesRoots"]["liquidityVenues"] == (
        "0x" + plan.protocol.statutes_state.liquidity_root.hex()
    )
    assert payload["bridgeBatch"]["parentOutputAmount"] == 528
    assert payload["bridgeBatch"]["propertyRegistryLauncherAmount"] == 1
    assert payload["bridgeBatch"]["changeAmount"] == 0
    assert payload["bridgeBatch"]["networkFeeSource"] == (
        "separate-fountain-fee-till"
    )
    assert payload["puzzleHashes"]["poolInnerMod"] == (
        "0xf6704dc71b171811a142c1a3ed92867880db3bad1e8e49f0f7c5cdf6d246739f"
    )


def test_rc22_bundle_keeps_nine_inputs_and_49_atomic_spends() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    plan = ceremony_plan(faucet, coins)
    built = build_rc22_genesis_ceremony_bundle(
        plan=plan,
        faucet=faucet,
        funding_coins=coins,
    )
    assert len(built.spend_bundle.coin_spends) == 49
    spent = {
        bytes32(spend.coin.name())
        for spend in built.spend_bundle.coin_spends
    }
    assert plan.protocol.statutes_launcher_id in spent
    assert all(
        bytes32(parent.name()) in spent
        for parent in plan.bridge_batch.parent_coins
    )


def test_bridge_batch_has_unique_outputs_and_no_embedded_fee() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    built = build_rc22_genesis_ceremony_bundle(
        plan=ceremony_plan(faucet, coins),
        faucet=faucet,
        funding_coins=coins,
    )
    batch_spend = next(
        spend
        for spend in built.spend_bundle.coin_spends
        if spend.coin.name() == coins.bridge_batch.name()
    )
    conditions = conditions_dict_for_solution(
        batch_spend.puzzle_reveal,
        batch_spend.solution,
        INFINITE_COST,
    )
    created_amount = sum(
        int.from_bytes(condition.vars[1], "big")
        for condition in conditions[ConditionOpcode.CREATE_COIN]
    )
    additions = compute_additions(batch_spend)
    addition_ids = [coin.name() for coin in additions]

    assert RC22_BRIDGE_PARENT_TOTAL == 528
    assert RC22_PROPERTY_REGISTRY_LAUNCHER_AMOUNT == 1
    assert RC22_BRIDGE_BATCH_FUNDING_AMOUNT == 529
    assert created_amount == RC22_BRIDGE_BATCH_FUNDING_AMOUNT
    assert len(additions) == len(built.plan.bridge_batch.parent_coins) + 1
    assert len(addition_ids) == len(set(addition_ids))
    assert ConditionOpcode.RESERVE_FEE not in conditions


@pytest.mark.parametrize("wrong_amount", (528, 530, 531))
def test_bridge_funding_requires_exact_529_mojos(
    wrong_amount: int,
) -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    wrong = replace(
        coins,
        bridge_batch=Coin(
            coins.bridge_batch.parent_coin_info,
            coins.bridge_batch.puzzle_hash,
            uint64(wrong_amount),
        ),
    )
    wrong_plan = ceremony_plan(faucet, wrong)
    with pytest.raises(ValueError, match="exactly 529"):
        build_rc22_genesis_ceremony_bundle(
            plan=wrong_plan,
            faucet=faucet,
            funding_coins=wrong,
        )


def test_plan_hash_rejects_surface_mutation() -> None:
    faucet = _FakeFaucet()
    plan = ceremony_plan(faucet, funding_coins(faucet))
    with pytest.raises(ValueError, match="plan hash"):
        verify_rc22_genesis_ceremony_plan(
            replace(plan, expires_at=plan.expires_at + 1)
        )
