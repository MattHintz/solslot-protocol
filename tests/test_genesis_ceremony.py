from __future__ import annotations

from dataclasses import replace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.genesis_ceremony import (
    GENESIS_BRIDGE_BATCH_SIZE,
    GenesisFundingCoins,
    build_genesis_ceremony_bundle,
    build_genesis_ceremony_plan,
    verify_genesis_ceremony_plan,
)
from solslot_puzzles.protocol_deployment import ProtocolDeploymentParams
from solslot_puzzles.sgt_driver import TEST_KOS_MINT_EXECUTE_PUBKEY
from tests.test_protocol_deployment import _FakeFaucet


SOURCE_SHAS = {
    "protocol": "1" * 40,
    "evm": "2" * 40,
    "api": "3" * 40,
    "customerWeb": "4" * 40,
    "adminPortal": "5" * 40,
}
EVM_ADDRESSES = {
    "forwarder": "0x" + "11" * 20,
    "verifierAdapter": "0x" + "22" * 20,
    "attestationEmitter": "0x" + "33" * 20,
}
ADMIN_KEYS = (
    bytes.fromhex("02" + "11" * 32),
    bytes.fromhex("03" + "22" * 32),
    bytes.fromhex("02" + "33" * 32),
)
VALIDATOR_KEYS = (b"\x41" * 48, b"\x42" * 48, b"\x43" * 48)


def funding_coins(faucet: _FakeFaucet) -> GenesisFundingCoins:
    amounts = (1_000_100, 100, 100, 100, 100, 100, 100, 100, 1_000)
    coins = tuple(
        Coin(
            bytes32(bytes([index]) * 32),
            faucet.address_puzzle_hash,
            uint64(amount),
        )
        for index, amount in enumerate(amounts, start=1)
    )
    return GenesisFundingCoins(*coins)


def ceremony_plan(faucet: _FakeFaucet, coins: GenesisFundingCoins):
    return build_genesis_ceremony_plan(
        ceremony_id=bytes32(b"\xa1" * 32),
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
        params=ProtocolDeploymentParams(min_nav_registry_version=1),
    )


def test_plan_derives_all_surfaces_and_bridge_lineage() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    plan = ceremony_plan(faucet, coins)

    verify_genesis_ceremony_plan(plan)
    assert plan.admin_quorum.threshold == 2
    assert plan.validator_threshold == 2
    assert len(plan.bridge_batch.parent_coins) == GENESIS_BRIDGE_BATCH_SIZE
    assert len(plan.bridge_batch.bridge_coins) == GENESIS_BRIDGE_BATCH_SIZE
    assert len({coin.name() for coin in plan.bridge_batch.bridge_coins}) == 32
    assert all(coin.amount == 1 for coin in plan.bridge_batch.bridge_coins)
    assert all(
        bridge.parent_coin_info == parent.name()
        for parent, bridge in zip(
            plan.bridge_batch.parent_coins,
            plan.bridge_batch.bridge_coins,
            strict=True,
        )
    )
    assert set(plan.canonical_payload()["launcherIds"]) == {
        "pool",
        "did",
        "governance",
        "navRegistry",
        "protocolConfig",
        "adminAuthority",
        "vaultVersionRegistry",
        "propertyRegistry",
    }
    assert plan.property_registry_version == 0
    assert plan.property_registry.launcher_id != bytes32.zeros


def test_plan_hash_binds_mutations() -> None:
    faucet = _FakeFaucet()
    plan = ceremony_plan(faucet, funding_coins(faucet))
    mutated = replace(plan, expires_at=plan.expires_at + 1)
    with pytest.raises(ValueError, match="plan hash"):
        verify_genesis_ceremony_plan(mutated)


def test_bundle_contains_all_ephemeral_spends() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    plan = ceremony_plan(faucet, coins)
    built = build_genesis_ceremony_bundle(
        plan=plan,
        faucet=faucet,
        funding_coins=coins,
    )

    assert len(built.spend_bundle.coin_spends) == 49
    spent_ids = {spend.coin.name() for spend in built.spend_bundle.coin_spends}
    assert all(parent.name() in spent_ids for parent in plan.bridge_batch.parent_coins)
    assert bytes(built.spend_bundle.aggregated_signature) != bytes(96)


def test_live_coin_change_invalidates_signed_plan() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    plan = ceremony_plan(faucet, coins)
    replacement = Coin(
        bytes32(b"\xfe" * 32),
        faucet.address_puzzle_hash,
        uint64(100),
    )
    changed = replace(coins, pool=replacement)
    with pytest.raises(ValueError, match="signed ceremony plan"):
        build_genesis_ceremony_bundle(
            plan=plan,
            faucet=faucet,
            funding_coins=changed,
        )


def test_noncanonical_admin_or_validator_sets_fail() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    common = dict(
        ceremony_id=bytes32(b"\xa1" * 32),
        expires_at=1_800_000_000,
        source_shas=SOURCE_SHAS,
        evm_addresses=EVM_ADDRESSES,
        funding=coins.ids(),
        faucet_puzzle_hash=faucet.address_puzzle_hash,
        governance_bls_pubkey=b"\x51" * 48,
        kos_mint_execute_pubkey=TEST_KOS_MINT_EXECUTE_PUBKEY,
        trusted_treasury_reserve_puzzle_hash=bytes32(b"\x61" * 32),
        trusted_protocol_treasury_puzzle_hash=bytes32(b"\x62" * 32),
        trusted_governance_rewards_puzzle_hash=bytes32(b"\x63" * 32),
        trusted_governance_rewards_root=bytes32(b"\x64" * 32),
        retired_coordinates=(),
        params=ProtocolDeploymentParams(min_nav_registry_version=1),
    )
    with pytest.raises(ValueError, match="exactly three admin"):
        build_genesis_ceremony_plan(
            **common,
            admin_compressed_pubkeys=ADMIN_KEYS[:2],
            validator_pubkeys=VALIDATOR_KEYS,
        )
    with pytest.raises(ValueError, match="three validators"):
        build_genesis_ceremony_plan(
            **common,
            admin_compressed_pubkeys=ADMIN_KEYS,
            validator_pubkeys=VALIDATOR_KEYS[:2],
        )


def test_ceremony_rejects_empty_mint_execute_cosigner() -> None:
    faucet = _FakeFaucet()
    coins = funding_coins(faucet)
    with pytest.raises(ValueError, match="kos_mint_execute_pubkey"):
        build_genesis_ceremony_plan(
            ceremony_id=bytes32(b"\xa1" * 32),
            expires_at=1_800_000_000,
            source_shas=SOURCE_SHAS,
            evm_addresses=EVM_ADDRESSES,
            funding=coins.ids(),
            faucet_puzzle_hash=faucet.address_puzzle_hash,
            governance_bls_pubkey=b"\x51" * 48,
            kos_mint_execute_pubkey=b"\x00" * 48,
            admin_compressed_pubkeys=ADMIN_KEYS,
            validator_pubkeys=VALIDATOR_KEYS,
            trusted_treasury_reserve_puzzle_hash=bytes32(b"\x61" * 32),
            trusted_protocol_treasury_puzzle_hash=bytes32(b"\x62" * 32),
            trusted_governance_rewards_puzzle_hash=bytes32(b"\x63" * 32),
            trusted_governance_rewards_root=bytes32(b"\x64" * 32),
            retired_coordinates=(),
            params=ProtocolDeploymentParams(min_nav_registry_version=1),
        )
