from __future__ import annotations

import copy

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.artifact_schema_v2 import (
    CeremonyCoordinates,
    artifact_hash,
    build_public_artifact,
    verify_public_artifact,
)
from solslot_puzzles.protocol_deployment import ProtocolDeploymentParams, ProtocolDeploymentPlan
from tests.test_protocol_deployment import (
    DID_GENESIS,
    GOV_GENESIS,
    POOL_GENESIS,
    SGT_GENESIS,
    _FakeFaucet,
    trusted_v2_kwargs,
)


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


def ceremony() -> CeremonyCoordinates:
    return CeremonyCoordinates(
        nav_registry_launcher_id=bytes32(b"\x91" * 32),
        protocol_config_launcher_id=bytes32(b"\x92" * 32),
        admin_authority_launcher_id=bytes32(b"\x93" * 32),
        vault_version_registry_launcher_id=bytes32(b"\x94" * 32),
        bridge_policy_hash=bytes32(b"\x95" * 32),
    )


def plan() -> ProtocolDeploymentPlan:
    faucet = _FakeFaucet()
    return ProtocolDeploymentPlan(
        network="testnet11",
        params=ProtocolDeploymentParams(),
        faucet_inner_puzhash=faucet.address_puzzle_hash,
        sgt_genesis_coin_id=SGT_GENESIS,
        pool_genesis_coin_id=POOL_GENESIS,
        did_genesis_coin_id=DID_GENESIS,
        gov_genesis_coin_id=GOV_GENESIS,
        **trusted_v2_kwargs(),
    )


def artifact() -> dict:
    return build_public_artifact(
        plan=plan(),
        ceremony=ceremony(),
        source_shas=SOURCE_SHAS,
        evm_chain_id=84532,
        evm_addresses=EVM_ADDRESSES,
        retired_coordinates=["0x" + "aa" * 32],
        build_timestamp="2026-07-12T00:00:00+00:00",
    )


def test_artifact_has_required_public_v2_surface() -> None:
    value = artifact()
    assert value["schemaVersion"] == 2
    assert value["protocolVersion"] == "solslot-v2"
    assert value["sgtGenesisCoinId"].startswith("0x")
    assert value["sgtTailHash"] == value["puzzleHashes"]["sgtTailHash"]
    assert value["launcherIds"]["vaultVersionRegistry"].startswith("0x")
    verify_public_artifact(value)


def test_artifact_hash_is_canonical_and_tamper_evident() -> None:
    value = artifact()
    assert value["artifactHash"] == artifact_hash(value)
    tampered = copy.deepcopy(value)
    tampered["network"] = "mainnet"
    with pytest.raises(ValueError, match="artifactHash"):
        verify_public_artifact(tampered)


def test_missing_source_or_zero_coordinate_fails_closed() -> None:
    sources = dict(SOURCE_SHAS)
    del sources["api"]
    with pytest.raises(ValueError, match="sourceShas"):
        build_public_artifact(
            plan=plan(),
            ceremony=ceremony(),
            source_shas=sources,
            evm_chain_id=84532,
            evm_addresses=EVM_ADDRESSES,
            retired_coordinates=[],
        )

    bad = CeremonyCoordinates(
        nav_registry_launcher_id=bytes32.zeros,
        protocol_config_launcher_id=bytes32(b"\x92" * 32),
        admin_authority_launcher_id=bytes32(b"\x93" * 32),
        vault_version_registry_launcher_id=bytes32(b"\x94" * 32),
        bridge_policy_hash=bytes32(b"\x95" * 32),
    )
    with pytest.raises(ValueError, match="nonzero"):
        build_public_artifact(
            plan=plan(),
            ceremony=bad,
            source_shas=SOURCE_SHAS,
            evm_chain_id=84532,
            evm_addresses=EVM_ADDRESSES,
            retired_coordinates=[],
        )
