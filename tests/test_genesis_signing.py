from __future__ import annotations

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.genesis_signing import (
    ADMIN_ENROLLMENT_TYPE,
    GENESIS_ARTIFACT_SIGNATURE_TYPE,
    GENESIS_PLAN_SIGNATURE_TYPE,
    genesis_admin_enrollment_typed_data,
    genesis_artifact_signing_typed_data,
    genesis_plan_signing_typed_data,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def test_admin_enrollment_binds_slot_wallet_nonce_and_expiry() -> None:
    typed = genesis_admin_enrollment_typed_data(
        ceremony_id=b32(1),
        slot=2,
        wallet="0x" + "ab" * 20,
        nonce=b32(2),
        expires_at=1_800_000_000,
    )
    assert typed["primaryType"] == ADMIN_ENROLLMENT_TYPE
    assert typed["domain"] == {
        "name": "Solslot Protocol",
        "version": "2",
        "chainId": 11155111,
    }
    assert typed["message"] == {
        "ceremonyId": "0x" + "01" * 32,
        "slot": 2,
        "wallet": "0x" + "ab" * 20,
        "nonce": "0x" + "02" * 32,
        "expiresAt": 1_800_000_000,
        "network": "testnet11",
    }


def test_plan_signature_binds_roster_and_exact_plan() -> None:
    typed = genesis_plan_signing_typed_data(
        ceremony_id=b32(1),
        roster_hash=b32(2),
        plan_hash=b32(3),
        expires_at=1_800_000_000,
    )
    assert typed["primaryType"] == GENESIS_PLAN_SIGNATURE_TYPE
    assert typed["message"]["rosterHash"] == "0x" + "02" * 32
    assert typed["message"]["planHash"] == "0x" + "03" * 32


def test_artifact_signature_helper_is_dependency_light_and_binds_hashes() -> None:
    typed = genesis_artifact_signing_typed_data(
        {
            "schemaVersion": 2,
            "protocolVersion": "solslot-v2",
            "network": "testnet11",
            "evmChainId": 11155111,
            "artifactHash": "0x" + "01" * 32,
            "ceremony": {
                "ceremonyId": "0x" + "02" * 32,
                "planHash": "0x" + "03" * 32,
            },
        }
    )
    assert typed["primaryType"] == GENESIS_ARTIFACT_SIGNATURE_TYPE
    assert typed["message"] == {
        "artifactHash": "0x" + "01" * 32,
        "ceremonyId": "0x" + "02" * 32,
        "planHash": "0x" + "03" * 32,
        "network": "testnet11",
    }


@pytest.mark.parametrize("slot", [0, 4])
def test_admin_enrollment_rejects_invalid_slot(slot: int) -> None:
    with pytest.raises(ValueError, match="slot"):
        genesis_admin_enrollment_typed_data(
            ceremony_id=b32(1),
            slot=slot,
            wallet="0x" + "ab" * 20,
            nonce=b32(2),
            expires_at=1,
        )


def test_genesis_signatures_reject_wrong_network_or_chain() -> None:
    with pytest.raises(ValueError, match="testnet11"):
        genesis_plan_signing_typed_data(
            ceremony_id=b32(1),
            roster_hash=b32(2),
            plan_hash=b32(3),
            expires_at=1,
            network="mainnet",
        )
    with pytest.raises(ValueError, match="Sepolia"):
        genesis_plan_signing_typed_data(
            ceremony_id=b32(1),
            roster_hash=b32(2),
            plan_hash=b32(3),
            expires_at=1,
            chain_id=1,
        )
