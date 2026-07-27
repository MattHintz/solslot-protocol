from __future__ import annotations

import copy

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.artifact_schema_v3 import (
    INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    artifact_hash,
    artifact_signing_typed_data,
    build_public_artifact,
    verify_public_artifact,
)
from tests.test_genesis_ceremony_rc22 import ceremony_plan, funding_coins
from tests.test_genesis_ceremony import ADMIN_KEYS
from tests.test_protocol_deployment import _FakeFaucet


def _signatures(*slots: int) -> list[dict[str, object]]:
    return [
        {
            "adminIndex": slot,
            "compressedPubkey": "0x" + ADMIN_KEYS[slot].hex(),
            "signature": "0x" + bytes([slot + 1] * 65).hex(),
        }
        for slot in slots
    ]


def _artifact(*, signed_slots: tuple[int, ...] = (0, 2)) -> dict:
    faucet = _FakeFaucet()
    return build_public_artifact(
        plan=ceremony_plan(faucet, funding_coins(faucet)),
        spend_bundle_id=bytes32(b"\x91" * 32),
        confirmed_block_index=1234,
        build_timestamp="2026-07-27T00:00:00+00:00",
        signatures=_signatures(*signed_slots),
        review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    )


def _accept(*_args: object) -> bool:
    return True


def test_v3_artifact_reconstructs_the_complete_rc22_plan() -> None:
    value = _artifact()
    assert value["schemaVersion"] == 3
    assert value["protocolVersion"] == "solslot-v2-rc22"
    assert value["genesisPlan"]["schema"] == "solslot-genesis-plan-v3"
    assert "statutes" in value["launcherIds"]
    assert "navRegistry" not in value["launcherIds"]
    assert value["bridgePolicy"]["fundingAmount"] == 529
    assert value["bridgePolicy"]["networkFeeSource"] == (
        "separate-fountain-fee-till"
    )
    assert value["solsTailHash"] == value["puzzleHashes"]["solsTailHash"]
    assert value["permanentRules"]["solsPrimaryPurchasesDisabled"] is True
    verify_public_artifact(value, signature_verifier=_accept)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    (
        (("genesisPlan", "launcherIds", "pool"), "0x" + "ff" * 32, "reconstruct"),
        (("launcherIds", "pool"), "0x" + "fe" * 32, "launcherIds"),
        (("bridgePolicy", "fundingAmount"), 530, "bridgePolicy"),
        (
            ("permanentRules", "solsPrimaryPurchasesDisabled"),
            False,
            "permanentRules",
        ),
    ),
)
def test_v3_artifact_rejects_plan_or_projection_tampering(
    path: tuple[str, ...],
    replacement: object,
    message: str,
) -> None:
    value = copy.deepcopy(_artifact())
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    value["artifactHash"] = artifact_hash(value)
    with pytest.raises(ValueError, match=message):
        verify_public_artifact(value, signature_verifier=_accept)


def test_v3_signing_payload_and_owner_plus_one_policy() -> None:
    value = _artifact()
    typed = artifact_signing_typed_data(value)
    assert typed["domain"]["version"] == "3"
    assert typed["message"]["planHash"] == value["ceremony"]["planHash"]

    value["signatures"] = _signatures(1, 2)
    with pytest.raises(ValueError, match="slot 0"):
        verify_public_artifact(value, signature_verifier=_accept)
