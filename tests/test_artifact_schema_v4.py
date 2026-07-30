from __future__ import annotations

import copy

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.artifact_schema_v4 import (
    artifact_hash,
    artifact_signing_typed_data,
    build_public_artifact,
    verify_public_artifact,
)
from solslot_puzzles.artifact_schema_v3 import (
    INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
)
from tests.test_genesis_ceremony import ADMIN_KEYS
from tests.test_genesis_ceremony_rc23 import (
    ceremony_plan,
    funding_coins,
)
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
        build_timestamp="2026-07-29T00:00:00+00:00",
        signatures=_signatures(*signed_slots),
        review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    )


def _accept(*_args: object) -> bool:
    return True


def test_v4_artifact_reconstructs_authority_v3_and_recovery_roster() -> None:
    value = _artifact()
    assert value["schemaVersion"] == 4
    assert value["protocolVersion"] == "solslot-v2-rc23"
    assert value["genesisPlan"]["schema"] == "solslot-genesis-plan-v4"
    assert value["adminAuthority"]["version"] == 3
    assert value["adminAuthority"]["policy"] == "owner-plus-one"
    assert len(value["adminAuthority"]["identityVaults"]) == 3
    assert value["adminRecoveryKits"] == (
        value["genesisPlan"]["adminRecoveryKits"]
    )
    assert value["puzzleHashes"]["adminAuthorityInnerMod"] == (
        value["genesisPlan"]["puzzleHashes"]["adminAuthorityInnerMod"]
    )
    assert value["bridgePolicy"]["fundingAmount"] == 530
    verify_public_artifact(value, signature_verifier=_accept)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    (
        (
            ("genesisPlan", "adminRecoveryKits", 0, "revision"),
            2,
            "reconstruct",
        ),
        (
            ("adminRecoveryKits", 1, "evmGuardian"),
            "0x" + "ff" * 20,
            "adminRecoveryKits",
        ),
        (
            ("adminAuthority", "identityVaults", 2, "launcherId"),
            "0x" + "fe" * 32,
            "adminAuthority",
        ),
        (
            ("puzzleHashes", "adminAuthorityInnerMod"),
            "0x" + "fd" * 32,
            "puzzleHashes",
        ),
        (
            (
                "genesisPlan",
                "recoveryDependencyManifestHash",
            ),
            "0x" + "fc" * 32,
            "reconstruct",
        ),
    ),
)
def test_v4_artifact_rejects_recovery_or_authority_tampering(
    path: tuple[object, ...],
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


def test_v4_signing_payload_and_owner_plus_one_policy() -> None:
    value = _artifact()
    typed = artifact_signing_typed_data(value)
    assert typed["domain"]["version"] == "4"
    assert typed["message"]["planHash"] == value["ceremony"]["planHash"]

    value["signatures"] = _signatures(1, 2)
    with pytest.raises(ValueError, match="slot 0"):
        verify_public_artifact(value, signature_verifier=_accept)
