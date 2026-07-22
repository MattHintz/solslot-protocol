from __future__ import annotations

import copy

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.artifact_schema_v2 import (
    INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    artifact_hash,
    artifact_signing_typed_data,
    build_public_artifact,
    verify_public_artifact,
)
from tests.test_genesis_ceremony import ADMIN_KEYS, ceremony_plan, funding_coins
from tests.test_protocol_deployment import _FakeFaucet


def signatures(*slots: int) -> list[dict[str, object]]:
    return [
        {
            "adminIndex": slot,
            "compressedPubkey": "0x" + ADMIN_KEYS[slot].hex(),
            "signature": "0x" + (bytes([slot + 1]) * 65).hex(),
        }
        for slot in slots
    ]


def artifact(*, signed_slots: tuple[int, ...] = (0, 2)) -> dict:
    faucet = _FakeFaucet()
    plan = ceremony_plan(faucet, funding_coins(faucet))
    return build_public_artifact(
        plan=plan,
        spend_bundle_id=bytes32(b"\x81" * 32),
        confirmed_block_index=1234,
        build_timestamp="2026-07-14T00:00:00+00:00",
        signatures=signatures(*signed_slots),
    )


def internal_test_artifact() -> dict:
    faucet = _FakeFaucet()
    plan = ceremony_plan(faucet, funding_coins(faucet))
    return build_public_artifact(
        plan=plan,
        spend_bundle_id=bytes32(b"\x82" * 32),
        confirmed_block_index=1234,
        build_timestamp="2026-07-14T00:00:00+00:00",
        signatures=signatures(0, 2),
        review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    )


def accept_test_signature(
    _payload: dict, _index: int, _pubkey: bytes, _signature: bytes
) -> bool:
    return True


def test_artifact_has_complete_signed_v2_surface() -> None:
    value = artifact()
    assert value["schemaVersion"] == 2
    assert value["sourceManifestVersion"] == 3
    assert set(value["sourceShas"]) == {
        "protocol",
        "evm",
        "omnichain",
        "api",
        "legacyBackend",
        "keyOfSolomon",
        "samuel",
        "customerWeb",
        "adminPortal",
    }
    assert value["protocolVersion"] == "solslot-v2"
    assert value["network"] == "testnet11"
    assert value["evmChainId"] == 11155111
    assert value["reviewClass"] == "independent-release-review"
    assert value["testOnly"] is False
    assert value["auditStatus"] == "independently-reviewed"
    assert value["sgtGenesisCoinId"].startswith("0x")
    assert value["sgtTailHash"] == value["puzzleHashes"]["sgtTailHash"]
    assert value["adminAuthority"]["threshold"] == 2
    assert len(value["validatorSet"]["pubkeys"]) == 3
    assert len(value["bridgePolicy"]["bridgeCoinIds"]) == 32
    verify_public_artifact(value, signature_verifier=accept_test_signature)


def test_internal_engineering_artifact_is_explicitly_test_only_and_unaudited() -> None:
    value = internal_test_artifact()
    assert value["reviewClass"] == "internal-engineering-testnet"
    assert value["testOnly"] is True
    assert value["auditStatus"] == "unaudited"
    verify_public_artifact(value, signature_verifier=accept_test_signature)

    value["testOnly"] = False
    value["artifactHash"] = artifact_hash(value)
    with pytest.raises(ValueError, match="test-only"):
        verify_public_artifact(value, signature_verifier=accept_test_signature)


def test_artifact_hash_is_canonical_and_tamper_evident() -> None:
    value = artifact()
    assert value["artifactHash"] == artifact_hash(value)
    tampered = copy.deepcopy(value)
    tampered["network"] = "mainnet"
    with pytest.raises(ValueError, match="network|artifactHash"):
        verify_public_artifact(tampered, signature_verifier=accept_test_signature)


def test_artifact_rejects_retired_six_repository_source_manifest() -> None:
    value = artifact()
    for name in ("omnichain", "keyOfSolomon", "samuel"):
        del value["sourceShas"][name]
    value["artifactHash"] = artifact_hash(value)
    with pytest.raises(ValueError, match="sourceShas are incomplete"):
        verify_public_artifact(value, signature_verifier=accept_test_signature)


def test_artifact_rejects_empty_mint_execute_cosigner() -> None:
    value = artifact()
    value["governanceStruct"]["mintExecuteCosignerPubkey"] = "0x" + ("00" * 48)
    value["artifactHash"] = artifact_hash(value)
    with pytest.raises(ValueError, match="mintExecuteCosignerPubkey.*nonzero"):
        verify_public_artifact(value, signature_verifier=accept_test_signature)


def test_artifact_rejects_cosigner_not_bound_to_governance_puzzle() -> None:
    value = artifact()
    replacement = AugSchemeMPL.key_gen(
        b"other artifact mint execute key seed".ljust(32, b"0")
    ).get_g1()
    value["governanceStruct"]["mintExecuteCosignerPubkey"] = "0x" + bytes(replacement).hex()
    value["artifactHash"] = artifact_hash(value)
    with pytest.raises(ValueError, match="not bound to governance puzzle hashes"):
        verify_public_artifact(value, signature_verifier=accept_test_signature)


def test_artifact_requires_two_distinct_roster_signatures() -> None:
    unsigned = artifact(signed_slots=())
    with pytest.raises(ValueError, match="two administrator signatures"):
        verify_public_artifact(unsigned, signature_verifier=accept_test_signature)

    one = artifact(signed_slots=(1,))
    with pytest.raises(ValueError, match="two administrator signatures"):
        verify_public_artifact(one, signature_verifier=accept_test_signature)

    duplicate = artifact(signed_slots=(1, 1))
    with pytest.raises(ValueError, match="distinct roster slots"):
        verify_public_artifact(duplicate, signature_verifier=accept_test_signature)


def test_artifact_rejects_wrong_roster_key_and_invalid_signature() -> None:
    wrong_key = artifact()
    wrong_key["signatures"][0]["compressedPubkey"] = "0x02" + "44" * 32
    with pytest.raises(ValueError, match="does not match roster"):
        verify_public_artifact(wrong_key, signature_verifier=accept_test_signature)

    with pytest.raises(ValueError, match="invalid"):
        verify_public_artifact(artifact(), signature_verifier=lambda *_args: False)


def test_artifact_signing_payload_binds_ceremony_and_plan() -> None:
    value = artifact()
    typed_data = artifact_signing_typed_data(value)
    assert typed_data["domain"] == {
        "name": "Solslot Protocol",
        "version": "2",
        "chainId": 11155111,
    }
    assert typed_data["primaryType"] == "SolslotGenesisArtifact"
    assert typed_data["message"]["artifactHash"] == value["artifactHash"]
    assert typed_data["message"]["ceremonyId"] == value["ceremony"]["ceremonyId"]
    assert typed_data["message"]["planHash"] == value["ceremony"]["planHash"]


def test_signature_verifier_is_mandatory() -> None:
    with pytest.raises(ValueError, match="signature verifier"):
        verify_public_artifact(artifact())
