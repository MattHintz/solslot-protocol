from __future__ import annotations

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_operation_v1 import (
    AdminOperationCoreV1,
    AdminOperationEnvelopeV1,
    AdminOperationSignatureV1,
)


def core() -> AdminOperationCoreV1:
    return AdminOperationCoreV1(
        authority_launcher_id=bytes32(b"\x11" * 32),
        network="testnet11",
        operation="mint.publish",
        payload_hash=bytes32(b"\x22" * 32),
        revision=7,
        nonce=bytes32(b"\x33" * 32),
        expires_at=1_800_000_000,
    )


def signature(index: int) -> AdminOperationSignatureV1:
    prefix = 2 if index != 1 else 3
    return AdminOperationSignatureV1(
        admin_index=index,
        compressed_pubkey=bytes([prefix]) + bytes([index + 1]) * 32,
        signature=bytes([index + 1]) * 65,
    )


def test_core_hash_and_typed_data_bind_every_authority_field() -> None:
    value = core()
    assert value.envelope_hash.hex() == "d361e49fbe369a8043dd36543090055613686366d375eb52a4606d0bb4069958"
    typed = value.eip712_typed_data(chain_id=11155111)
    assert typed["primaryType"] == "SolslotAdminOperation"
    assert typed["message"] == {
        "authorityLauncherId": "0x" + "11" * 32,
        "operation": "mint.publish",
        "payloadHash": "0x" + "22" * 32,
        "revision": 7,
        "nonce": "0x" + "33" * 32,
        "network": "testnet11",
        "expiresAt": 1_800_000_000,
    }


@pytest.mark.parametrize("indices", [(0, 1), (0, 2), (0, 1, 2)])
def test_envelope_accepts_owner_plus_coadmin(indices: tuple[int, ...]) -> None:
    envelope = AdminOperationEnvelopeV1.from_signatures(
        core(), [signature(index) for index in indices]
    )
    assert envelope.canonical_payload()["signatures"][0]["adminIndex"] == 0


@pytest.mark.parametrize("indices", [(1, 2), (0,), (1,), (2,)])
def test_envelope_rejects_authority_without_owner_plus_coadmin(
    indices: tuple[int, ...],
) -> None:
    with pytest.raises(ValueError, match="slot 0 and one coadministrator"):
        AdminOperationEnvelopeV1.from_signatures(
            core(), [signature(index) for index in indices]
        )


def test_envelope_rejects_duplicate_slot() -> None:
    with pytest.raises(ValueError, match="distinct"):
        AdminOperationEnvelopeV1.from_signatures(core(), [signature(0), signature(0)])


def test_core_rejects_ambiguous_or_unbounded_fields() -> None:
    with pytest.raises(ValueError, match="canonical lowercase"):
        AdminOperationCoreV1(
            authority_launcher_id=bytes32(b"\x11" * 32),
            network="testnet11",
            operation="MINT PUBLISH",
            payload_hash=bytes32(b"\x22" * 32),
            revision=0,
            nonce=bytes32(b"\x33" * 32),
            expires_at=1,
        )
