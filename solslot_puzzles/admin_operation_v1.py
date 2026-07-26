"""Canonical owner-plus-one authorization envelope for admin operations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from chia_rs.sized_bytes import bytes32


SCHEMA_VERSION = 1
PRIMARY_TYPE = "SolslotAdminOperation"
OWNER_INDEX = 0
COADMIN_INDICES = (1, 2)
_OPERATION_RE = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Encode the JSON-only envelope surface deterministically."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


@dataclass(frozen=True)
class AdminOperationCoreV1:
    authority_launcher_id: bytes32
    network: str
    operation: str
    payload_hash: bytes32
    revision: int
    nonce: bytes32
    expires_at: int

    def __post_init__(self) -> None:
        if self.authority_launcher_id == bytes32.zeros:
            raise ValueError("authority_launcher_id must be nonzero")
        if self.network not in {"testnet11", "mainnet"}:
            raise ValueError("network must be testnet11 or mainnet")
        if not _OPERATION_RE.fullmatch(self.operation):
            raise ValueError("operation must be a canonical lowercase identifier")
        if self.payload_hash == bytes32.zeros:
            raise ValueError("payload_hash must be nonzero")
        if self.revision < 0:
            raise ValueError("revision must be nonnegative")
        if self.nonce == bytes32.zeros:
            raise ValueError("nonce must be nonzero")
        if self.expires_at <= 0:
            raise ValueError("expires_at must be positive")

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "authorityLauncherId": _hex32(self.authority_launcher_id),
            "network": self.network,
            "operation": self.operation,
            "payloadHash": _hex32(self.payload_hash),
            "revision": self.revision,
            "nonce": _hex32(self.nonce),
            "expiresAt": self.expires_at,
        }

    @property
    def envelope_hash(self) -> bytes32:
        return bytes32(hashlib.sha256(canonical_json(self.canonical_payload())).digest())

    def eip712_typed_data(self, *, chain_id: int) -> dict[str, Any]:
        if chain_id <= 0:
            raise ValueError("chain_id must be positive")
        payload = self.canonical_payload()
        return {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                ],
                PRIMARY_TYPE: [
                    {"name": "authorityLauncherId", "type": "bytes32"},
                    {"name": "operation", "type": "string"},
                    {"name": "payloadHash", "type": "bytes32"},
                    {"name": "revision", "type": "uint256"},
                    {"name": "nonce", "type": "bytes32"},
                    {"name": "network", "type": "string"},
                    {"name": "expiresAt", "type": "uint256"},
                ],
            },
            "primaryType": PRIMARY_TYPE,
            "domain": {
                "name": "Solslot Protocol",
                "version": "2",
                "chainId": chain_id,
            },
            "message": {
                "authorityLauncherId": payload["authorityLauncherId"],
                "operation": payload["operation"],
                "payloadHash": payload["payloadHash"],
                "revision": payload["revision"],
                "nonce": payload["nonce"],
                "network": payload["network"],
                "expiresAt": payload["expiresAt"],
            },
        }


@dataclass(frozen=True)
class AdminOperationSignatureV1:
    admin_index: int
    compressed_pubkey: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if self.admin_index not in (OWNER_INDEX, *COADMIN_INDICES):
            raise ValueError("admin_index must identify one of the three slots")
        if len(self.compressed_pubkey) != 33:
            raise ValueError("compressed_pubkey must be 33 bytes")
        if len(self.signature) != 65:
            raise ValueError("signature must be 65 bytes")

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "adminIndex": self.admin_index,
            "compressedPubkey": "0x" + self.compressed_pubkey.hex(),
            "signature": "0x" + self.signature.hex(),
        }


@dataclass(frozen=True)
class AdminOperationEnvelopeV1:
    core: AdminOperationCoreV1
    signatures: tuple[AdminOperationSignatureV1, ...]

    @classmethod
    def from_signatures(
        cls,
        core: AdminOperationCoreV1,
        signatures: Sequence[AdminOperationSignatureV1],
    ) -> "AdminOperationEnvelopeV1":
        return cls(core=core, signatures=tuple(signatures))

    def __post_init__(self) -> None:
        indices = [signature.admin_index for signature in self.signatures]
        if len(indices) != len(set(indices)):
            raise ValueError("admin operation signatures must use distinct slots")
        if OWNER_INDEX not in indices or not set(indices).intersection(COADMIN_INDICES):
            raise ValueError("admin operation requires slot 0 and one coadministrator")

    def canonical_payload(self) -> dict[str, Any]:
        return {
            **self.core.canonical_payload(),
            "envelopeHash": _hex32(self.core.envelope_hash),
            "signatures": [
                signature.canonical_payload()
                for signature in sorted(self.signatures, key=lambda item: item.admin_index)
            ],
        }


__all__ = [
    "SCHEMA_VERSION",
    "PRIMARY_TYPE",
    "OWNER_INDEX",
    "COADMIN_INDICES",
    "AdminOperationCoreV1",
    "AdminOperationSignatureV1",
    "AdminOperationEnvelopeV1",
    "canonical_json",
]
