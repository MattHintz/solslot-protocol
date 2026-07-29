"""EIP-712 envelopes for the Solslot genesis ceremony."""

from __future__ import annotations

from typing import Any, Mapping

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.genesis_constants import GENESIS_EVM_CHAIN_ID, GENESIS_NETWORK


EIP712_DOMAIN_NAME = "Solslot Protocol"
EIP712_DOMAIN_VERSION = "2"
ADMIN_ENROLLMENT_TYPE = "SolslotGenesisAdminEnrollment"
GENESIS_PLAN_SIGNATURE_TYPE = "SolslotGenesisPlan"
GENESIS_ARTIFACT_SIGNATURE_TYPE = "SolslotGenesisArtifact"

_DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
]


def _hex32(value: bytes | bytes32 | str, field: str) -> str:
    normalized = value.lower() if isinstance(value, str) else "0x" + bytes(value).hex()
    if not normalized.startswith("0x") or len(normalized) != 66:
        raise ValueError(f"{field} must be a 0x-prefixed bytes32")
    int(normalized[2:], 16)
    if normalized == "0x" + "00" * 32:
        raise ValueError(f"{field} must be nonzero")
    return normalized


def _address(value: str, field: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x") or len(normalized) != 42:
        raise ValueError(f"{field} must be a 0x-prefixed 20-byte address")
    int(normalized[2:], 16)
    if normalized == "0x" + "00" * 20:
        raise ValueError(f"{field} must be nonzero")
    return normalized


def _domain(
    chain_id: int,
    *,
    version: str = EIP712_DOMAIN_VERSION,
) -> dict[str, Any]:
    if chain_id != GENESIS_EVM_CHAIN_ID:
        raise ValueError("genesis administrator signatures are restricted to Sepolia")
    return {
        "name": EIP712_DOMAIN_NAME,
        "version": version,
        "chainId": chain_id,
    }


def genesis_admin_enrollment_typed_data(
    *,
    ceremony_id: bytes32 | str,
    slot: int,
    wallet: str,
    nonce: bytes32 | str,
    expires_at: int,
    network: str = GENESIS_NETWORK,
    chain_id: int = GENESIS_EVM_CHAIN_ID,
) -> dict[str, Any]:
    """Bind one administrator wallet to one numbered, expiring roster slot."""
    if slot not in (1, 2, 3):
        raise ValueError("administrator slot must be 1, 2, or 3")
    if network != GENESIS_NETWORK:
        raise ValueError("genesis administrator enrollment is restricted to testnet11")
    if expires_at <= 0:
        raise ValueError("expires_at must be positive")
    return {
        "domain": _domain(chain_id),
        "primaryType": ADMIN_ENROLLMENT_TYPE,
        "types": {
            "EIP712Domain": _DOMAIN_FIELDS,
            ADMIN_ENROLLMENT_TYPE: [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "slot", "type": "uint8"},
                {"name": "wallet", "type": "address"},
                {"name": "nonce", "type": "bytes32"},
                {"name": "expiresAt", "type": "uint64"},
                {"name": "network", "type": "string"},
            ],
        },
        "message": {
            "ceremonyId": _hex32(ceremony_id, "ceremony_id"),
            "slot": slot,
            "wallet": _address(wallet, "wallet"),
            "nonce": _hex32(nonce, "nonce"),
            "expiresAt": expires_at,
            "network": network,
        },
    }


def genesis_plan_signing_typed_data(
    *,
    ceremony_id: bytes32 | str,
    roster_hash: bytes32 | str,
    plan_hash: bytes32 | str,
    expires_at: int,
    network: str = GENESIS_NETWORK,
    chain_id: int = GENESIS_EVM_CHAIN_ID,
) -> dict[str, Any]:
    """Bind administrator approval to one immutable deterministic plan."""
    if network != GENESIS_NETWORK:
        raise ValueError("genesis plan signatures are restricted to testnet11")
    if expires_at <= 0:
        raise ValueError("expires_at must be positive")
    return {
        "domain": _domain(chain_id),
        "primaryType": GENESIS_PLAN_SIGNATURE_TYPE,
        "types": {
            "EIP712Domain": _DOMAIN_FIELDS,
            GENESIS_PLAN_SIGNATURE_TYPE: [
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "rosterHash", "type": "bytes32"},
                {"name": "planHash", "type": "bytes32"},
                {"name": "network", "type": "string"},
                {"name": "expiresAt", "type": "uint64"},
            ],
        },
        "message": {
            "ceremonyId": _hex32(ceremony_id, "ceremony_id"),
            "rosterHash": _hex32(roster_hash, "roster_hash"),
            "planHash": _hex32(plan_hash, "plan_hash"),
            "network": network,
            "expiresAt": expires_at,
        },
    }


def genesis_artifact_signing_typed_data(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind an administrator signature to one canonical public artifact.

    This helper intentionally validates only the fields needed by EIP-712. Full
    artifact validation runs in the isolated ceremony worker so FastAPI request
    threads never import CLVM modules with thread-affine Rust objects.
    """
    schema_version = payload.get("schemaVersion")
    protocol_version = payload.get("protocolVersion")
    supported = {
        3: ("solslot-v2-rc22", "3"),
        4: ("solslot-v2-rc23", "4"),
    }
    if schema_version not in supported:
        raise ValueError("unsupported artifact schemaVersion")
    expected_protocol, domain_version = supported[int(schema_version)]
    if protocol_version != expected_protocol:
        raise ValueError("unsupported artifact protocolVersion")
    if payload.get("network") != GENESIS_NETWORK:
        raise ValueError("genesis artifact is restricted to testnet11")
    if payload.get("evmChainId") != GENESIS_EVM_CHAIN_ID:
        raise ValueError("genesis artifact is restricted to Sepolia")
    ceremony = payload.get("ceremony")
    if not isinstance(ceremony, Mapping):
        raise ValueError("artifact ceremony metadata is missing")
    return {
        "domain": _domain(
            int(payload["evmChainId"]),
            version=domain_version,
        ),
        "primaryType": GENESIS_ARTIFACT_SIGNATURE_TYPE,
        "types": {
            "EIP712Domain": _DOMAIN_FIELDS,
            GENESIS_ARTIFACT_SIGNATURE_TYPE: [
                {"name": "artifactHash", "type": "bytes32"},
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "planHash", "type": "bytes32"},
                {"name": "network", "type": "string"},
            ],
        },
        "message": {
            "artifactHash": _hex32(str(payload.get("artifactHash", "")), "artifactHash"),
            "ceremonyId": _hex32(
                str(ceremony.get("ceremonyId", "")), "ceremonyId"
            ),
            "planHash": _hex32(str(ceremony.get("planHash", "")), "planHash"),
            "network": str(payload["network"]),
        },
    }


__all__ = [
    "EIP712_DOMAIN_NAME",
    "EIP712_DOMAIN_VERSION",
    "ADMIN_ENROLLMENT_TYPE",
    "GENESIS_PLAN_SIGNATURE_TYPE",
    "GENESIS_ARTIFACT_SIGNATURE_TYPE",
    "genesis_admin_enrollment_typed_data",
    "genesis_artifact_signing_typed_data",
    "genesis_plan_signing_typed_data",
]
