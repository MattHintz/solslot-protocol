"""Canonical public artifact bundle for a Solslot V2 deployment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_deployment import PROTOCOL_VERSION, ProtocolDeploymentPlan


SCHEMA_VERSION = 2
REQUIRED_SOURCE_REFS = (
    "protocol",
    "evm",
    "api",
    "customerWeb",
    "adminPortal",
)
REQUIRED_EVM_ADDRESSES = (
    "forwarder",
    "verifierAdapter",
    "attestationEmitter",
)


def _hex32(value: bytes | bytes32 | str, field: str) -> str:
    if isinstance(value, str):
        normalized = value.lower()
    else:
        normalized = "0x" + bytes(value).hex()
    if not normalized.startswith("0x") or len(normalized) != 66:
        raise ValueError(f"{field} must be a 0x-prefixed 32-byte value")
    int(normalized[2:], 16)
    if normalized == "0x" + "00" * 32:
        raise ValueError(f"{field} must be nonzero")
    return normalized


def _address(value: str, field: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x") or len(normalized) != 42:
        raise ValueError(f"{field} must be a 0x-prefixed EVM address")
    int(normalized[2:], 16)
    if normalized == "0x" + "00" * 20:
        raise ValueError(f"{field} must be nonzero")
    return normalized


def _source_ref(value: str, field: str) -> str:
    normalized = value.lower()
    if len(normalized) != 40:
        raise ValueError(f"sourceShas.{field} must be a 40-character Git SHA")
    int(normalized, 16)
    return normalized


def canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def artifact_hash(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value
        for key, value in payload.items()
        if key not in {"artifactHash", "signatures"}
    }
    return "0x" + hashlib.sha256(canonical_json(unsigned)).hexdigest()


@dataclass(frozen=True)
class CeremonyCoordinates:
    nav_registry_launcher_id: bytes32
    protocol_config_launcher_id: bytes32
    admin_authority_launcher_id: bytes32
    vault_version_registry_launcher_id: bytes32
    bridge_policy_hash: bytes32


def build_public_artifact(
    *,
    plan: ProtocolDeploymentPlan,
    ceremony: CeremonyCoordinates,
    source_shas: Mapping[str, str],
    evm_chain_id: int,
    evm_addresses: Mapping[str, str],
    retired_coordinates: Sequence[str],
    build_timestamp: str | None = None,
    signatures: Sequence[Mapping[str, str]] = (),
) -> dict[str, Any]:
    if plan.protocol_version != PROTOCOL_VERSION:
        raise ValueError("deployment plan is not Solslot V2")
    if evm_chain_id <= 0:
        raise ValueError("evmChainId must be positive")
    missing_sources = set(REQUIRED_SOURCE_REFS) - set(source_shas)
    if missing_sources:
        raise ValueError(f"sourceShas missing fields: {sorted(missing_sources)}")
    missing_addresses = set(REQUIRED_EVM_ADDRESSES) - set(evm_addresses)
    if missing_addresses:
        raise ValueError(f"evmAddresses missing fields: {sorted(missing_addresses)}")

    timestamp = build_timestamp or datetime.now(timezone.utc).isoformat()
    payload: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "network": plan.network,
        "buildTimestamp": timestamp,
        "sourceShas": {
            key: _source_ref(source_shas[key], key) for key in REQUIRED_SOURCE_REFS
        },
        "puzzleHashes": {
            "poolInnerModHash": _hex32(plan.pool_inner_mod_hash, "poolInnerModHash"),
            "poolInnerPuzzleHash": _hex32(plan.pool_inner_puzhash, "poolInnerPuzzleHash"),
            "poolFullPuzzleHash": _hex32(plan.pool_full_puzhash, "poolFullPuzzleHash"),
            "poolTokenTailHash": _hex32(plan.pool_token_tail_hash, "poolTokenTailHash"),
            "smartDeedInnerModHash": _hex32(
                plan.smart_deed_inner_mod_hash, "smartDeedInnerModHash"
            ),
            "p2PoolModHash": _hex32(plan.p2_pool_mod_hash, "p2PoolModHash"),
            "sgtTailHash": _hex32(plan.sgt_tail_hash, "sgtTailHash"),
        },
        "launcherIds": {
            "pool": _hex32(plan.pool_launcher_id, "poolLauncherId"),
            "did": _hex32(plan.did_launcher_id, "didLauncherId"),
            "governance": _hex32(plan.tracker_launcher_id, "governanceLauncherId"),
            "navRegistry": _hex32(
                ceremony.nav_registry_launcher_id, "navRegistryLauncherId"
            ),
            "protocolConfig": _hex32(
                ceremony.protocol_config_launcher_id, "protocolConfigLauncherId"
            ),
            "adminAuthority": _hex32(
                ceremony.admin_authority_launcher_id, "adminAuthorityLauncherId"
            ),
            "vaultVersionRegistry": _hex32(
                ceremony.vault_version_registry_launcher_id,
                "vaultVersionRegistryLauncherId",
            ),
        },
        "sgtGenesisCoinId": _hex32(plan.sgt_genesis_coin_id, "sgtGenesisCoinId"),
        "sgtTailHash": _hex32(plan.sgt_tail_hash, "sgtTailHash"),
        "governanceStruct": {
            "treeHash": _hex32(
                plan.governance_singleton_struct_hash,
                "governanceSingletonStructHash",
            ),
            "launcherId": _hex32(
                plan.tracker_launcher_id, "governanceLauncherId"
            ),
        },
        "bridgePolicy": {
            "policyVersion": 2,
            "policyHash": _hex32(ceremony.bridge_policy_hash, "bridgePolicyHash"),
        },
        "evmChainId": evm_chain_id,
        "evmAddresses": {
            key: _address(evm_addresses[key], key) for key in REQUIRED_EVM_ADDRESSES
        },
        "retiredCoordinates": [
            _hex32(value, "retiredCoordinates") for value in retired_coordinates
        ],
        "signatures": [dict(signature) for signature in signatures],
    }
    payload["artifactHash"] = artifact_hash(payload)
    return payload


def verify_public_artifact(payload: Mapping[str, Any]) -> None:
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported artifact schemaVersion")
    if payload.get("protocolVersion") != PROTOCOL_VERSION:
        raise ValueError("unsupported or retired protocolVersion")
    if payload.get("artifactHash") != artifact_hash(payload):
        raise ValueError("artifactHash does not match canonical payload")
