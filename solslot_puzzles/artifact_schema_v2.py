"""Signed public artifact bundle for a confirmed Solslot V2 genesis."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import property_registry_driver as property_registry
from solslot_puzzles.genesis_ceremony import (
    GENESIS_ADMIN_THRESHOLD,
    GENESIS_EVM_CHAIN_ID,
    GENESIS_NETWORK,
    GenesisCeremonyPlan,
    verify_genesis_ceremony_plan,
)
from solslot_puzzles.protocol_deployment import (
    PROTOCOL_VERSION,
    singleton_full_puzzle_hash,
    singleton_struct,
)


SCHEMA_VERSION = 2
REQUIRED_CHIA_CONFIRMATIONS = 3
ARTIFACT_SIGNATURE_TYPE = "SolslotGenesisArtifact"
INDEPENDENT_REVIEW_CLASS = "independent-release-review"
INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS = "internal-engineering-testnet"
REVIEW_CLASSES = frozenset(
    {
        INDEPENDENT_REVIEW_CLASS,
        INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    }
)
REQUIRED_SOURCE_REFS = (
    "protocol",
    "evm",
    "api",
    "legacyBackend",
    "customerWeb",
    "adminPortal",
)
REQUIRED_EVM_ADDRESSES = (
    "forwarder",
    "verifierAdapter",
    "attestationEmitter",
)
REQUIRED_LAUNCHER_IDS = (
    "pool",
    "did",
    "governance",
    "navRegistry",
    "protocolConfig",
    "adminAuthority",
    "vaultVersionRegistry",
    "propertyRegistry",
)

ArtifactSignatureVerifier = Callable[[Mapping[str, Any], int, bytes, bytes], bool]


def _hex_value(
    value: bytes | bytes32 | str,
    field: str,
    *,
    length: int,
    nonzero: bool = True,
) -> str:
    normalized = value.lower() if isinstance(value, str) else "0x" + bytes(value).hex()
    if not normalized.startswith("0x") or len(normalized) != 2 + (length * 2):
        raise ValueError(f"{field} must be a 0x-prefixed {length}-byte value")
    int(normalized[2:], 16)
    if nonzero and normalized == "0x" + "00" * length:
        raise ValueError(f"{field} must be nonzero")
    return normalized


def _hex32(value: bytes | bytes32 | str, field: str) -> str:
    return _hex_value(value, field, length=32)


def _fresh_puzzle_module(filename: str) -> Program:
    """Load a module for the current thread without using the global CLVM cache.

    Chia's Rust LazyNode is intentionally thread-affine. Public-artifact
    verification also runs from FastAPI worker threads, so using
    ``load_puzzle`` here would reuse a node created by another request or the
    main thread. The committed hex is the release artifact we want to verify;
    parsing it per check keeps this small derivation thread-safe.
    """
    hex_path = Path(__file__).with_name(f"{filename}.hex")
    try:
        return Program.from_bytes(bytes.fromhex(hex_path.read_text(encoding="ascii")))
    except (OSError, ValueError) as exc:
        raise ValueError(f"artifact verifier cannot load frozen {filename}") from exc


def _address(value: str, field: str) -> str:
    return _hex_value(value, field, length=20)


def _source_ref(value: str, field: str) -> str:
    normalized = value.lower()
    if len(normalized) != 40:
        raise ValueError(f"sourceShas.{field} must be a 40-character Git SHA")
    int(normalized, 16)
    return normalized


def _program(value: object, field: str) -> tuple[str, Program]:
    normalized = str(value).lower()
    if not normalized.startswith("0x") or len(normalized) <= 2:
        raise ValueError(f"{field} must be a nonempty 0x-prefixed CLVM program")
    try:
        raw = bytes.fromhex(normalized[2:])
        return normalized, Program.from_bytes(raw)
    except ValueError as exc:
        raise ValueError(f"{field} must be valid serialized CLVM") from exc


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


def build_public_artifact(
    *,
    plan: GenesisCeremonyPlan,
    spend_bundle_id: bytes32 | str,
    confirmed_block_index: int,
    build_timestamp: str | None = None,
    signatures: Sequence[Mapping[str, Any]] = (),
    review_class: str = INDEPENDENT_REVIEW_CLASS,
) -> dict[str, Any]:
    """Build the artifact signed by two members of the frozen admin roster."""
    verify_genesis_ceremony_plan(plan)
    if confirmed_block_index <= 0:
        raise ValueError("confirmedBlockIndex must be positive")

    timestamp = build_timestamp or datetime.now(timezone.utc).isoformat()
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("buildTimestamp must be ISO-8601") from exc
    if review_class not in REVIEW_CLASSES:
        raise ValueError("unsupported genesis review class")
    internal_test = review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS

    base = plan.base_protocol
    payload: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "network": plan.network,
        "evmChainId": plan.evm_chain_id,
        "reviewClass": review_class,
        "testOnly": internal_test,
        "auditStatus": "unaudited" if internal_test else "independently-reviewed",
        "buildTimestamp": timestamp,
        "ceremony": {
            "ceremonyId": _hex32(plan.ceremony_id, "ceremonyId"),
            "planHash": _hex32(plan.plan_hash, "planHash"),
            "spendBundleId": _hex32(spend_bundle_id, "spendBundleId"),
            "confirmedBlockIndex": confirmed_block_index,
            "requiredChiaConfirmations": REQUIRED_CHIA_CONFIRMATIONS,
        },
        "sourceShas": {
            key: _source_ref(plan.source_shas[key], key)
            for key in REQUIRED_SOURCE_REFS
        },
        "puzzleHashes": {
            "poolInnerModHash": _hex32(base.pool_inner_mod_hash, "poolInnerModHash"),
            "poolInnerPuzzleHash": _hex32(base.pool_inner_puzhash, "poolInnerPuzzleHash"),
            "poolFullPuzzleHash": _hex32(base.pool_full_puzhash, "poolFullPuzzleHash"),
            "poolTokenTailHash": _hex32(base.pool_token_tail_hash, "poolTokenTailHash"),
            "smartDeedInnerModHash": _hex32(
                base.smart_deed_inner_mod_hash, "smartDeedInnerModHash"
            ),
            "p2PoolModHash": _hex32(base.p2_pool_mod_hash, "p2PoolModHash"),
            "p2VaultModHash": _hex32(base.p2_vault_mod_hash, "p2VaultModHash"),
            "didInnerPuzzleHash": _hex32(base.did_inner_puzhash, "didInnerPuzzleHash"),
            "didFullPuzzleHash": _hex32(base.did_full_puzhash, "didFullPuzzleHash"),
            "protocolTreasuryPuzzleHash": _hex32(
                base.trusted_protocol_treasury_puzhash,
                "protocolTreasuryPuzzleHash",
            ),
            "governanceInnerPuzzleHash": _hex32(
                base.tracker_inner_puzhash, "governanceInnerPuzzleHash"
            ),
            "governanceFullPuzzleHash": _hex32(
                base.tracker_full_puzhash, "governanceFullPuzzleHash"
            ),
            "navRegistryInnerPuzzleHash": _hex32(
                plan.nav_registry.inner_puzzle_hash, "navRegistryInnerPuzzleHash"
            ),
            "navRegistryFullPuzzleHash": _hex32(
                plan.nav_registry.full_puzzle_hash, "navRegistryFullPuzzleHash"
            ),
            "protocolConfigInnerPuzzleHash": _hex32(
                plan.protocol_config.inner_puzzle_hash,
                "protocolConfigInnerPuzzleHash",
            ),
            "protocolConfigFullPuzzleHash": _hex32(
                plan.protocol_config.full_puzzle_hash,
                "protocolConfigFullPuzzleHash",
            ),
            "adminAuthorityInnerPuzzleHash": _hex32(
                plan.admin_authority.inner_puzzle_hash,
                "adminAuthorityInnerPuzzleHash",
            ),
            "adminAuthorityFullPuzzleHash": _hex32(
                plan.admin_authority.full_puzzle_hash,
                "adminAuthorityFullPuzzleHash",
            ),
            "vaultVersionRegistryInnerPuzzleHash": _hex32(
                plan.vault_version_registry.inner_puzzle_hash,
                "vaultVersionRegistryInnerPuzzleHash",
            ),
            "vaultVersionRegistryFullPuzzleHash": _hex32(
                plan.vault_version_registry.full_puzzle_hash,
                "vaultVersionRegistryFullPuzzleHash",
            ),
            "propertyRegistryInnerModHash": _hex32(
                property_registry.property_registry_inner_mod_hash(),
                "propertyRegistryInnerModHash",
            ),
            "propertyRegistryInnerPuzzleHash": _hex32(
                plan.property_registry.inner_puzzle_hash,
                "propertyRegistryInnerPuzzleHash",
            ),
            "propertyRegistryFullPuzzleHash": _hex32(
                plan.property_registry.full_puzzle_hash,
                "propertyRegistryFullPuzzleHash",
            ),
            "sgtTailHash": _hex32(base.sgt_tail_hash, "sgtTailHash"),
        },
        "launcherIds": {
            "pool": _hex32(base.pool_launcher_id, "poolLauncherId"),
            "did": _hex32(base.did_launcher_id, "didLauncherId"),
            "governance": _hex32(base.tracker_launcher_id, "governanceLauncherId"),
            "navRegistry": _hex32(
                plan.nav_registry.launcher_id, "navRegistryLauncherId"
            ),
            "protocolConfig": _hex32(
                plan.protocol_config.launcher_id, "protocolConfigLauncherId"
            ),
            "adminAuthority": _hex32(
                plan.admin_authority.launcher_id, "adminAuthorityLauncherId"
            ),
            "vaultVersionRegistry": _hex32(
                plan.vault_version_registry.launcher_id,
                "vaultVersionRegistryLauncherId",
            ),
            "propertyRegistry": _hex32(
                plan.property_registry.launcher_id,
                "propertyRegistryLauncherId",
            ),
        },
        "sgtGenesisCoinId": _hex32(base.sgt_genesis_coin_id, "sgtGenesisCoinId"),
        "sgtTailHash": _hex32(base.sgt_tail_hash, "sgtTailHash"),
        "governanceStruct": {
            "treeHash": _hex32(
                base.governance_singleton_struct_hash,
                "governanceSingletonStructHash",
            ),
            "launcherId": _hex32(base.tracker_launcher_id, "governanceLauncherId"),
            "serialized": "0x" + bytes(singleton_struct(base.tracker_launcher_id)).hex(),
            "mintExecuteCosignerPubkey": _hex_value(
                base.kos_mint_execute_pubkey,
                "governanceStruct.mintExecuteCosignerPubkey",
                length=48,
            ),
        },
        "protocolDid": {
            "launcherId": _hex32(base.did_launcher_id, "didLauncherId"),
            "singletonStruct": "0x" + bytes(singleton_struct(base.did_launcher_id)).hex(),
            "innerPuzzleHash": _hex32(base.did_inner_puzhash, "didInnerPuzzleHash"),
            "fullPuzzleHash": _hex32(base.did_full_puzhash, "didFullPuzzleHash"),
        },
        "propertyRegistry": {
            "launcherId": _hex32(
                plan.property_registry.launcher_id, "propertyRegistryLauncherId"
            ),
            "governanceBlsPubkey": _hex_value(
                base.trusted_nav_registry_gov_pubkey,
                "propertyRegistryGovernanceBlsPubkey",
                length=48,
            ),
            "currentPuzzleHash": _hex32(
                plan.property_registry.full_puzzle_hash,
                "propertyRegistryFullPuzzleHash",
            ),
        },
        "protocolParameters": {
            "smartDeedPuzzleVersion": base.smart_deed_puzzle_version,
            "poolPuzzleVersion": base.pool_puzzle_version,
            "sgtTotalSupply": base.params.sgt_total_supply,
            "quorumBps": base.params.quorum_bps,
            "votingWindowSeconds": base.params.voting_window_seconds,
            "minProposalStake": base.params.min_proposal_stake,
            "fpScale": base.params.fp_scale,
            "minNavRegistryVersion": base.params.min_nav_registry_version,
            "initialPoolStatus": base.params.initial_pool_status,
            "initialTotalPoolTokenSupply": base.params.initial_total_pool_token_supply,
            "initialTreasuryReserveTokens": base.params.initial_treasury_reserve_tokens,
        },
        "stateVersions": {
            "navRegistry": plan.nav_registry_version,
            "protocolConfig": plan.protocol_config_version,
            "adminAuthority": plan.admin_authority_version,
            "vault": plan.vault_version,
            "propertyRegistry": plan.property_registry_version,
        },
        "adminAuthority": {
            "threshold": plan.admin_quorum.threshold,
            "rosterHash": _hex32(plan.admin_quorum.admins_hash, "adminRosterHash"),
            "mipsRootHash": _hex32(
                plan.admin_quorum.mips_root_hash, "adminMipsRootHash"
            ),
            "compressedPubkeys": [
                _hex_value(pubkey, "adminCompressedPubkey", length=33)
                for pubkey in plan.admin_quorum.compressed_pubkeys
            ],
        },
        "validatorSet": {
            "threshold": plan.validator_threshold,
            "pubkeys": [
                _hex_value(pubkey, "validatorPubkey", length=48)
                for pubkey in plan.validator_pubkeys
            ],
        },
        "bridgePolicy": {
            "policyVersion": 2,
            "policyHash": _hex32(plan.bridge_batch.policy_hash, "bridgePolicyHash"),
            "initialCoinCount": len(plan.bridge_batch.bridge_coins),
            "lowWaterMark": plan.bridge_batch.low_water_mark,
            "parentCoinIds": [
                _hex32(coin.name(), "bridgeParentCoinId")
                for coin in plan.bridge_batch.parent_coins
            ],
            "bridgeCoinIds": [
                _hex32(coin.name(), "bridgeCoinId")
                for coin in plan.bridge_batch.bridge_coins
            ],
        },
        "canonicalVaultParamsHash": _hex32(
            plan.canonical_params_hash, "canonicalVaultParamsHash"
        ),
        "evmAddresses": {
            key: _address(plan.evm_addresses[key], key)
            for key in REQUIRED_EVM_ADDRESSES
        },
        "retiredCoordinates": [
            _hex32(value, "retiredCoordinate") for value in plan.retired_coordinates
        ],
        "signaturePolicy": {
            "type": ARTIFACT_SIGNATURE_TYPE,
            "threshold": GENESIS_ADMIN_THRESHOLD,
            "rosterHash": _hex32(plan.admin_quorum.admins_hash, "adminRosterHash"),
        },
        "signatures": [dict(signature) for signature in signatures],
    }
    payload["artifactHash"] = artifact_hash(payload)
    return payload


def artifact_signing_typed_data(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact EIP-712 object presented to each artifact signer."""
    _verify_artifact_content(payload)
    ceremony = payload["ceremony"]
    return {
        "domain": {
            "name": "Solslot Protocol",
            "version": "2",
            "chainId": payload["evmChainId"],
        },
        "primaryType": ARTIFACT_SIGNATURE_TYPE,
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            ARTIFACT_SIGNATURE_TYPE: [
                {"name": "artifactHash", "type": "bytes32"},
                {"name": "ceremonyId", "type": "bytes32"},
                {"name": "planHash", "type": "bytes32"},
                {"name": "network", "type": "string"},
            ],
        },
        "message": {
            "artifactHash": payload["artifactHash"],
            "ceremonyId": ceremony["ceremonyId"],
            "planHash": ceremony["planHash"],
            "network": payload["network"],
        },
    }


def _verify_artifact_content(payload: Mapping[str, Any]) -> None:
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported artifact schemaVersion")
    if payload.get("protocolVersion") != PROTOCOL_VERSION:
        raise ValueError("unsupported or retired protocolVersion")
    if payload.get("network") != GENESIS_NETWORK:
        raise ValueError("artifact network is not testnet11")
    if payload.get("evmChainId") != GENESIS_EVM_CHAIN_ID:
        raise ValueError("artifact EVM chain is not Sepolia")
    review_class = payload.get("reviewClass")
    if review_class not in REVIEW_CLASSES:
        raise ValueError("artifact reviewClass is unsupported")
    if review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS:
        if payload.get("testOnly") is not True or payload.get("auditStatus") != "unaudited":
            raise ValueError("internal engineering artifact must be test-only and unaudited")
    elif payload.get("testOnly") is not False or payload.get("auditStatus") != "independently-reviewed":
        raise ValueError("independently reviewed artifact metadata is invalid")
    if payload.get("artifactHash") != artifact_hash(payload):
        raise ValueError("artifactHash does not match canonical payload")

    sources = payload.get("sourceShas")
    if not isinstance(sources, Mapping) or set(sources) != set(REQUIRED_SOURCE_REFS):
        raise ValueError("artifact sourceShas are incomplete")
    for key in REQUIRED_SOURCE_REFS:
        _source_ref(str(sources[key]), key)

    launchers = payload.get("launcherIds")
    if not isinstance(launchers, Mapping) or set(launchers) != set(REQUIRED_LAUNCHER_IDS):
        raise ValueError("artifact launcherIds are incomplete")
    launcher_values = [_hex32(str(launchers[key]), key) for key in REQUIRED_LAUNCHER_IDS]
    if len(set(launcher_values)) != len(launcher_values):
        raise ValueError("artifact launcher IDs must be distinct")

    puzzles = payload.get("puzzleHashes")
    if not isinstance(puzzles, Mapping):
        raise ValueError("artifact puzzle hashes are missing")
    for key in (
        "didInnerPuzzleHash",
        "didFullPuzzleHash",
        "protocolTreasuryPuzzleHash",
        "governanceInnerPuzzleHash",
        "governanceFullPuzzleHash",
        "propertyRegistryFullPuzzleHash",
        "p2PoolModHash",
        "p2VaultModHash",
    ):
        _hex32(str(puzzles.get(key, "")), key)

    did = payload.get("protocolDid")
    if not isinstance(did, Mapping):
        raise ValueError("artifact protocol DID material is missing")
    if (
        did.get("launcherId") != launchers["did"]
        or did.get("innerPuzzleHash") != puzzles["didInnerPuzzleHash"]
        or did.get("fullPuzzleHash") != puzzles["didFullPuzzleHash"]
    ):
        raise ValueError("artifact protocol DID material is inconsistent")
    did_struct_hex, did_struct = _program(
        did.get("singletonStruct"), "protocolDid.singletonStruct"
    )
    expected_did_struct = singleton_struct(
        bytes32.fromhex(str(launchers["did"]).removeprefix("0x"))
    )
    if did_struct_hex != "0x" + bytes(expected_did_struct).hex() or did_struct != expected_did_struct:
        raise ValueError("artifact protocol DID singleton struct is invalid")

    governance = payload.get("governanceStruct")
    if not isinstance(governance, Mapping) or governance.get("launcherId") != launchers["governance"]:
        raise ValueError("artifact governance singleton material is missing")
    governance_hex, governance_program = _program(
        governance.get("serialized"), "governanceStruct.serialized"
    )
    expected_governance = singleton_struct(
        bytes32.fromhex(str(launchers["governance"]).removeprefix("0x"))
    )
    if (
        governance_hex != "0x" + bytes(expected_governance).hex()
        or governance_program != expected_governance
        or governance.get("treeHash")
        != _hex32(expected_governance.get_tree_hash(), "governanceStruct.treeHash")
    ):
        raise ValueError("artifact governance singleton struct is invalid")
    _hex_value(
        str(governance.get("mintExecuteCosignerPubkey", "")),
        "governanceStruct.mintExecuteCosignerPubkey",
        length=48,
    )
    params = payload.get("protocolParameters")
    if not isinstance(params, Mapping):
        raise ValueError("artifact protocol parameters are missing")
    try:
        cosigner_pubkey = bytes.fromhex(
            str(governance["mintExecuteCosignerPubkey"]).removeprefix("0x")
        )
        governance_module = _fresh_puzzle_module("governance_singleton_inner.clsp")
        expected_governance_inner = governance_module.curry(
            governance_module.get_tree_hash(),
            expected_governance,
            bytes32(_fresh_puzzle_module("sgt_free_inner.clsp").get_tree_hash()),
            bytes32(_fresh_puzzle_module("sgt_locked_inner.clsp").get_tree_hash()),
            CAT_MOD_HASH,
            bytes32.fromhex(str(puzzles["sgtTailHash"]).removeprefix("0x")),
            bytes32.fromhex(str(puzzles["didFullPuzzleHash"]).removeprefix("0x")),
            singleton_struct(
                bytes32.fromhex(str(launchers["pool"]).removeprefix("0x"))
            ),
            int(params["quorumBps"]),
            int(params["votingWindowSeconds"]),
            int(params["sgtTotalSupply"]),
            int(params["minProposalStake"]),
            cosigner_pubkey,
            0,
            0,
            0,
            0,
        ).get_tree_hash()
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("artifact governance co-signer binding is malformed") from exc
    expected_governance_full = singleton_full_puzzle_hash(
        bytes32.fromhex(str(launchers["governance"]).removeprefix("0x")),
        bytes32(expected_governance_inner),
    )
    if (
        puzzles.get("governanceInnerPuzzleHash")
        != _hex32(expected_governance_inner, "governanceInnerPuzzleHash")
        or puzzles.get("governanceFullPuzzleHash")
        != _hex32(expected_governance_full, "governanceFullPuzzleHash")
    ):
        raise ValueError(
            "artifact MINT co-signer public key is not bound to governance puzzle hashes"
        )

    registry = payload.get("propertyRegistry")
    if not isinstance(registry, Mapping):
        raise ValueError("artifact property registry material is missing")
    if (
        registry.get("launcherId") != launchers["propertyRegistry"]
        or registry.get("currentPuzzleHash") != puzzles["propertyRegistryFullPuzzleHash"]
    ):
        raise ValueError("artifact property registry material is inconsistent")
    _hex_value(
        str(registry.get("governanceBlsPubkey", "")),
        "propertyRegistry.governanceBlsPubkey",
        length=48,
    )

    retired = payload.get("retiredCoordinates")
    if not isinstance(retired, list) or not retired:
        raise ValueError("artifact must enumerate retired coordinates")
    retired_values = [_hex32(str(value), "retiredCoordinate") for value in retired]
    if len(set(retired_values)) != len(retired_values):
        raise ValueError("retired coordinates must be distinct")
    if set(retired_values) & set(launcher_values):
        raise ValueError("active launcher appears in retired coordinates")

    ceremony = payload.get("ceremony")
    if not isinstance(ceremony, Mapping):
        raise ValueError("artifact ceremony metadata is missing")
    for key in ("ceremonyId", "planHash", "spendBundleId"):
        _hex32(str(ceremony.get(key, "")), key)
    if int(ceremony.get("confirmedBlockIndex", 0)) <= 0:
        raise ValueError("artifact ceremony is not confirmed")
    if ceremony.get("requiredChiaConfirmations") != REQUIRED_CHIA_CONFIRMATIONS:
        raise ValueError("artifact Chia confirmation policy is invalid")

    admin = payload.get("adminAuthority")
    policy = payload.get("signaturePolicy")
    if not isinstance(admin, Mapping) or not isinstance(policy, Mapping):
        raise ValueError("artifact admin signature policy is missing")
    if admin.get("threshold") != GENESIS_ADMIN_THRESHOLD:
        raise ValueError("artifact admin authority is not 2-of-3")
    pubkeys = admin.get("compressedPubkeys")
    if not isinstance(pubkeys, list) or len(pubkeys) != 3:
        raise ValueError("artifact must contain three administrator keys")
    normalized_admin_keys = [
        _hex_value(str(value), "adminCompressedPubkey", length=33)
        for value in pubkeys
    ]
    if len(set(normalized_admin_keys)) != 3:
        raise ValueError("artifact administrator keys must be distinct")
    if (
        policy.get("type") != ARTIFACT_SIGNATURE_TYPE
        or policy.get("threshold") != GENESIS_ADMIN_THRESHOLD
        or policy.get("rosterHash") != admin.get("rosterHash")
    ):
        raise ValueError("artifact signature policy does not match the roster")

    validators = payload.get("validatorSet")
    if not isinstance(validators, Mapping) or validators.get("threshold") != 2:
        raise ValueError("artifact validator set is not 2-of-3")
    validator_keys = validators.get("pubkeys")
    if not isinstance(validator_keys, list) or len(validator_keys) != 3:
        raise ValueError("artifact must contain three validator keys")
    normalized_validator_keys = [
        _hex_value(str(value), "validatorPubkey", length=48)
        for value in validator_keys
    ]
    if len(set(normalized_validator_keys)) != 3:
        raise ValueError("artifact validator keys must be distinct")

    bridge = payload.get("bridgePolicy")
    if not isinstance(bridge, Mapping):
        raise ValueError("artifact bridge policy is missing")
    if bridge.get("policyVersion") != 2 or bridge.get("initialCoinCount") != 32:
        raise ValueError("artifact bridge policy is not the V2 32-coin policy")
    if bridge.get("lowWaterMark") != 8:
        raise ValueError("artifact bridge low-water mark is invalid")
    _hex32(str(bridge.get("policyHash", "")), "bridgePolicyHash")

    addresses = payload.get("evmAddresses")
    if not isinstance(addresses, Mapping) or set(addresses) != set(REQUIRED_EVM_ADDRESSES):
        raise ValueError("artifact EVM addresses are incomplete")
    normalized_addresses = [
        _address(str(addresses[key]), key) for key in REQUIRED_EVM_ADDRESSES
    ]
    if len(set(normalized_addresses)) != len(normalized_addresses):
        raise ValueError("artifact EVM addresses must be distinct")


def verify_public_artifact(
    payload: Mapping[str, Any],
    *,
    signature_verifier: ArtifactSignatureVerifier | None = None,
) -> None:
    """Fail closed unless two roster-bound artifact signatures are valid."""
    _verify_artifact_content(payload)
    if signature_verifier is None:
        raise ValueError("artifact signature verifier is required")

    signatures = payload.get("signatures")
    if not isinstance(signatures, list) or not (2 <= len(signatures) <= 3):
        raise ValueError("artifact requires two administrator signatures")
    admin_keys = payload["adminAuthority"]["compressedPubkeys"]
    seen: set[int] = set()
    for entry in signatures:
        if not isinstance(entry, Mapping):
            raise ValueError("artifact signature entry is malformed")
        index = int(entry.get("adminIndex", -1))
        if index not in (0, 1, 2) or index in seen:
            raise ValueError("artifact signatures must use distinct roster slots")
        seen.add(index)
        pubkey_hex = _hex_value(
            str(entry.get("compressedPubkey", "")),
            "signature.compressedPubkey",
            length=33,
        )
        if pubkey_hex != admin_keys[index]:
            raise ValueError("artifact signature key does not match roster slot")
        signature_hex = _hex_value(
            str(entry.get("signature", "")),
            "signature.signature",
            length=65,
        )
        if not signature_verifier(
            payload,
            index,
            bytes.fromhex(pubkey_hex[2:]),
            bytes.fromhex(signature_hex[2:]),
        ):
            raise ValueError("artifact administrator signature is invalid")


__all__ = [
    "SCHEMA_VERSION",
    "REQUIRED_CHIA_CONFIRMATIONS",
    "ARTIFACT_SIGNATURE_TYPE",
    "INDEPENDENT_REVIEW_CLASS",
    "INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS",
    "REVIEW_CLASSES",
    "ArtifactSignatureVerifier",
    "canonical_json",
    "artifact_hash",
    "artifact_signing_typed_data",
    "build_public_artifact",
    "verify_public_artifact",
]
