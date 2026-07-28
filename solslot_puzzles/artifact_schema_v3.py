"""Signed public artifact for the confirmed Solslot RC22 genesis."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.genesis_ceremony_rc22 import (
    GENESIS_ADMIN_COADMIN_INDICES,
    GENESIS_ADMIN_COADMIN_THRESHOLD,
    GENESIS_ADMIN_OWNER_INDEX,
    GENESIS_ADMIN_POLICY,
    GENESIS_ADMIN_THRESHOLD,
    GENESIS_EVM_CHAIN_ID,
    GENESIS_NETWORK,
    RC22_BRIDGE_BATCH_FUNDING_AMOUNT,
    RC22_BRIDGE_PARENT_TOTAL,
    RC22_GENESIS_PLAN_SCHEMA,
    RC22_PROPERTY_REGISTRY_LAUNCHER_AMOUNT,
    SOURCE_MANIFEST_VERSION,
    RC22GenesisCeremonyPlan,
    RC22GenesisFundingCoinIds,
    build_rc22_genesis_ceremony_plan,
    verify_rc22_genesis_ceremony_plan,
)
from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.protocol_deployment_rc22 import RC22_PROTOCOL_VERSION
from solslot_puzzles.protocol_statutes_v1 import (
    MAX_EXCHANGE_FEE_BPS,
    UPGRADE_DELAY_SECONDS,
    ProtocolParameters,
)


SCHEMA_VERSION = 3
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
    "omnichain",
    "api",
    "legacyBackend",
    "keyOfSolomon",
    "samuel",
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
    "statutes",
    "protocolConfig",
    "adminAuthority",
    "vaultVersionRegistry",
    "propertyRegistry",
)
REQUIRED_FUNDING_IDS = (
    "sgt",
    "pool",
    "did",
    "governance",
    "statutes",
    "protocol_config",
    "admin_authority",
    "vault_version_registry",
    "bridge_batch",
)

ArtifactSignatureVerifier = Callable[[Mapping[str, Any], int, bytes, bytes], bool]


def _hex_value(
    value: bytes | bytes32 | str,
    field: str,
    *,
    length: int,
    nonzero: bool = True,
) -> str:
    normalized = (
        value.lower()
        if isinstance(value, str)
        else "0x" + bytes(value).hex()
    )
    if not normalized.startswith("0x") or len(normalized) != 2 + length * 2:
        raise ValueError(
            f"{field} must be a 0x-prefixed {length}-byte value"
        )
    try:
        int(normalized[2:], 16)
    except ValueError as exc:
        raise ValueError(f"{field} must be valid hex") from exc
    if nonzero and normalized == "0x" + "00" * length:
        raise ValueError(f"{field} must be nonzero")
    return normalized


def _hex32(value: bytes | bytes32 | str, field: str) -> str:
    return _hex_value(value, field, length=32)


def _bytes32(value: object, field: str) -> bytes32:
    return bytes32.fromhex(_hex32(str(value), field).removeprefix("0x"))


def _bytes(value: object, field: str, length: int) -> bytes:
    return bytes.fromhex(
        _hex_value(str(value), field, length=length).removeprefix("0x")
    )


def _source_ref(value: object, field: str) -> str:
    normalized = str(value).lower()
    if len(normalized) != 40:
        raise ValueError(f"sourceShas.{field} must be a full commit SHA")
    try:
        int(normalized, 16)
    except ValueError as exc:
        raise ValueError(f"sourceShas.{field} must be valid hex") from exc
    return normalized


def _address(value: object, field: str) -> str:
    return _hex_value(str(value), field, length=20)


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


def _top_level_projection(plan: RC22GenesisCeremonyPlan) -> dict[str, Any]:
    protocol = plan.protocol
    canonical = plan.canonical_payload()
    return {
        "sourceShas": dict(plan.source_shas),
        "puzzleHashes": {
            "poolInnerModHash": _hex32(
                protocol.pool_inner_mod_hash, "poolInnerModHash"
            ),
            "poolInnerPuzzleHash": _hex32(
                protocol.pool_inner_puzzle_hash, "poolInnerPuzzleHash"
            ),
            "poolFullPuzzleHash": _hex32(
                protocol.pool_full_puzzle_hash, "poolFullPuzzleHash"
            ),
            "poolTokenTailHash": _hex32(
                protocol.sols_tail_hash, "poolTokenTailHash"
            ),
            "smartDeedInnerModHash": _hex32(
                protocol.smart_deed_inner_mod_hash,
                "smartDeedInnerModHash",
            ),
            "p2PoolModHash": _hex32(
                protocol.p2_pool_mod_hash, "p2PoolModHash"
            ),
            "deedLauncherPuzzleHash": _hex32(
                protocol.pool_config.deed_launcher_puzzle_hash,
                "deedLauncherPuzzleHash",
            ),
            "p2VaultModHash": _hex32(
                protocol.p2_vault_mod_hash, "p2VaultModHash"
            ),
            "vaultInnerModHash": _hex32(
                protocol.vault_inner_mod_hash, "vaultInnerModHash"
            ),
            "didInnerPuzzleHash": _hex32(
                protocol.did_inner_puzzle_hash, "didInnerPuzzleHash"
            ),
            "didFullPuzzleHash": _hex32(
                protocol.did_full_puzzle_hash, "didFullPuzzleHash"
            ),
            "governanceInnerPuzzleHash": _hex32(
                protocol.governance_inner_puzzle_hash,
                "governanceInnerPuzzleHash",
            ),
            "governanceFullPuzzleHash": _hex32(
                protocol.governance_full_puzzle_hash,
                "governanceFullPuzzleHash",
            ),
            "statutesInnerModHash": _hex32(
                protocol.statutes_inner_mod_hash, "statutesInnerModHash"
            ),
            "statutesInnerPuzzleHash": _hex32(
                protocol.statutes_inner_puzzle_hash,
                "statutesInnerPuzzleHash",
            ),
            "statutesFullPuzzleHash": _hex32(
                protocol.statutes_full_puzzle_hash,
                "statutesFullPuzzleHash",
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
            "propertyRegistryInnerPuzzleHash": _hex32(
                plan.property_registry.inner_puzzle_hash,
                "propertyRegistryInnerPuzzleHash",
            ),
            "propertyRegistryFullPuzzleHash": _hex32(
                plan.property_registry.full_puzzle_hash,
                "propertyRegistryFullPuzzleHash",
            ),
            "sgtTailHash": _hex32(protocol.sgt_tail_hash, "sgtTailHash"),
            "solsTailHash": _hex32(protocol.sols_tail_hash, "solsTailHash"),
            "solsReserveSeedPuzzleHash": _hex32(
                protocol.sols_reserve_seed_puzzle_hash,
                "solsReserveSeedPuzzleHash",
            ),
            "bridgePolicy": _hex32(
                protocol.trusted_zkpassport_bridge_policy_hash,
                "bridgePolicy",
            ),
        },
        "launcherIds": dict(canonical["launcherIds"]),
        "sgtGenesisCoinId": _hex32(
            protocol.sgt_genesis_coin_id, "sgtGenesisCoinId"
        ),
        "sgtTailHash": _hex32(protocol.sgt_tail_hash, "sgtTailHash"),
        "solsTailHash": _hex32(protocol.sols_tail_hash, "solsTailHash"),
        "solsReserveSeed": {
            "amount": 1,
            "puzzleHash": _hex32(
                protocol.sols_reserve_seed_puzzle_hash,
                "solsReserveSeedPuzzleHash",
            ),
            "coinId": _hex32(
                protocol.sols_reserve_seed_coin_id,
                "solsReserveSeedCoinId",
            ),
            "circulating": False,
        },
        "governanceStruct": {
            "treeHash": _hex32(
                protocol.governance_singleton_struct_hash,
                "governanceSingletonStructHash",
            ),
            "launcherId": _hex32(
                protocol.governance_launcher_id,
                "governanceLauncherId",
            ),
            "serialized": "0x"
            + bytes(singleton_struct(protocol.governance_launcher_id)).hex(),
            "mintExecuteCosignerPubkey": _hex_value(
                protocol.kos_mint_execute_pubkey,
                "mintExecuteCosignerPubkey",
                length=48,
            ),
        },
        "protocolDid": {
            "launcherId": _hex32(protocol.did_launcher_id, "didLauncherId"),
            "singletonStruct": "0x"
            + bytes(singleton_struct(protocol.did_launcher_id)).hex(),
            "innerPuzzleHash": _hex32(
                protocol.did_inner_puzzle_hash, "didInnerPuzzleHash"
            ),
            "fullPuzzleHash": _hex32(
                protocol.did_full_puzzle_hash, "didFullPuzzleHash"
            ),
        },
        "propertyRegistry": {
            "launcherId": _hex32(
                plan.property_registry.launcher_id,
                "propertyRegistryLauncherId",
            ),
            "governanceBlsPubkey": _hex_value(
                protocol.governance_bls_pubkey,
                "propertyRegistryGovernanceBlsPubkey",
                length=48,
            ),
            "currentPuzzleHash": _hex32(
                plan.property_registry.full_puzzle_hash,
                "propertyRegistryFullPuzzleHash",
            ),
        },
        "protocolParameters": dict(canonical["protocolParameters"]),
        "permanentRules": dict(canonical["permanentRules"]),
        "stateVersions": {
            "statutes": protocol.statutes_state.registry_version,
            "pool": protocol.pool_state.state_version,
            "protocolConfig": plan.protocol_config_version,
            "adminAuthority": plan.admin_authority_version,
            "vault": plan.vault_version,
            "propertyRegistry": plan.property_registry_version,
        },
        "statutes": {
            "contentHash": _hex32(
                protocol.statutes_state.content_hash,
                "statutesContentHash",
            ),
            "roots": {
                "parameters": _hex32(
                    protocol.statutes_state.parameters_root,
                    "statutesParametersRoot",
                ),
                "collections": _hex32(
                    protocol.statutes_state.collections_root,
                    "statutesCollectionsRoot",
                ),
                "oracles": _hex32(
                    protocol.statutes_state.oracle_root,
                    "statutesOracleRoot",
                ),
                "bridgeRoutes": _hex32(
                    protocol.statutes_state.routes_root,
                    "statutesRoutesRoot",
                ),
                "liquidityVenues": _hex32(
                    protocol.statutes_state.liquidity_root,
                    "statutesLiquidityRoot",
                ),
                "pauses": _hex32(
                    protocol.statutes_state.pauses_root,
                    "statutesPausesRoot",
                ),
            },
        },
        "adminAuthority": {
            "threshold": plan.admin_quorum.threshold,
            "policy": GENESIS_ADMIN_POLICY,
            "ownerIndex": plan.admin_quorum.owner_index,
            "coadminIndices": list(plan.admin_quorum.coadmin_indices),
            "coadminThreshold": plan.admin_quorum.coadmin_threshold,
            "rosterHash": _hex32(
                plan.admin_quorum.admins_hash, "adminRosterHash"
            ),
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
            "policyHash": _hex32(
                plan.bridge_batch.policy_hash, "bridgePolicyHash"
            ),
            "fundingAmount": RC22_BRIDGE_BATCH_FUNDING_AMOUNT,
            "parentOutputAmount": RC22_BRIDGE_PARENT_TOTAL,
            "propertyRegistryLauncherAmount": (
                RC22_PROPERTY_REGISTRY_LAUNCHER_AMOUNT
            ),
            "networkFeeSource": "separate-fountain-fee-till",
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
            plan.canonical_vault_params_hash,
            "canonicalVaultParamsHash",
        ),
        "evmAddresses": dict(plan.evm_addresses),
        "retiredCoordinates": [
            _hex32(value, "retiredCoordinate")
            for value in plan.retired_coordinates
        ],
    }


def build_public_artifact(
    *,
    plan: RC22GenesisCeremonyPlan,
    spend_bundle_id: bytes32 | str,
    confirmed_block_index: int,
    build_timestamp: str | None = None,
    signatures: Sequence[Mapping[str, Any]] = (),
    review_class: str = INDEPENDENT_REVIEW_CLASS,
) -> dict[str, Any]:
    verify_rc22_genesis_ceremony_plan(plan)
    if confirmed_block_index <= 0:
        raise ValueError("confirmedBlockIndex must be positive")
    timestamp = build_timestamp or datetime.now(timezone.utc).isoformat()
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("buildTimestamp must be ISO-8601") from exc
    if review_class not in REVIEW_CLASSES:
        raise ValueError("unsupported genesis review class")
    internal_test = (
        review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS
    )
    payload: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "protocolVersion": RC22_PROTOCOL_VERSION,
        "network": plan.network,
        "evmChainId": plan.evm_chain_id,
        "reviewClass": review_class,
        "testOnly": internal_test,
        "auditStatus": (
            "pending-external-review"
            if internal_test
            else "independently-reviewed"
        ),
        "buildTimestamp": timestamp,
        "sourceManifestVersion": SOURCE_MANIFEST_VERSION,
        "ceremony": {
            "ceremonyId": _hex32(plan.ceremony_id, "ceremonyId"),
            "planHash": _hex32(plan.plan_hash, "planHash"),
            "spendBundleId": _hex32(spend_bundle_id, "spendBundleId"),
            "confirmedBlockIndex": confirmed_block_index,
            "requiredChiaConfirmations": REQUIRED_CHIA_CONFIRMATIONS,
        },
        "genesisPlan": plan.canonical_payload(),
        **_top_level_projection(plan),
        "signaturePolicy": {
            "type": ARTIFACT_SIGNATURE_TYPE,
            "threshold": GENESIS_ADMIN_THRESHOLD,
            "policy": GENESIS_ADMIN_POLICY,
            "ownerIndex": GENESIS_ADMIN_OWNER_INDEX,
            "coadminIndices": list(GENESIS_ADMIN_COADMIN_INDICES),
            "coadminThreshold": GENESIS_ADMIN_COADMIN_THRESHOLD,
            "rosterHash": _hex32(
                plan.admin_quorum.admins_hash, "adminRosterHash"
            ),
        },
        "signatures": [dict(signature) for signature in signatures],
    }
    payload["artifactHash"] = artifact_hash(payload)
    return payload


def artifact_signing_typed_data(payload: Mapping[str, Any]) -> dict[str, Any]:
    _verify_artifact_content(payload)
    ceremony = payload["ceremony"]
    return {
        "domain": {
            "name": "Solslot Protocol",
            "version": "3",
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


def _rebuild_plan(payload: Mapping[str, Any]) -> RC22GenesisCeremonyPlan:
    plan = payload.get("genesisPlan")
    if not isinstance(plan, Mapping):
        raise ValueError("artifact genesisPlan is missing")
    if plan.get("schema") != RC22_GENESIS_PLAN_SCHEMA:
        raise ValueError("artifact genesis plan schema is not RC22 V3")
    sources = plan.get("sourceShas")
    addresses = plan.get("evmAddresses")
    funding = plan.get("fundingCoinIds")
    params = plan.get("protocolParameters")
    admin = plan.get("adminAuthority")
    validators = plan.get("validatorSet")
    trusted = plan.get("trustedDestinations")
    state = plan.get("state")
    if not all(
        isinstance(value, Mapping)
        for value in (
            sources,
            addresses,
            funding,
            params,
            admin,
            validators,
            trusted,
            state,
        )
    ):
        raise ValueError("artifact genesis plan is incomplete")
    if set(funding) != set(REQUIRED_FUNDING_IDS):
        raise ValueError("artifact funding coin IDs are incomplete")
    resolved_parameters = ProtocolParameters(
        voting_window_seconds=int(params["votingWindowSeconds"]),
        quorum_bps=int(params["quorumBps"]),
        min_proposal_stake=int(params["minProposalStake"]),
        nav_validity_seconds=int(params["navValiditySeconds"]),
        oracle_max_age_seconds=int(params["oracleMaxAgeSeconds"]),
        exchange_fee_bps=int(params["exchangeFeeBps"]),
        protocol_fee_bps=int(params["protocolFeeBps"]),
        sgt_rewards_fee_bps=int(params["sgtRewardsFeeBps"]),
        reward_epoch_seconds=int(params["rewardEpochSeconds"]),
    )
    return build_rc22_genesis_ceremony_plan(
        ceremony_id=_bytes32(plan["ceremonyId"], "ceremonyId"),
        expires_at=int(plan["expiresAt"]),
        source_shas={
            key: _source_ref(sources[key], key)
            for key in REQUIRED_SOURCE_REFS
        },
        evm_addresses={
            key: _address(addresses[key], key)
            for key in REQUIRED_EVM_ADDRESSES
        },
        funding=RC22GenesisFundingCoinIds(
            **{
                key: _bytes32(funding[key], f"fundingCoinIds.{key}")
                for key in REQUIRED_FUNDING_IDS
            }
        ),
        faucet_puzzle_hash=_bytes32(
            plan["faucetPuzzleHash"], "faucetPuzzleHash"
        ),
        governance_bls_pubkey=_bytes(
            plan["governanceBlsPubkey"], "governanceBlsPubkey", 48
        ),
        kos_mint_execute_pubkey=_bytes(
            plan["kosMintExecutePubkey"], "kosMintExecutePubkey", 48
        ),
        admin_compressed_pubkeys=[
            _bytes(value, "adminCompressedPubkey", 33)
            for value in admin["compressedPubkeys"]
        ],
        validator_pubkeys=[
            _bytes(value, "validatorPubkey", 48)
            for value in validators["pubkeys"]
        ],
        trusted_treasury_reserve_puzzle_hash=_bytes32(
            trusted["treasuryReservePuzzleHash"],
            "treasuryReservePuzzleHash",
        ),
        trusted_protocol_treasury_puzzle_hash=_bytes32(
            trusted["protocolTreasuryPuzzleHash"],
            "protocolTreasuryPuzzleHash",
        ),
        trusted_governance_rewards_puzzle_hash=_bytes32(
            trusted["governanceRewardsPuzzleHash"],
            "governanceRewardsPuzzleHash",
        ),
        trusted_governance_rewards_root=_bytes32(
            trusted["governanceRewardsRoot"], "governanceRewardsRoot"
        ),
        retired_coordinates=[
            _bytes32(value, "retiredCoordinate")
            for value in plan["retiredCoordinates"]
        ],
        parameters=resolved_parameters,
        network=str(plan["network"]),
        evm_chain_id=int(plan["evmChainId"]),
        protocol_config_version=int(state["protocolConfigVersion"]),
        admin_authority_version=int(state["adminAuthorityVersion"]),
        vault_version=int(state["vaultVersion"]),
        property_registry_version=int(state["propertyRegistryVersion"]),
    )


def _verify_artifact_content(payload: Mapping[str, Any]) -> None:
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported artifact schemaVersion")
    if payload.get("protocolVersion") != RC22_PROTOCOL_VERSION:
        raise ValueError("unsupported or retired protocolVersion")
    if payload.get("network") != GENESIS_NETWORK:
        raise ValueError("artifact network is not testnet11")
    if payload.get("evmChainId") != GENESIS_EVM_CHAIN_ID:
        raise ValueError("artifact EVM chain is not Base Sepolia")
    review_class = payload.get("reviewClass")
    if review_class not in REVIEW_CLASSES:
        raise ValueError("artifact reviewClass is unsupported")
    if review_class == INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS:
        if (
            payload.get("testOnly") is not True
            or payload.get("auditStatus") != "pending-external-review"
        ):
            raise ValueError(
                "internal engineering artifact must be test-only "
                "and pending external review"
            )
    elif (
        payload.get("testOnly") is not False
        or payload.get("auditStatus") != "independently-reviewed"
    ):
        raise ValueError("independently reviewed artifact metadata is invalid")
    if payload.get("sourceManifestVersion") != SOURCE_MANIFEST_VERSION:
        raise ValueError("artifact sourceManifestVersion is unsupported")
    if payload.get("artifactHash") != artifact_hash(payload):
        raise ValueError("artifactHash does not match canonical payload")

    rebuilt = _rebuild_plan(payload)
    canonical = rebuilt.canonical_payload()
    if payload["genesisPlan"] != canonical:
        raise ValueError(
            "artifact genesis plan does not reconstruct from RC22 source rules"
        )
    if payload.get("ceremony", {}).get("planHash") != canonical["planHash"]:
        raise ValueError("artifact ceremony plan hash is inconsistent")
    projection = _top_level_projection(rebuilt)
    for key, value in projection.items():
        if payload.get(key) != value:
            raise ValueError(f"artifact {key} does not match its RC22 plan")

    permanent = payload["permanentRules"]
    if (
        permanent["maxExchangeFeeBps"] != MAX_EXCHANGE_FEE_BPS
        or permanent["upgradeDelaySeconds"] != UPGRADE_DELAY_SECONDS
        or not all(
            permanent[name] is True
            for name in (
                "voteConservation",
                "replayProtection",
                "treasuryNonWithdrawal",
                "protocolOnlySmartDeedSolsExchange",
                "zkPassportRequired",
                "solsSupplyNeverMelted",
                "solsPrimaryPurchasesDisabled",
            )
        )
    ):
        raise ValueError("artifact permanent protocol rules are invalid")

    ceremony = payload.get("ceremony")
    if not isinstance(ceremony, Mapping):
        raise ValueError("artifact ceremony metadata is missing")
    for key in ("ceremonyId", "planHash", "spendBundleId"):
        _hex32(ceremony.get(key, ""), key)
    if int(ceremony.get("confirmedBlockIndex", 0)) <= 0:
        raise ValueError("artifact ceremony is not confirmed")
    if (
        ceremony.get("requiredChiaConfirmations")
        != REQUIRED_CHIA_CONFIRMATIONS
    ):
        raise ValueError("artifact Chia confirmation policy is invalid")

    admin = payload["adminAuthority"]
    policy = payload.get("signaturePolicy")
    if not isinstance(policy, Mapping):
        raise ValueError("artifact signature policy is missing")
    if (
        policy.get("type") != ARTIFACT_SIGNATURE_TYPE
        or policy.get("threshold") != GENESIS_ADMIN_THRESHOLD
        or policy.get("policy") != GENESIS_ADMIN_POLICY
        or policy.get("ownerIndex") != GENESIS_ADMIN_OWNER_INDEX
        or policy.get("coadminIndices")
        != list(GENESIS_ADMIN_COADMIN_INDICES)
        or policy.get("coadminThreshold")
        != GENESIS_ADMIN_COADMIN_THRESHOLD
        or policy.get("rosterHash") != admin["rosterHash"]
    ):
        raise ValueError("artifact signature policy does not match the roster")


def verify_public_artifact(
    payload: Mapping[str, Any],
    *,
    signature_verifier: ArtifactSignatureVerifier | None = None,
) -> None:
    _verify_artifact_content(payload)
    if signature_verifier is None:
        raise ValueError("artifact signature verifier is required")
    signatures = payload.get("signatures")
    if not isinstance(signatures, list) or not 2 <= len(signatures) <= 3:
        raise ValueError("artifact requires two administrator signatures")
    admin_keys = payload["adminAuthority"]["compressedPubkeys"]
    seen: set[int] = set()
    for entry in signatures:
        if not isinstance(entry, Mapping):
            raise ValueError("artifact signature entry is malformed")
        index = int(entry.get("adminIndex", -1))
        if index not in (0, 1, 2) or index in seen:
            raise ValueError(
                "artifact signatures must use distinct roster slots"
            )
        seen.add(index)
        pubkey_hex = _hex_value(
            entry.get("compressedPubkey", ""),
            "signature.compressedPubkey",
            length=33,
        )
        if pubkey_hex != admin_keys[index]:
            raise ValueError(
                "artifact signature key does not match roster slot"
            )
        signature_hex = _hex_value(
            entry.get("signature", ""),
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
    if GENESIS_ADMIN_OWNER_INDEX not in seen or not (
        seen & set(GENESIS_ADMIN_COADMIN_INDICES)
    ):
        raise ValueError(
            "artifact requires slot 0 and one coadministrator signature"
        )


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
