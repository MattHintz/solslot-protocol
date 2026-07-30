"""Signed public artifact for the recovery-aware Solslot RC23 genesis."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from chia_rs.sized_bytes import bytes32

from solslot_puzzles.artifact_schema_v3 import (
    ARTIFACT_SIGNATURE_TYPE,
    INDEPENDENT_REVIEW_CLASS,
    INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS,
    REQUIRED_CHIA_CONFIRMATIONS,
    REQUIRED_EVM_ADDRESSES,
    REQUIRED_FUNDING_IDS,
    REQUIRED_SOURCE_REFS,
    REVIEW_CLASSES,
    _address,
    _bytes,
    _bytes32,
    _hex32,
    _hex_value,
    _source_ref,
    _top_level_projection,
    artifact_hash,
    canonical_json,
)
from solslot_puzzles.genesis_ceremony import (
    GENESIS_ADMIN_COADMIN_INDICES,
    GENESIS_ADMIN_COADMIN_THRESHOLD,
    GENESIS_ADMIN_OWNER_INDEX,
    GENESIS_ADMIN_POLICY,
    GENESIS_ADMIN_THRESHOLD,
    GENESIS_EVM_CHAIN_ID,
    GENESIS_NETWORK,
)
from solslot_puzzles.genesis_ceremony_rc23 import (
    RC23_GENESIS_PLAN_SCHEMA,
    RC23_PROTOCOL_VERSION,
    RC23_SOURCE_MANIFEST_VERSION,
    RC23GenesisCeremonyPlan,
    RC23GenesisFundingCoinIds,
    build_rc23_genesis_ceremony_plan,
    verify_rc23_genesis_ceremony_plan,
)
from solslot_puzzles.protocol_statutes_v1 import (
    MAX_EXCHANGE_FEE_BPS,
    UPGRADE_DELAY_SECONDS,
    ProtocolParameters,
)


SCHEMA_VERSION = 4
ArtifactSignatureVerifier = Callable[
    [Mapping[str, Any], int, bytes, bytes],
    bool,
]


def _projection(plan: RC23GenesisCeremonyPlan) -> dict[str, Any]:
    projection = _top_level_projection(plan)
    canonical = plan.canonical_payload()
    hashes = dict(projection["puzzleHashes"])
    hashes.update(
        {
            "adminAuthorityInnerMod": canonical["puzzleHashes"][
                "adminAuthorityInnerMod"
            ],
            "adminAuthorityInner": canonical["puzzleHashes"][
                "adminAuthorityInner"
            ],
            "adminAuthorityFull": canonical["puzzleHashes"][
                "adminAuthorityFull"
            ],
            "adminIdentityCustody": list(
                canonical["puzzleHashes"]["adminIdentityCustody"]
            ),
            "adminIdentityFull": list(
                canonical["puzzleHashes"]["adminIdentityFull"]
            ),
        }
    )
    projection["puzzleHashes"] = hashes
    projection["adminRecoveryKits"] = list(
        canonical["adminRecoveryKits"]
    )
    return projection


def build_public_artifact(
    *,
    plan: RC23GenesisCeremonyPlan,
    spend_bundle_id: bytes32 | str,
    confirmed_block_index: int,
    build_timestamp: str | None = None,
    signatures: Sequence[Mapping[str, Any]] = (),
    review_class: str = INDEPENDENT_REVIEW_CLASS,
) -> dict[str, Any]:
    verify_rc23_genesis_ceremony_plan(plan)
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
        "protocolVersion": RC23_PROTOCOL_VERSION,
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
        "sourceManifestVersion": RC23_SOURCE_MANIFEST_VERSION,
        "ceremony": {
            "ceremonyId": _hex32(plan.ceremony_id, "ceremonyId"),
            "planHash": _hex32(plan.plan_hash, "planHash"),
            "spendBundleId": _hex32(
                spend_bundle_id,
                "spendBundleId",
            ),
            "confirmedBlockIndex": confirmed_block_index,
            "requiredChiaConfirmations": REQUIRED_CHIA_CONFIRMATIONS,
        },
        "genesisPlan": plan.canonical_payload(),
        **_projection(plan),
        "signaturePolicy": {
            "type": ARTIFACT_SIGNATURE_TYPE,
            "threshold": GENESIS_ADMIN_THRESHOLD,
            "policy": GENESIS_ADMIN_POLICY,
            "ownerIndex": GENESIS_ADMIN_OWNER_INDEX,
            "coadminIndices": list(GENESIS_ADMIN_COADMIN_INDICES),
            "coadminThreshold": GENESIS_ADMIN_COADMIN_THRESHOLD,
            "rosterHash": _hex32(
                plan.admin_roster_hash,
                "adminRosterHash",
            ),
        },
        "signatures": [dict(signature) for signature in signatures],
    }
    payload["artifactHash"] = artifact_hash(payload)
    return payload


def artifact_signing_typed_data(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    _verify_artifact_content(payload)
    ceremony = payload["ceremony"]
    return {
        "domain": {
            "name": "Solslot Protocol",
            "version": "4",
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


def _rebuild_plan(
    payload: Mapping[str, Any],
) -> RC23GenesisCeremonyPlan:
    plan = payload.get("genesisPlan")
    if not isinstance(plan, Mapping):
        raise ValueError("artifact genesisPlan is missing")
    if plan.get("schema") != RC23_GENESIS_PLAN_SCHEMA:
        raise ValueError("artifact genesis plan schema is not RC23 V4")
    sources = plan.get("sourceShas")
    addresses = plan.get("evmAddresses")
    funding = plan.get("fundingCoinIds")
    params = plan.get("protocolParameters")
    admin = plan.get("adminAuthority")
    recovery_kits = plan.get("adminRecoveryKits")
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
    ) or not isinstance(recovery_kits, list):
        raise ValueError("artifact genesis plan is incomplete")
    if set(funding) != set(REQUIRED_FUNDING_IDS):
        raise ValueError("artifact funding coin IDs are incomplete")
    identities = admin.get("identityVaults")
    if not isinstance(identities, list) or len(identities) != 3:
        raise ValueError("artifact Authority V3 identity roster is incomplete")
    if len(recovery_kits) != 3:
        raise ValueError("artifact recovery-kit roster is incomplete")
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
    return build_rc23_genesis_ceremony_plan(
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
        funding=RC23GenesisFundingCoinIds(
            **{
                key: _bytes32(
                    funding[key],
                    f"fundingCoinIds.{key}",
                )
                for key in REQUIRED_FUNDING_IDS
            }
        ),
        faucet_puzzle_hash=_bytes32(
            plan["faucetPuzzleHash"],
            "faucetPuzzleHash",
        ),
        governance_bls_pubkey=_bytes(
            plan["governanceBlsPubkey"],
            "governanceBlsPubkey",
            48,
        ),
        kos_mint_execute_pubkey=_bytes(
            plan["kosMintExecutePubkey"],
            "kosMintExecutePubkey",
            48,
        ),
        admin_compressed_pubkeys=[
            _bytes(
                value,
                "adminCompressedPubkey",
                33,
            )
            for value in admin["compressedPubkeys"]
        ],
        admin_recovery_bls_pubkeys=[
            _bytes(
                item["recoveryBlsPubkey"],
                "recoveryBlsPubkey",
                48,
            )
            for item in recovery_kits
        ],
        admin_recovery_evm_guardians=[
            _address(item["evmGuardian"], "evmGuardian")
            for item in recovery_kits
        ],
        admin_recovery_revisions=[
            int(item["revision"]) for item in recovery_kits
        ],
        admin_recovery_drill_hashes=[
            _bytes32(
                item["drillChallengeHash"],
                "drillChallengeHash",
            )
            for item in recovery_kits
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
            trusted["governanceRewardsRoot"],
            "governanceRewardsRoot",
        ),
        retired_coordinates=[
            _bytes32(value, "retiredCoordinate")
            for value in plan["retiredCoordinates"]
        ],
        parameters=resolved_parameters,
        network=str(plan["network"]),
        evm_chain_id=int(plan["evmChainId"]),
        protocol_config_version=int(
            state["protocolConfigVersion"]
        ),
        admin_authority_version=int(
            state["adminAuthorityVersion"]
        ),
        vault_version=int(state["vaultVersion"]),
        property_registry_version=int(
            state["propertyRegistryVersion"]
        ),
    )


def _verify_artifact_content(payload: Mapping[str, Any]) -> None:
    if payload.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("unsupported artifact schemaVersion")
    if payload.get("protocolVersion") != RC23_PROTOCOL_VERSION:
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
            or payload.get("auditStatus")
            != "pending-external-review"
        ):
            raise ValueError(
                "internal engineering artifact must be test-only and "
                "pending external review"
            )
    elif (
        payload.get("testOnly") is not False
        or payload.get("auditStatus") != "independently-reviewed"
    ):
        raise ValueError(
            "independently reviewed artifact metadata is invalid"
        )
    if (
        payload.get("sourceManifestVersion")
        != RC23_SOURCE_MANIFEST_VERSION
    ):
        raise ValueError(
            "artifact sourceManifestVersion is unsupported"
        )
    if payload.get("artifactHash") != artifact_hash(payload):
        raise ValueError(
            "artifactHash does not match canonical payload"
        )

    rebuilt = _rebuild_plan(payload)
    canonical = rebuilt.canonical_payload()
    if payload.get("genesisPlan") != canonical:
        raise ValueError(
            "artifact genesis plan does not reconstruct from RC23 rules"
        )
    ceremony = payload.get("ceremony")
    if not isinstance(ceremony, Mapping):
        raise ValueError("artifact ceremony metadata is missing")
    if ceremony.get("planHash") != canonical["planHash"]:
        raise ValueError(
            "artifact ceremony plan hash is inconsistent"
        )
    for key in ("ceremonyId", "planHash", "spendBundleId"):
        _hex32(ceremony.get(key, ""), key)
    if int(ceremony.get("confirmedBlockIndex", 0)) <= 0:
        raise ValueError("artifact ceremony is not confirmed")
    if (
        ceremony.get("requiredChiaConfirmations")
        != REQUIRED_CHIA_CONFIRMATIONS
    ):
        raise ValueError(
            "artifact Chia confirmation policy is invalid"
        )

    projection = _projection(rebuilt)
    for key, value in projection.items():
        if payload.get(key) != value:
            raise ValueError(
                f"artifact {key} does not match its RC23 plan"
            )
    permanent = payload["permanentRules"]
    if (
        permanent["maxExchangeFeeBps"] != MAX_EXCHANGE_FEE_BPS
        or permanent["upgradeDelaySeconds"]
        != UPGRADE_DELAY_SECONDS
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
        raise ValueError(
            "artifact permanent protocol rules are invalid"
        )
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
        raise ValueError(
            "artifact signature policy does not match Authority V3"
        )


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
        raise ValueError(
            "artifact requires two administrator signatures"
        )
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
            raise ValueError(
                "artifact administrator signature is invalid"
            )
    if GENESIS_ADMIN_OWNER_INDEX not in seen or not (
        seen & set(GENESIS_ADMIN_COADMIN_INDICES)
    ):
        raise ValueError(
            "artifact requires slot 0 and one coadministrator signature"
        )


__all__ = [
    "SCHEMA_VERSION",
    "ArtifactSignatureVerifier",
    "artifact_hash",
    "artifact_signing_typed_data",
    "build_public_artifact",
    "canonical_json",
    "verify_public_artifact",
]
