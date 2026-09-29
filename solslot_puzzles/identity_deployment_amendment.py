"""Canonical, append-only activation record for an identity deployment.

The genesis artifact remains immutable.  This module validates a separately
published statement whose digest is announced by a confirmed spend of the
current administrator authority singleton.  Consumers must verify both the
statement and its on-chain anchor before selecting the effective deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


SCHEMA = "solslot.identity-deployment-amendment.v1"
STATEMENT_TYPE = "SOLSLOT_IDENTITY_DEPLOYMENT_V1"
ANNOUNCEMENT_PREFIX = b"SOLSLOT_IDENTITY_DEPLOYMENT_V1:"
ZERO_HASH = "0x" + "00" * 32
SUPPORTED_NETWORKS = frozenset({"testnet11", "mainnet"})

_HEX32_RE = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
_SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

_TOP_KEYS = frozenset(
    {
        "schema",
        "statementType",
        "revision",
        "previousAmendmentHash",
        "baseArtifactHash",
        "ceremonyId",
        "chiaNetwork",
        "evmChainId",
        "oldDeployment",
        "newDeployment",
        "identityPolicy",
        "chiaBridgePolicyHash",
        "activationBoundary",
        "deploymentSourceShas",
        "activationSourceShas",
        "deploymentPlanHash",
        "deploymentArtifactHash",
        "approvalExpiresAt",
    }
)
_ADDRESS_KEYS = frozenset({"forwarder", "verifierAdapter", "attestationEmitter"})
_NEW_DEPLOYMENT_KEYS = frozenset(
    {
        "addresses",
        "transactions",
        "runtimeCodeHashes",
        "rootVerifierAddress",
        "rootVerifierCodeHash",
        "trustedDirectRelayer",
        "immutableBindings",
        "acceptedProofVersions",
        "credentialPolicyVersion",
    }
)
_TRANSACTION_KEYS = frozenset({"hash", "blockNumber", "blockHash", "nonce", "initCodeHash"})
_BOUNDARY_KEYS = frozenset(
    {
        "authorityLauncherId",
        "authorityCoinId",
        "authorityVersion",
        "rosterIdentityCoinIds",
        "signerSlots",
        "signerIdentityCoinIds",
    }
)
_POLICY_KEYS = frozenset(
    {"schema", "adapter", "domain", "devMode", "minimumAge", "sanctions", "realDocumentOnly", "policyId"}
)
_SANCTIONS_KEYS = frozenset({"countries", "lists", "strict"})
_IMMUTABLE_KEYS = frozenset({"emitterVerifier", "emitterForwarder", "emitterRelayer", "adapterRootVerifier"})


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _no_duplicate_pairs(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_canonical_statement(raw: bytes | str) -> dict[str, Any]:
    """Parse an exact canonical JSON statement and reject duplicate keys."""
    try:
        encoded = raw.encode("ascii") if isinstance(raw, str) else bytes(raw)
        value = json.loads(encoded, object_pairs_hook=_no_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("identity amendment must be valid ASCII JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("identity amendment must be a JSON object")
    if canonical_json(value) != encoded:
        raise ValueError("identity amendment JSON is not canonical")
    return value


def amendment_hash(statement: Mapping[str, Any]) -> str:
    validate_statement_shape(statement)
    return "0x" + hashlib.sha256(canonical_json(statement)).hexdigest()


def announcement_message(statement_hash: str) -> bytes:
    _require_hex32(statement_hash, "statement_hash")
    return ANNOUNCEMENT_PREFIX + bytes.fromhex(statement_hash[2:])


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value.keys())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} fields mismatch; missing={missing}, extra={extra}")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _require_hex32(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HEX32_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase 32-byte hex value")
    return value


def _require_address(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase EVM address")
    if value == "0x" + "00" * 20:
        raise ValueError(f"{label} must be nonzero")
    return value


def _addresses(value: Any, label: str) -> Mapping[str, Any]:
    item = _mapping(value, label)
    _exact_keys(item, _ADDRESS_KEYS, label)
    for name in sorted(_ADDRESS_KEYS):
        _require_address(item[name], f"{label}.{name}")
    if len(set(item.values())) != 3:
        raise ValueError(f"{label} addresses must be distinct")
    return item


def validate_statement_shape(statement: Mapping[str, Any]) -> None:
    """Validate the closed amendment schema without consulting external state."""
    _exact_keys(statement, _TOP_KEYS, "identity amendment")
    if statement["schema"] != SCHEMA or statement["statementType"] != STATEMENT_TYPE:
        raise ValueError("unsupported identity amendment schema")
    revision = _positive_int(statement["revision"], "revision")
    previous = _require_hex32(statement["previousAmendmentHash"], "previousAmendmentHash")
    if revision == 1 and previous != ZERO_HASH:
        raise ValueError("revision 1 must have a zero previousAmendmentHash")
    if revision > 1 and previous == ZERO_HASH:
        raise ValueError("later revisions must name the previous amendment")
    _require_hex32(statement["baseArtifactHash"], "baseArtifactHash")
    _require_hex32(statement["ceremonyId"], "ceremonyId")
    if statement["chiaNetwork"] not in SUPPORTED_NETWORKS:
        raise ValueError("unsupported Chia network")
    _positive_int(statement["evmChainId"], "evmChainId")
    old_addresses = _addresses(statement["oldDeployment"], "oldDeployment")

    new = _mapping(statement["newDeployment"], "newDeployment")
    _exact_keys(new, _NEW_DEPLOYMENT_KEYS, "newDeployment")
    new_addresses = _addresses(new["addresses"], "newDeployment.addresses")
    if old_addresses == new_addresses:
        raise ValueError("new deployment must change the address triple")
    runtimes = _mapping(new["runtimeCodeHashes"], "runtimeCodeHashes")
    _exact_keys(runtimes, _ADDRESS_KEYS, "runtimeCodeHashes")
    transactions = _mapping(new["transactions"], "transactions")
    _exact_keys(transactions, _ADDRESS_KEYS, "transactions")
    for name in sorted(_ADDRESS_KEYS):
        _require_hex32(runtimes[name], f"runtimeCodeHashes.{name}")
        tx = _mapping(transactions[name], f"transactions.{name}")
        _exact_keys(tx, _TRANSACTION_KEYS, f"transactions.{name}")
        _require_hex32(tx["hash"], f"transactions.{name}.hash")
        _positive_int(tx["blockNumber"], f"transactions.{name}.blockNumber")
        _require_hex32(tx["blockHash"], f"transactions.{name}.blockHash")
        if isinstance(tx["nonce"], bool) or not isinstance(tx["nonce"], int) or tx["nonce"] < 0:
            raise ValueError(f"transactions.{name}.nonce must be nonnegative")
        _require_hex32(tx["initCodeHash"], f"transactions.{name}.initCodeHash")
    _require_address(new["rootVerifierAddress"], "rootVerifierAddress")
    _require_hex32(new["rootVerifierCodeHash"], "rootVerifierCodeHash")
    _require_address(new["trustedDirectRelayer"], "trustedDirectRelayer")
    bindings = _mapping(new["immutableBindings"], "immutableBindings")
    _exact_keys(bindings, _IMMUTABLE_KEYS, "immutableBindings")
    expected_bindings = {
        "emitterVerifier": new_addresses["verifierAdapter"],
        "emitterForwarder": new_addresses["forwarder"],
        "emitterRelayer": new["trustedDirectRelayer"],
        "adapterRootVerifier": new["rootVerifierAddress"],
    }
    if dict(bindings) != expected_bindings:
        raise ValueError("immutable contract bindings do not match deployment addresses")
    versions = new["acceptedProofVersions"]
    if versions != ["0.20.0", "0.21.0"]:
        raise ValueError("accepted proof versions must be exactly 0.20.0 and 0.21.0")
    if new["credentialPolicyVersion"] != 2:
        raise ValueError("credentialPolicyVersion must be 2")

    policy = _mapping(statement["identityPolicy"], "identityPolicy")
    _exact_keys(policy, _POLICY_KEYS, "identityPolicy")
    sanctions = _mapping(policy["sanctions"], "identityPolicy.sanctions")
    _exact_keys(sanctions, _SANCTIONS_KEYS, "identityPolicy.sanctions")
    expected_policy = {
        "schema": "solslot.identity-policy.v1",
        "adapter": "SolslotZkPassportEligibilityVerifierV2",
        "domain": "solslot.com",
        "devMode": False,
        "minimumAge": 18,
        "sanctions": {"countries": "all", "lists": "all", "strict": False},
        "realDocumentOnly": True,
        "policyId": "0xb3337e7e06834b4f8189ad283a3105cf3be395473b6d7ac39c7a73d106b2aeb1",
    }
    if dict(policy) != expected_policy:
        raise ValueError("identity policy is not the approved production policy")
    _require_hex32(statement["chiaBridgePolicyHash"], "chiaBridgePolicyHash")

    boundary = _mapping(statement["activationBoundary"], "activationBoundary")
    _exact_keys(boundary, _BOUNDARY_KEYS, "activationBoundary")
    _require_hex32(boundary["authorityLauncherId"], "authorityLauncherId")
    _require_hex32(boundary["authorityCoinId"], "authorityCoinId")
    _positive_int(boundary["authorityVersion"], "authorityVersion")
    identity_coins = boundary["rosterIdentityCoinIds"]
    if not isinstance(identity_coins, list) or len(identity_coins) != 3:
        raise ValueError("activationBoundary.rosterIdentityCoinIds must contain three coins")
    for index, coin_id in enumerate(identity_coins):
        _require_hex32(coin_id, f"rosterIdentityCoinIds[{index}]")
    if len(set(identity_coins)) != 3:
        raise ValueError("activation identity coin ids must be distinct")
    signer_slots = boundary["signerSlots"]
    if (
        not isinstance(signer_slots, list)
        or len(signer_slots) != 2
        or signer_slots[0] != 0
        or signer_slots[1] not in (1, 2)
    ):
        raise ValueError("activation requires owner slot 0 and one coadministrator")
    signer_coins = boundary["signerIdentityCoinIds"]
    if not isinstance(signer_coins, list) or len(signer_coins) != 2:
        raise ValueError("activation requires two signer identity coins")
    for index, coin_id in enumerate(signer_coins):
        _require_hex32(coin_id, f"signerIdentityCoinIds[{index}]")
    if signer_coins != [identity_coins[index] for index in signer_slots]:
        raise ValueError("signer identity coins do not match their roster slots")

    for field in ("deploymentSourceShas", "activationSourceShas"):
        sources = _mapping(statement[field], field)
        if not sources or any(
            not isinstance(name, str)
            or not name
            or not isinstance(sha, str)
            or not _SOURCE_SHA_RE.fullmatch(sha)
            for name, sha in sources.items()
        ):
            raise ValueError(f"{field} must be a nonempty map of lowercase Git commit SHAs")
    _require_hex32(statement["deploymentPlanHash"], "deploymentPlanHash")
    _require_hex32(statement["deploymentArtifactHash"], "deploymentArtifactHash")
    _positive_int(statement["approvalExpiresAt"], "approvalExpiresAt")


def verify_statement_against_records(
    statement: Mapping[str, Any],
    *,
    base_artifact: Mapping[str, Any],
    deployment_artifact: Mapping[str, Any],
    deployment_plan_hash: str,
    previous_amendment_hash: str = ZERO_HASH,
) -> None:
    """Bind a valid statement to the immutable genesis and EVM receipt records."""
    validate_statement_shape(statement)
    if statement["baseArtifactHash"] != base_artifact.get("artifactHash"):
        raise ValueError("base genesis artifact hash mismatch")
    ceremony = _mapping(base_artifact.get("ceremony"), "base ceremony")
    if statement["ceremonyId"] != ceremony.get("ceremonyId"):
        raise ValueError("base ceremony id mismatch")
    if statement["chiaNetwork"] != base_artifact.get("network"):
        raise ValueError("base Chia network mismatch")
    if statement["evmChainId"] != base_artifact.get("evmChainId"):
        raise ValueError("base EVM chain mismatch")
    if dict(statement["oldDeployment"]) != dict(base_artifact.get("evmAddresses", {})):
        raise ValueError("old deployment does not match genesis")
    if statement["chiaBridgePolicyHash"] != _mapping(
        base_artifact.get("permanentRules"), "permanentRules"
    ).get("zkPassportPolicyHash"):
        raise ValueError("Chia bridge policy hash changed")
    if statement["previousAmendmentHash"] != previous_amendment_hash:
        raise ValueError("amendment chain is not contiguous")

    expected_new = _new_deployment_from_artifact(deployment_artifact)
    if dict(statement["newDeployment"]) != expected_new:
        raise ValueError("new deployment does not match deployment evidence")
    if dict(statement["identityPolicy"]) != {
        **dict(deployment_artifact.get("identityPolicy", {})),
        "realDocumentOnly": True,
        "policyId": "0xb3337e7e06834b4f8189ad283a3105cf3be395473b6d7ac39c7a73d106b2aeb1",
    }:
        raise ValueError("identity policy does not match deployment evidence")
    _require_hex32(deployment_plan_hash, "deployment_plan_hash")
    if statement["deploymentPlanHash"] != deployment_plan_hash:
        raise ValueError("deployment plan hash mismatch")
    if statement["deploymentArtifactHash"] != deployment_artifact.get("artifactHash"):
        raise ValueError("deployment artifact hash mismatch")
    if dict(statement["deploymentSourceShas"]) != dict(deployment_artifact.get("sourceShas", {})):
        raise ValueError("deployment source SHAs do not match deployment evidence")


def _new_deployment_from_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    addresses = {
        "forwarder": artifact.get("forwarderAddress"),
        "verifierAdapter": artifact.get("verifierAdapterAddress"),
        "attestationEmitter": artifact.get("attestationEmitterAddress"),
    }
    transactions = {}
    for name, tx in _mapping(artifact.get("deploymentTransactions"), "deploymentTransactions").items():
        transactions[name] = {
            "hash": tx["hash"],
            "blockNumber": tx["blockNumber"],
            "blockHash": tx["blockHash"],
            "nonce": tx["nonce"],
            "initCodeHash": tx["initCodeHash"],
        }
    runtimes = dict(_mapping(artifact.get("runtimeCodeHashes"), "runtimeCodeHashes"))
    root_code_hash = runtimes.pop("zkPassportRootVerifier")
    return {
        "addresses": addresses,
        "transactions": transactions,
        "runtimeCodeHashes": runtimes,
        "rootVerifierAddress": artifact.get("zkPassportRootVerifierAddress"),
        "rootVerifierCodeHash": root_code_hash,
        "trustedDirectRelayer": artifact.get("trustedDirectRelayerAddress"),
        "immutableBindings": {
            "emitterVerifier": addresses["verifierAdapter"],
            "emitterForwarder": addresses["forwarder"],
            "emitterRelayer": artifact.get("trustedDirectRelayerAddress"),
            "adapterRootVerifier": artifact.get("zkPassportRootVerifierAddress"),
        },
        "acceptedProofVersions": ["0.20.0", "0.21.0"],
        "credentialPolicyVersion": artifact.get("credentialPolicyVersion"),
    }


def build_statement(
    *,
    base_artifact: Mapping[str, Any],
    deployment_artifact: Mapping[str, Any],
    deployment_plan_hash: str,
    activation_source_shas: Mapping[str, str],
    activation_boundary: Mapping[str, Any],
    revision: int,
    previous_amendment_hash: str,
    approval_expires_at: int,
) -> dict[str, Any]:
    policy = dict(_mapping(deployment_artifact.get("identityPolicy"), "identityPolicy"))
    policy.update(
        {
            "realDocumentOnly": True,
            "policyId": "0xb3337e7e06834b4f8189ad283a3105cf3be395473b6d7ac39c7a73d106b2aeb1",
        }
    )
    statement = {
        "schema": SCHEMA,
        "statementType": STATEMENT_TYPE,
        "revision": revision,
        "previousAmendmentHash": previous_amendment_hash,
        "baseArtifactHash": base_artifact["artifactHash"],
        "ceremonyId": base_artifact["ceremony"]["ceremonyId"],
        "chiaNetwork": base_artifact["network"],
        "evmChainId": base_artifact["evmChainId"],
        "oldDeployment": dict(base_artifact["evmAddresses"]),
        "newDeployment": _new_deployment_from_artifact(deployment_artifact),
        "identityPolicy": policy,
        "chiaBridgePolicyHash": base_artifact["permanentRules"]["zkPassportPolicyHash"],
        "activationBoundary": dict(activation_boundary),
        "deploymentSourceShas": dict(deployment_artifact["sourceShas"]),
        "activationSourceShas": dict(activation_source_shas),
        "deploymentPlanHash": deployment_plan_hash,
        "deploymentArtifactHash": deployment_artifact["artifactHash"],
        "approvalExpiresAt": approval_expires_at,
    }
    verify_statement_against_records(
        statement,
        base_artifact=base_artifact,
        deployment_artifact=deployment_artifact,
        deployment_plan_hash=deployment_plan_hash,
        previous_amendment_hash=previous_amendment_hash,
    )
    return statement


@dataclass(frozen=True)
class ConfirmedAmendmentAnchor:
    amendment_hash: str
    authority_launcher_id: str
    spent_authority_coin_id: str
    authority_version: int
    confirmed_height: int
    confirmed_timestamp: int
    announcement: bytes

    def verify(self, statement: Mapping[str, Any]) -> None:
        expected_hash = amendment_hash(statement)
        boundary = statement["activationBoundary"]
        if self.amendment_hash != expected_hash:
            raise ValueError("confirmed anchor amendment hash mismatch")
        if self.announcement != announcement_message(expected_hash):
            raise ValueError("confirmed anchor announcement mismatch")
        if self.authority_launcher_id != boundary["authorityLauncherId"]:
            raise ValueError("confirmed anchor authority launcher mismatch")
        if self.spent_authority_coin_id != boundary["authorityCoinId"]:
            raise ValueError("confirmed anchor authority coin mismatch")
        if self.authority_version != boundary["authorityVersion"]:
            raise ValueError("confirmed anchor authority version mismatch")
        _positive_int(self.confirmed_height, "confirmed_height")
        _positive_int(self.confirmed_timestamp, "confirmed_timestamp")
        if self.confirmed_timestamp > statement["approvalExpiresAt"]:
            raise ValueError("identity amendment was anchored after approval expiry")


def resolve_effective_identity_deployment(
    *,
    base_artifact: Mapping[str, Any],
    deployment_artifact: Mapping[str, Any],
    deployment_plan_hash: str,
    statement: Mapping[str, Any],
    anchor: ConfirmedAmendmentAnchor,
    previous_amendment_hash: str = ZERO_HASH,
) -> dict[str, Any]:
    verify_statement_against_records(
        statement,
        base_artifact=base_artifact,
        deployment_artifact=deployment_artifact,
        deployment_plan_hash=deployment_plan_hash,
        previous_amendment_hash=previous_amendment_hash,
    )
    anchor.verify(statement)
    return {
        "schema": "solslot.effective-identity-deployment.v1",
        "source": "confirmed-authority-amendment",
        "baseArtifactHash": statement["baseArtifactHash"],
        "amendmentHash": anchor.amendment_hash,
        "revision": statement["revision"],
        "confirmedHeight": anchor.confirmed_height,
        "evmChainId": statement["evmChainId"],
        "addresses": dict(statement["newDeployment"]["addresses"]),
        "acceptedProofVersions": list(statement["newDeployment"]["acceptedProofVersions"]),
        "credentialPolicyVersion": statement["newDeployment"]["credentialPolicyVersion"],
        "identityPolicy": dict(statement["identityPolicy"]),
        "chiaBridgePolicyHash": statement["chiaBridgePolicyHash"],
    }


__all__ = [
    "ANNOUNCEMENT_PREFIX",
    "ConfirmedAmendmentAnchor",
    "SCHEMA",
    "STATEMENT_TYPE",
    "ZERO_HASH",
    "amendment_hash",
    "announcement_message",
    "build_statement",
    "canonical_json",
    "parse_canonical_statement",
    "resolve_effective_identity_deployment",
    "validate_statement_shape",
    "verify_statement_against_records",
]
