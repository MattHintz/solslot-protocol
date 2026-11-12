"""R1: one explicit Testnet11/Sepolia-to-Base identity network transition.

This draft is not installed. V1 deployment amendment parsing and hashes remain
unchanged. Callers must independently verify the full authority/identity spend
history and deployment receipts before supplying these confirmed anchors.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from solslot_puzzles import identity_deployment_amendment as v1

SCHEMA = 'solslot.identity-network-amendment.v1'
STATEMENT_TYPE = 'SOLSLOT_IDENTITY_NETWORK_V1'
ANNOUNCEMENT_PREFIX = b'SOLSLOT_IDENTITY_NETWORK_V1:'
KEYS = v1._TOP_KEYS | {'previousEvmChainId'}
ROOT_VERIFIER = '0x1d000001000efd9a6371f4d90bb8920d5431c0d8'
ROOT_CODE_HASH = '0xd03ae3bc396b99a680f6af1d6b3a957f0f932f3763c20e311df5f676c0bfee5b'


def validate_statement_shape(statement: Mapping[str, Any]) -> None:
    v1._exact_keys(statement, KEYS, 'identity network amendment')
    if statement['schema'] != SCHEMA or statement['statementType'] != STATEMENT_TYPE:
        raise ValueError('unsupported identity network amendment schema')
    if (type(statement['revision']) is not int or statement['revision'] != 2 or
            type(statement['previousEvmChainId']) is not int or statement['previousEvmChainId'] != 11155111 or
            type(statement['evmChainId']) is not int or statement['evmChainId'] != 8453 or
            statement['chiaNetwork'] != 'testnet11'):
        raise ValueError('only revision-two Testnet11 Sepolia-to-Base transition is supported')
    projection = {k: v for k, v in statement.items() if k != 'previousEvmChainId'}
    projection.update(schema=v1.SCHEMA, statementType=v1.STATEMENT_TYPE)
    # Reuse closed V1 nested schemas, policy and owner-plus-one constraints.
    # Projection is used only for shape checking, never hashing or anchoring.
    v1.validate_statement_shape(projection)
    new = statement['newDeployment']
    if new['rootVerifierAddress'] != ROOT_VERIFIER or new['rootVerifierCodeHash'] != ROOT_CODE_HASH:
        raise ValueError('official production root verifier binding differs')


def amendment_hash(statement: Mapping[str, Any]) -> str:
    validate_statement_shape(statement)
    return '0x' + hashlib.sha256(v1.canonical_json(statement)).hexdigest()


def parse_canonical_statement(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('identity network amendment must be an object')
    validate_statement_shape(value)
    if raw != v1.canonical_json(value):
        raise ValueError('identity network amendment is not canonical JSON')
    return value


def announcement_message(digest: str) -> bytes:
    v1._require_hex32(digest, 'network amendment digest')
    return ANNOUNCEMENT_PREFIX + bytes.fromhex(digest[2:])


def _verify_deployment_hash(record: Mapping[str, Any]) -> None:
    claimed = v1._require_hex32(record.get('artifactHash'), 'deployment artifact hash')
    body = {k: v for k, v in record.items() if k != 'artifactHash'}
    if claimed != '0x' + hashlib.sha256(v1.canonical_json(body)).hexdigest():
        raise ValueError('deployment artifact content hash differs')


@dataclass(frozen=True)
class ConfirmedPredecessor:
    statement: Mapping[str, Any]
    deployment_artifact: Mapping[str, Any]
    deployment_plan_hash: str
    anchor: v1.ConfirmedAmendmentAnchor

    def verify(self, base_artifact: Mapping[str, Any]) -> None:
        if (type(self.statement.get('revision')) is not int or self.statement['revision'] != 1 or
                self.statement.get('evmChainId') != 11155111 or
                self.deployment_artifact.get('chainId') != 11155111):
            raise ValueError('confirmed predecessor must be revision one on Sepolia')
        _verify_deployment_hash(self.deployment_artifact)
        v1.verify_statement_against_records(
            self.statement, base_artifact=base_artifact,
            deployment_artifact=self.deployment_artifact,
            deployment_plan_hash=self.deployment_plan_hash,
            previous_amendment_hash=v1.ZERO_HASH,
        )
        self.anchor.verify(self.statement)
        if self.statement['activationBoundary']['authorityLauncherId'] != base_artifact['launcherIds']['adminAuthority']:
            raise ValueError('predecessor authority launcher differs from genesis')


def verify_statement_against_records(
    statement: Mapping[str, Any], *, base_artifact: Mapping[str, Any],
    deployment_artifact: Mapping[str, Any], deployment_plan_hash: str,
    predecessor: ConfirmedPredecessor,
) -> None:
    predecessor.verify(base_artifact)
    verify_prepared_statement_against_records(statement, base_artifact=base_artifact,
        deployment_artifact=deployment_artifact, deployment_plan_hash=deployment_plan_hash,
        predecessor_statement=predecessor.statement,
        predecessor_deployment_artifact=predecessor.deployment_artifact,
        predecessor_deployment_plan_hash=predecessor.deployment_plan_hash)


def verify_prepared_statement_against_records(
    statement: Mapping[str, Any], *, base_artifact: Mapping[str, Any],
    deployment_artifact: Mapping[str, Any], deployment_plan_hash: str,
    predecessor_statement: Mapping[str, Any],
    predecessor_deployment_artifact: Mapping[str, Any], predecessor_deployment_plan_hash: str,
) -> None:
    """Validate staged records only; this function never establishes activation."""
    validate_statement_shape(statement)
    previous = predecessor_statement
    if previous.get('revision') != 1 or previous.get('evmChainId') != 11155111:
        raise ValueError('prepared predecessor must be revision one on Sepolia')
    if type(predecessor_deployment_artifact.get('chainId')) is not int or predecessor_deployment_artifact['chainId'] != 11155111:
        raise ValueError('prepared predecessor deployment must be on Sepolia')
    _verify_deployment_hash(predecessor_deployment_artifact)
    v1.verify_statement_against_records(previous, base_artifact=base_artifact,
        deployment_artifact=predecessor_deployment_artifact,
        deployment_plan_hash=predecessor_deployment_plan_hash, previous_amendment_hash=v1.ZERO_HASH)
    if statement['previousAmendmentHash'] != v1.amendment_hash(previous):
        raise ValueError('network amendment predecessor hash differs')
    for field, expected in (
        ('baseArtifactHash', base_artifact['artifactHash']),
        ('ceremonyId', base_artifact['ceremony']['ceremonyId']),
        ('chiaNetwork', base_artifact['network']),
        ('chiaBridgePolicyHash', base_artifact['permanentRules']['zkPassportPolicyHash']),
        ('previousEvmChainId', previous['evmChainId']),
        ('oldDeployment', previous['newDeployment']['addresses']),
        ('identityPolicy', previous['identityPolicy']),
    ):
        if statement[field] != expected:
            raise ValueError('network amendment ' + field + ' binding differs')
    if statement['activationBoundary']['authorityLauncherId'] != base_artifact['launcherIds']['adminAuthority']:
        raise ValueError('network amendment authority launcher differs from genesis')
    if statement['activationBoundary']['authorityVersion'] <= previous['activationBoundary']['authorityVersion']:
        raise ValueError('network amendment authority version does not advance')
    if statement['activationBoundary']['authorityCoinId'] == previous['activationBoundary']['authorityCoinId']:
        raise ValueError('network amendment reuses the spent predecessor authority coin')
    _verify_deployment_hash(deployment_artifact)
    if type(deployment_artifact.get('chainId')) is not int or deployment_artifact['chainId'] != statement['evmChainId']:
        raise ValueError('new deployment receipt is not on reviewed Base chain')
    if dict(statement['newDeployment']) != v1._new_deployment_from_artifact(deployment_artifact):
        raise ValueError('new network deployment does not match receipt evidence')
    expected_policy = {**dict(deployment_artifact.get('identityPolicy', {})),
                       'realDocumentOnly': True, 'policyId': previous['identityPolicy']['policyId']}
    if dict(statement['identityPolicy']) != expected_policy:
        raise ValueError('network amendment policy does not match deployment evidence')
    v1._require_hex32(deployment_plan_hash, 'deployment plan hash')
    if (statement['deploymentPlanHash'] != deployment_plan_hash or
            statement['deploymentArtifactHash'] != deployment_artifact['artifactHash'] or
            dict(statement['deploymentSourceShas']) != dict(deployment_artifact.get('sourceShas', {}))):
        raise ValueError('network amendment deployment hash/source binding differs')


def build_statement(*, base_artifact: Mapping[str, Any], deployment_artifact: Mapping[str, Any],
                    deployment_plan_hash: str, activation_source_shas: Mapping[str, str],
                    activation_boundary: Mapping[str, Any], approval_expires_at: int,
                    predecessor: ConfirmedPredecessor) -> dict[str, Any]:
    predecessor.verify(base_artifact)
    previous = predecessor.statement
    statement = {
        'schema': SCHEMA, 'statementType': STATEMENT_TYPE, 'revision': 2,
        'previousAmendmentHash': predecessor.anchor.amendment_hash,
        'baseArtifactHash': base_artifact['artifactHash'],
        'ceremonyId': base_artifact['ceremony']['ceremonyId'],
        'chiaNetwork': base_artifact['network'],
        'previousEvmChainId': previous['evmChainId'], 'evmChainId': 8453,
        'oldDeployment': dict(previous['newDeployment']['addresses']),
        'newDeployment': v1._new_deployment_from_artifact(deployment_artifact),
        'identityPolicy': dict(previous['identityPolicy']),
        'chiaBridgePolicyHash': base_artifact['permanentRules']['zkPassportPolicyHash'],
        'activationBoundary': dict(activation_boundary),
        'deploymentSourceShas': dict(deployment_artifact['sourceShas']),
        'activationSourceShas': dict(activation_source_shas),
        'deploymentPlanHash': deployment_plan_hash,
        'deploymentArtifactHash': deployment_artifact['artifactHash'],
        'approvalExpiresAt': approval_expires_at,
    }
    verify_statement_against_records(statement, base_artifact=base_artifact,
                                    deployment_artifact=deployment_artifact,
                                    deployment_plan_hash=deployment_plan_hash, predecessor=predecessor)
    return statement


@dataclass(frozen=True)
class ConfirmedNetworkAnchor(v1.ConfirmedAmendmentAnchor):
    def verify(self, statement: Mapping[str, Any]) -> None:
        digest = amendment_hash(statement)
        boundary = statement['activationBoundary']
        if self.amendment_hash != digest or self.announcement != announcement_message(digest):
            raise ValueError('confirmed network anchor digest or announcement differs')
        if (self.authority_launcher_id != boundary['authorityLauncherId'] or
                self.spent_authority_coin_id != boundary['authorityCoinId'] or
                self.authority_version != boundary['authorityVersion']):
            raise ValueError('confirmed network anchor authority boundary differs')
        v1._positive_int(self.confirmed_height, 'confirmed network height')
        v1._positive_int(self.confirmed_timestamp, 'confirmed network timestamp')
        if self.confirmed_timestamp > statement['approvalExpiresAt']:
            raise ValueError('network amendment anchored after approval expiry')


def resolve_effective_identity_deployment(*, base_artifact: Mapping[str, Any],
                                        deployment_artifact: Mapping[str, Any],
                                        deployment_plan_hash: str, statement: Mapping[str, Any],
                                        predecessor: ConfirmedPredecessor,
                                        anchor: ConfirmedNetworkAnchor) -> dict[str, Any]:
    verify_statement_against_records(statement, base_artifact=base_artifact,
                                    deployment_artifact=deployment_artifact,
                                    deployment_plan_hash=deployment_plan_hash, predecessor=predecessor)
    anchor.verify(statement)
    if anchor.confirmed_height <= predecessor.anchor.confirmed_height:
        raise ValueError('network amendment anchor does not follow predecessor')
    return {
        'schema': 'solslot.effective-identity-deployment.v1',
        'source': 'confirmed-authority-amendment',
        'baseArtifactHash': statement['baseArtifactHash'], 'amendmentHash': anchor.amendment_hash,
        'revision': 2, 'confirmedHeight': anchor.confirmed_height, 'evmChainId': 8453,
        'addresses': dict(statement['newDeployment']['addresses']),
        'acceptedProofVersions': list(statement['newDeployment']['acceptedProofVersions']),
        'credentialPolicyVersion': 2, 'identityPolicy': dict(statement['identityPolicy']),
        'chiaBridgePolicyHash': statement['chiaBridgePolicyHash'],
    }
