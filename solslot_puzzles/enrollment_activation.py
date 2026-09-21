"""Signed, optional fresh-genesis selection for enrollment permit V1.

These functions validate content, never grant approval or verify committee
signatures. Runtime callers must authenticate the complete artifact first.
Omission preserves historical RC23 plans and projections exactly.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from chia_rs.sized_bytes import bytes32
from . import load_puzzle
from .enrollment_permit import EnrollmentPermitContext, MAX_PERMIT_SECONDS, ENROLLMENT_IDENTITY_CHAIN_IDS
from .enrollment_permit_driver import make_permit_bridge_puzzle
from .enrollment_networks import enrollment_operational_chain_id

SOURCE_NAMES = frozenset(('protocol','evm','omnichain','api','legacyBackend',
    'keyOfSolomon','samuel','customerWeb','adminPortal'))
KEY_REF_PATTERN = r'https://[a-z][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net/keys/[a-zA-Z0-9-]{1,127}/[0-9a-f]{32}'
IDENTITY_PATTERN = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def exact_hex(value: Any, length: int, field: str) -> bytes:
    if (not isinstance(value,str) or re.fullmatch(r'0x[0-9a-f]{'+str(2*length)+'}',value) is None
            or value=='0x'+'00'*length):
        raise ValueError(f'enrollment activation {field} must be canonical nonzero hex')
    return bytes.fromhex(value[2:])


def enrollment_release_identity(source_shas: Mapping[str, str]) -> str:
    if (not isinstance(source_shas,Mapping) or set(source_shas)!=SOURCE_NAMES
            or any(not isinstance(v,str) or re.fullmatch(r'[0-9a-f]{40}',v) is None
                   or v=='0'*40 for v in source_shas.values())):
        raise ValueError('enrollment activation requires exact nine nonzero source commits')
    encoded=json.dumps({'schema':'solslot.enrollment-release.v1','sourceShas':dict(source_shas)},
        sort_keys=True,separators=(',',':')).encode('ascii')
    return '0x'+hashlib.sha256(encoded).hexdigest()


def activation_context(value: Mapping[str, Any]) -> EnrollmentPermitContext:
    return EnrollmentPermitContext(environment=value['environment'],network=value['network'],
        evm_chain_id=value['evmChainId'],emitter=exact_hex(value['emitter'],20,'emitter'),
        issuer=exact_hex(value['issuer'],20,'issuer'),
        deployment_id=bytes32(exact_hex(value['deploymentId'],32,'deploymentId')),
        release_identity=bytes32(exact_hex(value['releaseIdentity'],32,'releaseIdentity')))


def validate_enrollment_activation(value: Any, *, source_shas: Mapping[str,str],
        ceremony_id: str, emitter: str, validator_pubkeys: Sequence[bytes],
        environment: str | None = None) -> dict[str, Any]:
    fields={'schema','environment','network','evmChainId','deploymentId','sourceShas',
        'releaseIdentity','emitter','issuer','issuerKeyRef','issuerIdentityClientId',
        'permitVersion','adapterVersion','validatorMessageVersion','bridgeModuleHash',
        'contextHash','bridgePolicyHash','permitLifetimeSeconds','reviewEvidenceSha256'}
    if not isinstance(value,Mapping) or set(value)!=fields:
        raise ValueError('enrollment activation evidence is missing or incomplete')
    enrollment_operational_chain_id(value)
    expected={'network':'testnet11',
        'deploymentId':ceremony_id,'sourceShas':dict(source_shas),
        'releaseIdentity':enrollment_release_identity(source_shas),'emitter':emitter,
        'permitVersion':1,'adapterVersion':1,'validatorMessageVersion':1,
        'bridgeModuleHash':'0x'+load_puzzle('zkpassport_bridge_permit_v1.clsp').get_tree_hash().hex()}
    if (any(value[k]!=v for k,v in expected.items())
            or any(type(value[k]) is not int for k in ('evmChainId','permitVersion','adapterVersion','validatorMessageVersion','permitLifetimeSeconds'))
            or value['evmChainId'] not in ENROLLMENT_IDENTITY_CHAIN_IDS
            or not 1<=value['permitLifetimeSeconds']<=MAX_PERMIT_SECONDS
            or value['environment'] not in ('staging-alpha','production-alpha')
            or (environment is not None and value['environment']!=environment)
            or not isinstance(value['reviewEvidenceSha256'],str)
            or re.fullmatch(r'[0-9a-f]{64}',value['reviewEvidenceSha256']) is None
            or value['reviewEvidenceSha256']=='0'*64
            or not isinstance(value['issuerKeyRef'],str)
            or re.fullmatch(KEY_REF_PATTERN,value['issuerKeyRef']) is None
            or not isinstance(value['issuerIdentityClientId'],str)
            or re.fullmatch(IDENTITY_PATTERN,value['issuerIdentityClientId']) is None
            or value['issuerIdentityClientId']=='00000000-0000-0000-0000-000000000000'):
        raise ValueError('enrollment activation differs from its reviewed deployment or release')
    context=activation_context(value)
    if (value['contextHash']!='0x'+context.context_hash.hex()
            or value['bridgePolicyHash']!='0x'+make_permit_bridge_puzzle(validator_pubkeys,context.context_hash).get_tree_hash().hex()):
        raise ValueError('enrollment activation context or bridge policy does not reconstruct')
    return json.loads(json.dumps(dict(value)))


def activation_from_artifact(artifact: Mapping[str,Any], *, environment: str | None = None,
        required: bool = False) -> dict[str,Any] | None:
    value=artifact.get('enrollmentActivation')
    plan=artifact.get('genesisPlan',{})
    if not isinstance(plan,Mapping):
        raise ValueError('enrollment activation genesis plan is malformed')
    if value is None and 'enrollmentActivation' not in artifact and 'enrollmentActivation' not in plan and not required:
        return None
    try:
        checked=validate_enrollment_activation(value,source_shas=artifact['sourceShas'],
            ceremony_id=artifact['ceremony']['ceremonyId'],emitter=artifact['evmAddresses']['attestationEmitter'],
            validator_pubkeys=[exact_hex(k,48,'validatorPubkey') for k in artifact['validatorSet']['pubkeys']],
            environment=environment)
        if (artifact['network']!='testnet11' or type(artifact['evmChainId']) is not int
                or artifact['evmChainId']!=enrollment_operational_chain_id(checked) or artifact['validatorSet']['threshold']!=2
                or checked!=plan.get('enrollmentActivation')
                or artifact['bridgePolicy']['policyHash']!=checked['bridgePolicyHash']
                or artifact['puzzleHashes']['bridgePolicy']!=checked['bridgePolicyHash']):
            raise ValueError('enrollment activation differs from the signed genesis projection')
    except (KeyError,TypeError,AttributeError) as exc:
        raise ValueError('enrollment activation artifact is incomplete') from exc
    return checked


def enrollment_identity_chain_id(artifact: Mapping[str, Any], *, environment: str | None = None) -> int:
    """Read the identity chain from authenticated artifact content, never config.

    V1 activation preserves the operational EIP-712 chain at 84532. Explicit V2
    selects Base mainnet for both operations and identity, with Chia Testnet11.
    Historical artifacts without activation retain Ethereum Sepolia exactly.
    This validates content only; callers must authenticate artifact signatures.
    """
    if not isinstance(artifact, Mapping):
        raise ValueError('enrollment identity artifact must be an object')
    activation = activation_from_artifact(artifact, environment=environment)
    if activation is not None:
        return activation['evmChainId']
    if (artifact.get('network') != 'testnet11'
            or type(artifact.get('evmChainId')) is not int
            or artifact['evmChainId'] != 11155111):
        raise ValueError('legacy enrollment identity requires the Testnet11 Ethereum Sepolia artifact')
    return 11155111
