"""Synthetic review fixtures only. No fixture authorizes a live spend."""
import copy
from dataclasses import replace
import hashlib

import pytest

from .identity_amendment_fixtures import SYNTHETIC_PLAN_HASH, synthetic_identity_records

from solslot_puzzles import identity_network_amendment as network
from solslot_puzzles import identity_deployment_amendment as v1

def seal(record):
    record = {k: v for k, v in record.items() if k != 'artifactHash'}
    return {**record, 'artifactHash': '0x' + hashlib.sha256(v1.canonical_json(record)).hexdigest()}


@pytest.fixture
def records():
    base, old = synthetic_identity_records()
    old_plan = SYNTHETIC_PLAN_HASH
    boundary = {
        'authorityLauncherId': base['launcherIds']['adminAuthority'],
        'authorityCoinId': '0x' + 'aa' * 32, 'authorityVersion': 2,
        'rosterIdentityCoinIds': ['0x' + f'{i:02x}' * 32 for i in (1, 2, 3)],
        'signerSlots': [0, 1],
        'signerIdentityCoinIds': ['0x' + f'{i:02x}' * 32 for i in (1, 2)],
    }
    old_statement = v1.build_statement(
        base_artifact=base, deployment_artifact=old, deployment_plan_hash=old_plan,
        activation_source_shas={'protocol': '1' * 40, 'api': '2' * 40}, activation_boundary=boundary,
        revision=1, previous_amendment_hash=v1.ZERO_HASH, approval_expires_at=2_000_000_000,
    )
    old_hash = v1.amendment_hash(old_statement)
    predecessor = network.ConfirmedPredecessor(
        statement=old_statement, deployment_artifact=old, deployment_plan_hash=old_plan,
        anchor=v1.ConfirmedAmendmentAnchor(amendment_hash=old_hash,
            authority_launcher_id=boundary['authorityLauncherId'], spent_authority_coin_id=boundary['authorityCoinId'],
            authority_version=2, confirmed_height=4_800_000, confirmed_timestamp=1_999_999_800,
            announcement=v1.announcement_message(old_hash)),
    )
    new = copy.deepcopy(old)
    new.update(chainId=8453, network='base')
    for i, name in enumerate(['forwarder', 'verifierAdapter', 'attestationEmitter']):
        new[name + 'Address'] = '0x' + str(i + 4) * 40
        new['deploymentTransactions'][name]['hash'] = '0x' + str(i + 4) * 64
        new['deploymentTransactions'][name]['blockNumber'] = 52_000_000 + i
        new['deploymentTransactions'][name]['blockHash'] = '0x' + str(i + 7) * 64
    new = seal(new)
    new_boundary = copy.deepcopy(boundary)
    new_boundary.update(authorityCoinId='0x' + 'bb' * 32, authorityVersion=4)
    statement = network.build_statement(
        base_artifact=base, deployment_artifact=new, deployment_plan_hash='0x' + 'dd' * 32,
        activation_source_shas={'protocol': '3' * 40, 'api': '4' * 40},
        activation_boundary=new_boundary, approval_expires_at=2_000_000_200, predecessor=predecessor,
    )
    return base, new, predecessor, statement


def verify(records, statement=None, deployment=None, predecessor=None):
    base, new, prev, built = records
    return network.verify_statement_against_records(
        built if statement is None else statement, base_artifact=base,
        deployment_artifact=new if deployment is None else deployment,
        deployment_plan_hash='0x' + 'dd' * 32, predecessor=prev if predecessor is None else predecessor,
    )


def anchor_for(statement, predecessor):
    digest = network.amendment_hash(statement)
    boundary = statement['activationBoundary']
    return network.ConfirmedNetworkAnchor(amendment_hash=digest,
        authority_launcher_id=boundary['authorityLauncherId'], spent_authority_coin_id=boundary['authorityCoinId'],
        authority_version=boundary['authorityVersion'], confirmed_height=predecessor.anchor.confirmed_height + 10,
        confirmed_timestamp=2_000_000_100, announcement=network.announcement_message(digest))


def test_resolves_explicit_base_without_changing_genesis_or_v1(records):
    base, new, previous, statement = records
    original_base = copy.deepcopy(base)
    original_bytes = v1.canonical_json(previous.statement)
    original_hash = v1.amendment_hash(previous.statement)
    out = network.resolve_effective_identity_deployment(
        base_artifact=base, deployment_artifact=new, deployment_plan_hash='0x' + 'dd' * 32,
        statement=statement, predecessor=previous, anchor=anchor_for(statement, previous),
    )
    assert out['evmChainId'] == 8453 and out['revision'] == 2
    assert out['identityPolicy']['minimumAge'] == 18
    assert out['identityPolicy']['sanctions'] == {'countries': 'all', 'lists': 'all', 'strict': False}
    assert base == original_base and base['evmChainId'] == 11155111
    assert v1.canonical_json(previous.statement) == original_bytes
    assert v1.amendment_hash(previous.statement) == original_hash
    assert statement['oldDeployment'] == previous.statement['newDeployment']['addresses']
    assert statement['oldDeployment'] != base['evmAddresses']


@pytest.mark.parametrize('path,value', [
    (('evmChainId',), 1), (('previousEvmChainId',), 8453), (('chiaNetwork',), 'mainnet'),
    (('revision',), 3), (('revision',), True), (('previousAmendmentHash',), v1.ZERO_HASH),
    (('previousAmendmentHash',), '0x' + 'ee' * 32),
    (('baseArtifactHash',), '0x' + 'ee' * 32), (('ceremonyId',), '0x' + 'ee' * 32),
    (('oldDeployment', 'forwarder'), '0x' + '9' * 40),
    (('chiaBridgePolicyHash',), '0x' + 'ee' * 32),
    (('identityPolicy', 'minimumAge'), 0), (('identityPolicy', 'devMode'), True),
    (('identityPolicy', 'sanctions', 'countries'), 'none'),
    (('newDeployment', 'acceptedProofVersions'), ['0.21.0']),
    (('newDeployment', 'rootVerifierCodeHash'), '0x' + 'ee' * 32),
    (('newDeployment', 'transactions', 'forwarder', 'hash'), '0x' + 'ee' * 32),
    (('activationBoundary', 'authorityVersion'), 2),
    (('activationBoundary', 'authorityCoinId'), '0x' + 'aa' * 32),
    (('activationBoundary', 'authorityLauncherId'), '0x' + 'ee' * 32),
    (('deploymentArtifactHash',), '0x' + 'ee' * 32),
    (('deploymentPlanHash',), '0x' + 'ee' * 32),
    (('deploymentSourceShas', 'evm'), '5' * 40),
])
def test_altered_network_or_policy_fails_closed(records, path, value):
    changed = copy.deepcopy(records[3])
    cursor = changed
    for field in path[:-1]:
        cursor = cursor[field]
    cursor[path[-1]] = value
    with pytest.raises(ValueError):
        verify(records, statement=changed)


def test_extra_fields_and_v1_domain_rejected(records):
    changed = copy.deepcopy(records[3])
    changed['coordinatorApproved'] = True
    with pytest.raises(ValueError, match='fields mismatch'):
        network.amendment_hash(changed)
    with pytest.raises(ValueError, match='fields mismatch'):
        v1.amendment_hash(records[3])
    with pytest.raises(ValueError):
        network.amendment_hash(records[2].statement)


def test_owner_plus_one_still_required(records):
    changed = copy.deepcopy(records[3])
    changed['activationBoundary']['signerSlots'] = [1, 2]
    changed['activationBoundary']['signerIdentityCoinIds'] = changed['activationBoundary']['rosterIdentityCoinIds'][1:]
    with pytest.raises(ValueError, match='owner slot 0'):
        verify(records, statement=changed)


def test_receipt_network_and_content_hash_are_checked(records):
    changed = copy.deepcopy(records[1])
    changed['chainId'] = 11155111
    with pytest.raises(ValueError, match='content hash'):
        verify(records, deployment=changed)
    changed = seal(changed)
    with pytest.raises(ValueError, match='reviewed Base chain'):
        verify(records, deployment=changed)


def test_missing_or_replayed_predecessor_anchor_rejected(records):
    prev = records[2]
    with pytest.raises(ValueError, match='anchor amendment hash'):
        verify(records, predecessor=replace(prev, anchor=replace(prev.anchor, amendment_hash='0x' + 'ee' * 32)))
    with pytest.raises(ValueError, match='confirmed_height'):
        verify(records, predecessor=replace(prev, anchor=replace(prev.anchor, confirmed_height=0)))


def test_network_anchor_cannot_reuse_v1_message_or_predecessor_height(records):
    base, new, previous, statement = records
    anchor = anchor_for(statement, previous)
    with pytest.raises(ValueError, match='announcement'):
        replace(anchor, announcement=v1.announcement_message(anchor.amendment_hash)).verify(statement)
    with pytest.raises(ValueError, match='expiry'):
        replace(anchor, confirmed_timestamp=statement['approvalExpiresAt'] + 1).verify(statement)
    with pytest.raises(ValueError, match='does not follow predecessor'):
        network.resolve_effective_identity_deployment(
            base_artifact=base, deployment_artifact=new, deployment_plan_hash='0x' + 'dd' * 32,
            statement=statement, predecessor=previous,
            anchor=replace(anchor, confirmed_height=previous.anchor.confirmed_height),
        )
