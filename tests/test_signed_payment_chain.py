"""Payment-domain selection is signed without rewriting historical identity."""
from dataclasses import replace
from functools import partial

import pytest
from chia_rs.sized_bytes import bytes32
from solslot_puzzles.genesis_ceremony_rc23 import verify_rc23_genesis_ceremony_plan
from solslot_puzzles.artifact_schema_v4 import build_public_artifact, verify_public_artifact, artifact_hash
from solslot_puzzles.artifact_schema_v3 import INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS
from tests import test_genesis_ceremony_rc23 as fixtures
from tests.test_protocol_deployment import _FakeFaucet
from tests.test_artifact_schema_v4 import _signatures, _accept


def plan(monkeypatch, chain=None):
    faucet = _FakeFaucet()
    with monkeypatch.context() as patch:
        patch.setattr(fixtures, 'build_rc23_genesis_ceremony_plan',
                      partial(fixtures.build_rc23_genesis_ceremony_plan, payment_chain_id=chain))
        return fixtures.ceremony_plan(faucet, fixtures.funding_coins(faucet))


def artifact(p):
    return build_public_artifact(plan=p, spend_bundle_id=bytes32(b'\x91'*32),
        confirmed_block_index=1234, build_timestamp='2026-07-29T00:00:00+00:00',
        signatures=_signatures(0,2), review_class=INTERNAL_ENGINEERING_TESTNET_REVIEW_CLASS)


@pytest.mark.parametrize('chain', [8453, 84532])
def test_payment_chain_bound_in_plan_and_artifact_without_identity_change(monkeypatch, chain):
    old = plan(monkeypatch)
    new = plan(monkeypatch, chain)
    assert old.evm_chain_id == new.evm_chain_id == 11155111
    assert old.enrollment_activation == new.enrollment_activation is None
    assert old.admin_roster_hash == new.admin_roster_hash
    assert old.plan_hash != new.plan_hash
    assert 'paymentChainId' not in old.canonical_payload()
    assert 'paymentChainId' not in artifact(old)
    assert new.canonical_payload()['paymentChainId'] == chain
    value = artifact(new)
    assert value['paymentChainId'] == chain
    verify_public_artifact(value, signature_verifier=_accept)
    # Hash pinning detects an in-memory plan changed after approval.
    with pytest.raises(ValueError):
        verify_rc23_genesis_ceremony_plan(replace(new, payment_chain_id=84532 if chain == 8453 else 8453))


@pytest.mark.parametrize('chain', [True, '8453', 1, 11155111, 0])
def test_invalid_payment_domain_rejected(monkeypatch, chain):
    with pytest.raises(ValueError, match='payment chain'):
        plan(monkeypatch, chain)


@pytest.mark.parametrize('mutation', ['top', 'nested', 'remove_top', 'remove_nested'])
def test_rehashed_mismatching_artifact_rejected(monkeypatch, mutation):
    value = artifact(plan(monkeypatch, 8453))
    if mutation == 'top': value['paymentChainId'] = 84532
    if mutation == 'nested': value['genesisPlan']['paymentChainId'] = 84532
    if mutation == 'remove_top': del value['paymentChainId']
    if mutation == 'remove_nested': del value['genesisPlan']['paymentChainId']
    value['artifactHash'] = artifact_hash(value)
    with pytest.raises(ValueError):
        verify_public_artifact(value, signature_verifier=_accept)


def test_top_level_cannot_add_payment_domain_to_legacy_plan(monkeypatch):
    value = artifact(plan(monkeypatch))
    value['paymentChainId'] = 8453
    value['artifactHash'] = artifact_hash(value)
    with pytest.raises(ValueError, match='payment chain'):
        verify_public_artifact(value, signature_verifier=_accept)
