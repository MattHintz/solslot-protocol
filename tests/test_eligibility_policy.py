import copy
from dataclasses import replace
from functools import partial
import pytest
from solslot_puzzles.eligibility_policy import ELIGIBILITY_POLICY, require_eligibility_inputs
from solslot_puzzles.genesis_ceremony_rc23 import verify_rc23_genesis_ceremony_plan
from solslot_puzzles.artifact_schema_v4 import verify_public_artifact, artifact_hash
from tests import test_genesis_ceremony_rc23 as fixtures
from tests.test_protocol_deployment import _FakeFaucet
from tests.test_signed_payment_chain import artifact
from tests.test_artifact_schema_v4 import _accept


def new_plan(monkeypatch, policy):
    faucet = _FakeFaucet()
    with monkeypatch.context() as patch:
        patch.setattr(fixtures, 'build_rc23_genesis_ceremony_plan',
            partial(fixtures.build_rc23_genesis_ceremony_plan, identity_policy=policy, payment_chain_id=8453))
        return fixtures.ceremony_plan(faucet, fixtures.funding_coins(faucet))


def test_policy_is_part_of_the_signed_plan_and_artifact(monkeypatch):
    old = new_plan(monkeypatch, None)
    new = new_plan(monkeypatch, ELIGIBILITY_POLICY)
    assert old.plan_hash != new.plan_hash
    assert 'identityPolicy' not in artifact(old)
    value = artifact(new)
    assert value['identityPolicy'] == value['genesisPlan']['identityPolicy'] == ELIGIBILITY_POLICY
    verify_public_artifact(value, signature_verifier=_accept)
    with pytest.raises(ValueError):
        verify_rc23_genesis_ceremony_plan(replace(new, identity_policy=None))


@pytest.mark.parametrize('mutation', ['remove_top','remove_nested','dev','strict','extra'])
def test_policy_cannot_be_removed_relabelled_or_weakened(monkeypatch, mutation):
    value = artifact(new_plan(monkeypatch, ELIGIBILITY_POLICY))
    if mutation == 'remove_top': del value['identityPolicy']
    if mutation == 'remove_nested': del value['genesisPlan']['identityPolicy']
    if mutation == 'dev': value['identityPolicy']['devMode'] = True
    if mutation == 'strict': value['identityPolicy']['sanctions']['strict'] = True
    if mutation == 'extra': value['identityPolicy']['discloseName'] = True
    value['artifactHash'] = artifact_hash(value)
    with pytest.raises(ValueError): verify_public_artifact(value, signature_verifier=_accept)


def test_exact_predicates_admit_both_orders_and_reject_age_only_or_disclosures():
    age=bytes.fromhex('0100021200');sanctions=bytes.fromhex('090021')+bytes([9])*32+b'\x00'
    for value in (age+sanctions,sanctions+age):require_eligibility_inputs(value)
    for value in (age, sanctions, age+age, age+sanctions+b'\x00', age+sanctions[:-1]+b'\x01',
                  age+bytes.fromhex('080021')+bytes([9])*32+b'\x00'):
        with pytest.raises(ValueError):require_eligibility_inputs(value)
