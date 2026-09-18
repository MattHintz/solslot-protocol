import copy
import hashlib
import json
import pytest
from solslot_puzzles import load_puzzle
from solslot_puzzles.artifact_schema_v4 import _rebuild_plan,artifact_hash,build_public_artifact,verify_public_artifact
from solslot_puzzles.enrollment_activation import activation_context,activation_from_artifact,enrollment_release_identity,validate_enrollment_activation
from solslot_puzzles.enrollment_permit_driver import make_permit_bridge_puzzle
from tests.test_artifact_schema_v4 import _artifact,_accept


def activation(artifact=None,environment='staging-alpha'):
    artifact=artifact or _artifact()
    value=dict(schema='solslot.enrollment-activation.v1',environment=environment,network='testnet11',evmChainId=84532,
        deploymentId=artifact['ceremony']['ceremonyId'],sourceShas=copy.deepcopy(artifact['sourceShas']),
        releaseIdentity=enrollment_release_identity(artifact['sourceShas']),emitter=artifact['evmAddresses']['attestationEmitter'],
        issuer='0x7e5f4552091a69125d5dfcb7b8c2659029395bdf',issuerKeyRef='https://solslot-test.vault.azure.net/keys/permit-test/'+'ab'*16,
        issuerIdentityClientId='12345678-1234-1234-1234-123456789abc',permitVersion=1,adapterVersion=1,validatorMessageVersion=1,
        bridgeModuleHash='0x'+load_puzzle('zkpassport_bridge_permit_v1.clsp').get_tree_hash().hex(),
        permitLifetimeSeconds=900,reviewEvidenceSha256='cd'*32)
    context=activation_context(value)
    value['contextHash']='0x'+context.context_hash.hex()
    value['bridgePolicyHash']='0x'+make_permit_bridge_puzzle([bytes.fromhex(k[2:]) for k in artifact['validatorSet']['pubkeys']],context.context_hash).get_tree_hash().hex()
    return value


def selected_artifact(environment='staging-alpha'):
    original=_artifact();plan=copy.deepcopy(original['genesisPlan']);plan['enrollmentActivation']=activation(original,environment);plan['evmChainId']=84532
    rebuilt=_rebuild_plan({'genesisPlan':plan})
    return build_public_artifact(plan=rebuilt,spend_bundle_id=original['ceremony']['spendBundleId'],
        confirmed_block_index=1234,build_timestamp=original['buildTimestamp'],signatures=original['signatures'],review_class=original['reviewClass'])


def test_historical_omitted_activation_bytes_and_unknown_block_rejected():
    value=_artifact()
    # Historical V4 signed bytes predate the redundant treasury projection.
    # Preserve their pinned hash and verify without rewriting that evidence.
    del value['puzzleHashes']['protocolTreasuryPuzzleHash']
    value['artifactHash']=artifact_hash(value)
    verify_public_artifact(value,signature_verifier=_accept)
    assert hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()=='01b6517e4cc091858ec184947f752b274fd7d4e97248f171577219d4f1279786'
    assert activation_from_artifact(value) is None
    for bad in [None,{},dict(schema='solslot.enrollment-activation.v1',network='mainnet')]:
        changed=copy.deepcopy(value);changed['enrollmentActivation']=bad;changed['artifactHash']=artifact_hash(changed)
        with pytest.raises(ValueError,match='activation'):verify_public_artifact(changed,signature_verifier=_accept)


def test_selected_policy_changes_fresh_vault_and_every_bridge_coin_but_preserves_legacy_sources():
    old=_artifact();value=selected_artifact();verify_public_artifact(value,signature_verifier=_accept)
    active=activation_from_artifact(value,environment='staging-alpha')
    assert active==value['genesisPlan']['enrollmentActivation']
    assert value['puzzleHashes']['bridgePolicy']==active['bridgePolicyHash']!=old['puzzleHashes']['bridgePolicy']
    assert value['canonicalVaultParamsHash']!=old['canonicalVaultParamsHash']
    assert not set(value['bridgePolicy']['bridgeCoinIds'])&set(old['bridgePolicy']['bridgeCoinIds'])
    assert value['sourceShas']==old['sourceShas']
    production=selected_artifact('production-alpha')
    assert production['canonicalVaultParamsHash']!=value['canonicalVaultParamsHash']
    with pytest.raises(ValueError):activation_from_artifact(value,environment='production-alpha')


@pytest.mark.parametrize('field,bad',[
    ('environment','production-beta'),('network','mainnet'),('evmChainId',True),('evmChainId',1),
    ('deploymentId','0x'+'00'*32),('sourceShas',{}),('releaseIdentity','0x'+'ee'*32),
    ('emitter','0x'+'ef'*20),('issuer','0x'+'00'*20),('issuerKeyRef','https://evil.test/keys/key/version'),
    ('issuerKeyRef','https://solslot-test.vault.azure.net/keys/permit-test'),('issuerIdentityClientId',''),
    ('permitVersion',True),('adapterVersion',2),('validatorMessageVersion',2),
    ('bridgeModuleHash','0x'+'12'*32),('contextHash','0x'+'13'*32),('bridgePolicyHash','0x'+'14'*32),
    ('permitLifetimeSeconds',True),('permitLifetimeSeconds',0),('permitLifetimeSeconds',3601),
    ('reviewEvidenceSha256','00'*32)])
def test_mismatched_activation_rejected_even_when_resigned(field,bad):
    value=selected_artifact();value['enrollmentActivation'][field]=bad
    value['genesisPlan']['enrollmentActivation'][field]=bad
    value['artifactHash']=artifact_hash(value)
    with pytest.raises(ValueError):verify_public_artifact(value,signature_verifier=_accept)


def test_activation_missing_from_one_projection_is_not_a_legacy_fallback():
    for field in ('enrollmentActivation','genesisPlan'):
        value=selected_artifact()
        if field=='genesisPlan':del value[field]['enrollmentActivation']
        else:del value[field]
        value['artifactHash']=artifact_hash(value)
        with pytest.raises(ValueError):verify_public_artifact(value,signature_verifier=_accept)

@pytest.mark.parametrize('plan',[None,[],False,'invalid'])
def test_malformed_plan_is_rejected_without_legacy_fallback(plan):
    with pytest.raises(ValueError):activation_from_artifact({'genesisPlan':plan})

def test_permit_wire_and_native_owner_enum_cannot_be_reinterpreted():
    from chia_rs.sized_bytes import bytes32
    from solslot_puzzles.enrollment_permit import EnrollmentPermit,permit_owner_from_native
    permit=EnrollmentPermit(*(bytes32(bytes([i])*32) for i in range(1,5)),2,bytes32(b'o'*32),bytes32(b'b'*32),1,901)
    wire=permit.to_wire();assert EnrollmentPermit.from_wire(wire)==permit
    for field,value in [('ownerAuthType',True),('issuedAt',True),('permitHash','0x'+'aa'*32),('vaultLauncherId','0X'+'aa'*32),('currentVaultCoinId','0x'+'00'*32)]:
        with pytest.raises(ValueError):EnrollmentPermit.from_wire({**wire,field:value})
    with pytest.raises(ValueError):EnrollmentPermit.from_wire({**wire,'extra':'bad'})
    assert permit_owner_from_native(1,b'a'*48)[0]==1
    assert permit_owner_from_native(3,b'a'*20)[0]==2
    for native,key in [(2,b'a'*20),(True,b'a'*48),(3,b'a'*33),(1,b'a'*20)]:
        with pytest.raises(ValueError):permit_owner_from_native(native,key)
