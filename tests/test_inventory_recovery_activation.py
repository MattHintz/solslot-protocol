"""An optional independently signed recovery gate cannot change legacy artifacts."""
import copy
import pytest
from solslot_puzzles.inventory_activation import validate_inventory_recovery
from solslot_puzzles.artifact_schema_v4 import artifact_hash, verify_public_artifact
from tests.test_artifact_schema_v4 import _artifact, _accept
from tests.test_inventory_mint_activation import activation


def recovery(artifact):
    a=artifact['inventoryActivation']
    return dict(schema='solslot.inventory-recovery.v1',network='testnet11',environment=a['environment'],
        deploymentId=a['deploymentId'],inventoryVersion=2,adapterVersion=1,validatorLedgerVersion=10,minConfirmations=3,
        availableModuleHash=a['availableModuleHash'],sourceShas=copy.deepcopy(artifact['sourceShas']),
        reviewEvidenceSha256='cd'*32,historicalArtifactHashes=[])


def test_recovery_extension_is_optional_and_changes_the_signed_hash():
    a=_artifact(); original=copy.deepcopy(a)
    assert validate_inventory_recovery(a) is None
    with pytest.raises(ValueError): validate_inventory_recovery(a,required=True)
    a['inventoryActivation']=activation(a);a['inventoryRecovery']=recovery(a)
    with pytest.raises(ValueError,match='artifactHash'): verify_public_artifact(a,signature_verifier=_accept)
    a['artifactHash']=artifact_hash(a)
    verify_public_artifact(a,signature_verifier=_accept)  # synthetic verifier is not release approval
    assert a['puzzleHashes']==original['puzzleHashes'] and a['genesisPlan']==original['genesisPlan']
    with pytest.raises(ValueError): validate_inventory_recovery(a,environment='production-alpha')


@pytest.mark.parametrize('field,value',[
    ('network','mainnet'),('environment','production-beta'),('deploymentId','wrong'),('inventoryVersion',1),
    ('adapterVersion',True),('validatorLedgerVersion',9),('validatorLedgerVersion',True),('minConfirmations',2),
    ('minConfirmations',True),('availableModuleHash','0x'+'00'*32),('sourceShas',{}),('reviewEvidenceSha256','00'*32),
    ('historicalArtifactHashes',['0x'+'00'*32]),('historicalArtifactHashes',['0x'+'ab'*32]*2),
    ('historicalArtifactHashes','0x'+'ab'*32),('historicalArtifactHashes',['0x'+'AB'*32]),
    ('historicalArtifactHashes',['0x'+f'{n:064x}' for n in range(1,34)])])
def test_recovery_rejects_mismatched_or_incomplete_evidence(field,value):
    a=_artifact();a['inventoryActivation']=activation(a);a['inventoryRecovery']=recovery(a)
    a['inventoryRecovery'][field]=value;a['artifactHash']=artifact_hash(a)
    with pytest.raises(ValueError,match='recovery'): verify_public_artifact(a,signature_verifier=_accept)
