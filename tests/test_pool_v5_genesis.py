"""New pool selection is explicit and old signed plans remain unchanged."""
import copy
import inspect
import hashlib
import json
from pathlib import Path
import pytest
from solslot_puzzles.artifact_schema_v4 import _rebuild_plan,artifact_hash,verify_public_artifact
from solslot_puzzles.genesis_ceremony_rc23 import build_rc23_genesis_ceremony_plan
from tests.test_artifact_schema_v4 import _artifact,_accept
from tests.test_sols_reserve_seed_v2 import public


def test_pool_v5_manifest_appends_to_the_unchanged_historical_inventory():
    from solslot_puzzles import FROZEN_CHECKSUM,PUZZLE_FILENAMES,load_puzzle
    root=Path(__file__).resolve().parents[1]
    previous=json.loads((root/'release-manifests/alpha-draft46-puzzle-hashes.json').read_text())
    current=json.loads((root/'release-manifests/alpha-draft56-pool-v5-puzzle-hashes.json').read_text())
    assert current['deployable'] is False and current['replacements']==[]
    assert current['canonicalChecksum']==FROZEN_CHECKSUM
    assert current['preservedCanonicalChecksum']==previous['canonicalChecksum']
    assert tuple(current['puzzleHashes'])==PUZZLE_FILENAMES
    assert {name:value for name,value in current['puzzleHashes'].items() if name in previous['puzzleHashes']}==previous['puzzleHashes']
    for name,value in current['puzzleHashes'].items():
        assert load_puzzle(name).get_tree_hash().hex()==value
    [row]=current['additions']
    assert row['filename']=='pool_singleton_inner_v5.clsp'
    for suffix,field in [('', 'sourceSha256'),('.hex','hexSha256')]:
        assert hashlib.sha256((root/'solslot_puzzles'/(row['filename']+suffix)).read_bytes()).hexdigest()==row[field]


def test_pool_v5_is_explicit_and_roundtrips_without_reinterpreting_v4():
    assert inspect.signature(build_rc23_genesis_ceremony_plan).parameters['pool_puzzle_version'].default==5
    old=_artifact()
    original=copy.deepcopy(old)
    assert 'poolPuzzleVersion' not in old['genesisPlan']
    assert _rebuild_plan(old).protocol.pool_puzzle_version==4
    verify_public_artifact(old,signature_verifier=_accept)
    assert old==original
    selected=copy.deepcopy(old)
    selected['genesisPlan']['poolPuzzleVersion']=5
    plan=_rebuild_plan(selected)
    value=public(plan)
    assert value['genesisPlan']['poolPuzzleVersion']==5
    assert plan.plan_hash!=_rebuild_plan(old).plan_hash
    verify_public_artifact(value,signature_verifier=_accept)
    assert _rebuild_plan(value).canonical_payload()==plan.canonical_payload()
    for invalid in (4,None,True,0,6,'5'):
        changed=copy.deepcopy(value)
        changed['genesisPlan']['poolPuzzleVersion']=invalid
        changed['artifactHash']=artifact_hash(changed)
        with pytest.raises(ValueError):
            verify_public_artifact(changed,signature_verifier=_accept)
