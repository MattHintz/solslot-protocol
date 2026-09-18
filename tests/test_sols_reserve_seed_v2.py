"""Fresh Sols reserve hashes must correspond to the actual CAT reveal."""
import copy
import inspect
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from solslot_puzzles.artifact_schema_v4 import _rebuild_plan, artifact_hash, build_public_artifact, verify_public_artifact
from solslot_puzzles.genesis_ceremony_rc23 import build_rc23_genesis_ceremony_plan
from tests.test_artifact_schema_v4 import _artifact, _accept


def rebuilt(version):
    value = _artifact()
    value['genesisPlan']['solsReserveSeed']['version'] = version
    inner = Program.to((1, []))
    value['genesisPlan']['trustedDestinations']['treasuryReservePuzzleHash'] = '0x'+inner.get_tree_hash().hex()
    return _rebuild_plan(value), inner


def public(plan):
    original = _artifact()
    return build_public_artifact(plan=plan, spend_bundle_id=original['ceremony']['spendBundleId'],
        confirmed_block_index=1234,build_timestamp=original['buildTimestamp'],
        signatures=original['signatures'],review_class=original['reviewClass'])


def test_new_genesis_defaults_to_spendable_cat_seed_and_roundtrips():
    assert inspect.signature(build_rc23_genesis_ceremony_plan).parameters['sols_reserve_seed_version'].default == 2
    plan, inner = rebuilt(2)
    expected = construct_cat_puzzle(CAT_MOD, plan.protocol.sols_tail_hash, inner).get_tree_hash()
    assert plan.protocol.sols_reserve_seed_puzzle_hash == expected
    assert plan.canonical_payload()['solsReserveSeed']['version'] == 2
    value = public(plan)
    verify_public_artifact(value, signature_verifier=_accept)
    assert _rebuild_plan(value).canonical_payload() == plan.canonical_payload()
    # A re-signed version substitution cannot reinterpret the committed seed.
    for version in (1, None, True, 0, 3, '2'):
        changed = copy.deepcopy(value)
        changed['genesisPlan']['solsReserveSeed']['version'] = version
        changed['artifactHash'] = artifact_hash(changed)
        with pytest.raises(ValueError):
            verify_public_artifact(changed, signature_verifier=_accept)


def test_historical_seed_and_artifact_remain_reconstructible_without_rewrite():
    value = _artifact()
    original = copy.deepcopy(value)
    assert 'version' not in value['genesisPlan']['solsReserveSeed']
    verify_public_artifact(value, signature_verifier=_accept)
    assert value == original
    old, inner = rebuilt(1)
    new, _ = rebuilt(2)
    assert old.protocol.sols_reserve_seed_puzzle_hash != construct_cat_puzzle(CAT_MOD, old.protocol.sols_tail_hash, inner).get_tree_hash()
    assert old.protocol.sols_reserve_seed_coin_id != new.protocol.sols_reserve_seed_coin_id
    assert old.plan_hash != new.plan_hash
    assert 'version' not in old.canonical_payload()['solsReserveSeed']


@pytest.mark.parametrize('invalid',[None,[],False,'invalid'])
def test_malformed_seed_is_rejected(invalid):
    value = _artifact()
    value['genesisPlan']['solsReserveSeed'] = invalid
    value['artifactHash'] = artifact_hash(value)
    with pytest.raises(ValueError):
        verify_public_artifact(value, signature_verifier=_accept)


def test_pool_eve_lineage_requires_exact_launcher_and_cat_lineage_stays_strict():
    from chia.types.blockchain_format.coin import Coin
    from chia.wallet.lineage_proof import LineageProof
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
    from chia_rs.sized_bytes import bytes32
    from solslot_puzzles.sols_swap_v4_driver import _pool_lineage, _complete_lineage, SolsSwapOfferError
    parent = bytes32(b'p'*32)
    launcher = Coin(parent, SINGLETON_LAUNCHER_HASH, 1)
    coin = Coin(launcher.name(), bytes32(b'c'*32), 1)
    proof = LineageProof(parent_name=parent, amount=1)
    _pool_lineage(proof, coin, launcher.name())
    for forged in (LineageProof(), LineageProof(parent_name=parent,amount=3),
                   LineageProof(parent_name=bytes32(b'x'*32),amount=1)):
        with pytest.raises(SolsSwapOfferError):
            _pool_lineage(forged,coin,launcher.name())
    with pytest.raises(SolsSwapOfferError):
        _pool_lineage(proof,Coin(bytes32(b'x'*32),coin.puzzle_hash,1),launcher.name())
    with pytest.raises(SolsSwapOfferError):
        _complete_lineage(proof,'Sols payment coin')
