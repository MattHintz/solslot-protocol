"""Native exchange uses the new governed facts and its actual pause registry.

Settlement witnesses are synthetic; holder-ratified fact/upgrade transitions
and primary reconstruction are tested in their separate native/API suites.
"""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH,launch_conditions_and_coinsol
from chia_rs import Coin,G2Element,SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_registry import Registry
from solslot_puzzles.generation_statutes import GenerationStatutes
from solslot_puzzles.generation_statutes_settlement import GenerationStatutesSource
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.protocol_statutes_v1 import keyed_root
from solslot_puzzles.sols_swap_v4_driver import (build_deed_to_sols_protocol_offer,
    build_sols_to_deed_protocol_offer,prepare_vault_sols_buyer_offer,aggregate_sols_to_deed_swap)
from tests.test_sols_swap_v4_driver import (CONFIG,COLLECTION,EMPTY_POOL,STATUTES_LAUNCHER,VAULT_LAUNCHER,
    _fixture,_forward_arguments,_reverse_arguments,_singleton_child,_assert_signed_consensus,b32)


def source(version=1):
    acs=Program.to(1);fund=Coin(b32(220),acs.get_tree_hash(),uint64(100))
    registry_id=Coin(fund.name(),SINGLETON_LAUNCHER_HASH,uint64(1)).name()
    governance_id=type(registry_id)(CONFIG.governance_singleton_struct.rest().first().as_atom())
    stat=GenerationStatutes(b32(221),registry_id,governance_id,STATUTES_LAUNCHER,b32(222),
        pool_id=CONFIG.pool_launcher_id,permanent_rules=CONFIG.permanent_rules,
        collections_root=keyed_root([COLLECTION]),revision=2,version=version)
    if version==2:
        successor=Program.to([2,(1,load_puzzle('generation_statutes_logic_v1.clsp')),1])
        stat=replace(stat,module_hash=successor.get_tree_hash())
    permanent=replace(CONFIG,statutes_inner_mod_hash=load_puzzle('generation_statutes_v1.clsp').get_tree_hash(),
        vault_v2_mod_hash=load_puzzle('vault_singleton_inner_generation_v1.clsp').get_tree_hash())
    pool=GenerationPool(stat.generation,registry_id,b32(223),permanent,replace(EMPTY_POOL,state_version=2))
    registry=Registry(stat.generation,registry_id,governance_id,b32(224),(pool.component(),stat.component()))
    _,launch=launch_conditions_and_coinsol(fund,registry.inner(),[],uint64(1))
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
    coin=Coin(registry_id,puzzle_for_singleton(registry_id,registry.inner()).get_tree_hash(),uint64(1))
    context=GenerationStatutesSource(stat,registry,SingletonTip(registry_id,registry.inner(),coin,launch))
    stat_coin,lineage,_=_singleton_child(launcher_id=stat.launcher_id,parent_inner=stat.inner(),current_inner=stat.inner(),seed=225)
    return pool,context,stat_coin,lineage


@pytest.mark.parametrize('version',[1,2])
@pytest.mark.parametrize('reverse',[False,True])
def test_actual_native_swaps_use_canonical_statutes_and_registry_before_and_after_upgrade(version,reverse):
    pool,context,stat_coin,lineage=source(version)
    config=pool.config();params=context.statutes.economic_parameters();view=context.statutes.economic_view()
    if reverse:
        args=_reverse_arguments(parameters=params,config=config,statutes_state=view)
        buyer=None
    else:
        fixture=_fixture(parameters=params,config=config,statutes_state=view)
        args=_forward_arguments(fixture,parameters=params,config=config,statutes_state=view)
        buyer=prepare_vault_sols_buyer_offer(payment_coin=fixture.payment_coin,payment_lineage_proof=fixture.payment_lineage,
            receipt=fixture.receipt,config=config,vault_launcher_id=VAULT_LAUNCHER).offer
    args.update(statutes_coin=stat_coin,statutes_lineage_proof=lineage,statutes_source=context)
    if reverse:
        protocol=build_deed_to_sols_protocol_offer(**args,vault_signature_data=None)
        bundle=protocol.offer.to_valid_spend()
    else:
        protocol=build_sols_to_deed_protocol_offer(**args,vault_signature_data=None)
        bundle=aggregate_sols_to_deed_swap(buyer_offer=buyer,protocol_offer=protocol,receipt=args['receipt'],
            config=config,vault_launcher_id=VAULT_LAUNCHER).aggregate_offer.to_valid_spend()
    _assert_signed_consensus(bundle)
    assert sum(s.coin==context.registry_tip.coin for s in bundle.coin_spends)==1
    from solslot_puzzles.generation_economic_reader import reconstruct_economic_successor
    assert reconstruct_economic_successor(protocol.statutes_spend,context.statutes).after.state()==context.statutes.state()
    bad=SpendBundle([s for s in bundle.coin_spends if s.coin!=context.registry_tip.coin],G2Element())
    with pytest.raises(ValueError,match='MessageNotSentOrReceived'):_assert_signed_consensus(bad)
    missing=dict(args);missing.pop('statutes_source')
    with pytest.raises(ValueError):
        (build_deed_to_sols_protocol_offer if reverse else build_sols_to_deed_protocol_offer)(**missing,vault_signature_data=None)
    wrong=dict(args);wrong['statutes_source']=replace(context,statutes=replace(context.statutes,revision=3))
    with pytest.raises(ValueError):
        (build_deed_to_sols_protocol_offer if reverse else build_sols_to_deed_protocol_offer)(**wrong,vault_signature_data=None)
