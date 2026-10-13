"""Constrained Sols custody, reusing the existing CAT tail and pool receipts.

No keys or dispatch. Historical faucet custody and its API remain unchanged.
The new-generation reserve authorizes only the immutable pool's exact deposit
payout; all inputs co-spend and reproduce the complete remaining reserve.
"""
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH
from chia.wallet.trading.offer import OFFER_MOD_HASH

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_pool import GenerationPool, GenerationPoolConfig
from solslot_puzzles.generation_registry import singleton_struct


def reserve_inner(*, generation, registry_id, pool_id, component_id):
    from chia_rs.sized_bytes import bytes32
    if any(not isinstance(v,bytes32) or v==bytes32.zeros for v in
           (generation,registry_id,pool_id,component_id)):
        raise ValueError('reserve requires exact nonzero generation authority bindings')
    mod=load_puzzle('generation_sols_reserve_v1.clsp')
    return mod.curry(mod.get_tree_hash(),generation,singleton_struct(registry_id),singleton_struct(pool_id),
        component_id,load_puzzle('generation_pool_v1.clsp').get_tree_hash(),CAT_MOD.get_tree_hash(),
        load_puzzle('generation_sols_tail_v1.clsp').get_tree_hash(),OFFER_MOD_HASH)


def reserve_solution(*, config, state, pool_coin, reserve_coin, pool_params, coins=None):
    if not isinstance(config,GenerationPoolConfig):
        raise ValueError('constrained reserve requires the stable generation pool')
    inner=reserve_inner(generation=config.generation,registry_id=config.registry_id,
        pool_id=config.pool_launcher_id,component_id=config.component_id)
    if inner.get_tree_hash()!=config.reserve_puzzle_hash:
        raise ValueError('reserve differs from the permanently bound pool destination')
    from dataclasses import fields
    from solslot_puzzles.pool_v4_driver import PoolV4Config
    permanent=PoolV4Config(**{f.name:getattr(config,f.name) for f in fields(PoolV4Config)
                            if f.name!='pool_puzzle_version'})
    pool=GenerationPool(config.generation,config.registry_id,config.component_id,permanent,state,
        config.module_hash,config.version,config.compatibility)
    full=construct_cat_puzzle(CAT_MOD,config.permanent_rules.sols_tail_hash,inner)
    selected=tuple(sorted(coins or (reserve_coin,),key=lambda c:bytes(c.name())))
    if (not 0<len(selected)<=64 or len({c.name() for c in selected})!=len(selected)
            or reserve_coin not in selected or any(c.puzzle_hash!=full.get_tree_hash() or c.amount<=0 for c in selected)
            or sum(c.amount for c in selected)!=state.economics.reserve_sols_mojos):
        raise ValueError('all current reserve inputs must conserve the governed reserve balance')
    tail=load_puzzle('generation_sols_tail_v1.clsp').curry(SINGLETON_MOD_HASH,config.pool_launcher_id,SINGLETON_LAUNCHER_HASH)
    if tail.get_tree_hash()!=config.permanent_rules.sols_tail_hash:
        raise ValueError('reserve changes the permanent Sols token identity')
    return Program.to([b'PAYOUT',pool.state(),config.module_hash,config.version,config.compatibility,
        pool_coin.name(),reserve_coin.name(),int(reserve_coin.amount),
        [[c.parent_coin_info,int(c.amount)] for c in selected],pool_params,tail])


def merge_reserve(*, config, coins, lineages):
    """Reuse the historical atomic CAT consolidation, with constrained custody.

    This moves no asset to a new recipient and changes no pool state. It needs
    no registry pause permission and remains available during emergency waits.
    """
    if not isinstance(config,GenerationPoolConfig):
        raise ValueError('reserve merge requires its actual generation pool')
    inner=reserve_inner(generation=config.generation,registry_id=config.registry_id,
        pool_id=config.pool_launcher_id,component_id=config.component_id)
    if inner.get_tree_hash()!=config.reserve_puzzle_hash:
        raise ValueError('reserve merge changes the permanent custody destination')
    full=construct_cat_puzzle(CAT_MOD,config.permanent_rules.sols_tail_hash,inner)
    if (not 1<len(coins)<=64 or len(coins)!=len(lineages) or len({c.name() for c in coins})!=len(coins)
            or any(c.puzzle_hash!=full.get_tree_hash() or c.amount<=0 for c in coins)
            or sum(c.amount for c in coins)>=2**64):
        raise ValueError('reserve merge requires distinct current same-custody CAT inputs')
    paired=sorted(zip(coins,lineages),key=lambda pair:bytes(pair[0].name()))
    group=[[c.parent_coin_info,int(c.amount)] for c,_ in paired]
    solutions=[Program.to([b'MERGE',[],b'',0,0,b'',coin.name(),int(coin.amount),group,[],[]]) for coin,_ in paired]
    from chia.wallet.cat_wallet.cat_utils import SpendableCAT,unsigned_spend_bundle_for_spendable_cats
    from chia.wallet.lineage_proof import LineageProof
    from chia_rs import Coin
    from chia_rs.sized_ints import uint64
    native=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(coin,
        config.permanent_rules.sols_tail_hash,inner,solution,lineage_proof=lineage)
        for (coin,lineage),solution in zip(paired,solutions)])
    first=paired[0][0]
    successor=Coin(first.name(),full.get_tree_hash(),uint64(sum(c.amount for c in coins)))
    if native.additions()!=[successor]:
        raise ValueError('reserve merge does not reproduce all funds at the same custody')
    return successor,LineageProof(first.parent_coin_info,inner.get_tree_hash(),first.amount),tuple(native.coin_spends),tuple(
        inner.run(solution) for solution in solutions)
