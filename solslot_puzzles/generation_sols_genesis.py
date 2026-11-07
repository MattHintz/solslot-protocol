"""One-use native Sols anchor assembly; no keys, selection, dispatch or clock."""
from dataclasses import dataclass, replace

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.util.compute_additions import compute_additions_with_cost
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_pool import GenerationPool
from solslot_puzzles.generation_transactions import NativeOperation, SingletonTip, MAX_NATIVE_COST, _tip


@dataclass(frozen=True)
class SolsSeed:
    inner: Program
    eve: Coin
    reserve: Coin
    tail: Program


def sols_seed(pool: GenerationPool, funding: Coin) -> SolsSeed:
    pool.inner()
    e=pool.economics.economics
    if (pool.economics.state_version!=1 or e.bootstrap_complete or e.inventory_nav_micro_usd
            or e.treasury_assets_micro_usd or e.proven_liabilities_micro_usd or e.deed_count
            or e.total_sols_mojos!=1 or e.reserve_sols_mojos!=1
            or pool.economics.inventory_root!=Program.to([]).get_tree_hash() or funding.amount<1):
        raise ValueError('Sols anchor requires the untouched initial pool and funded one-mojo parent')
    from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD_HASH, SINGLETON_LAUNCHER_HASH
    tail=load_puzzle('generation_sols_tail_v1.clsp').curry(SINGLETON_MOD_HASH,pool.launcher_id,SINGLETON_LAUNCHER_HASH)
    if tail.get_tree_hash()!=pool.permanent.permanent_rules.sols_tail_hash:
        raise ValueError('Sols seed changes the permanent pool token identity')
    inner=load_puzzle('generation_sols_eve_v1.clsp').curry(pool.generation,
        pool.config().pool_singleton_struct,pool.permanent.reserve_puzzle_hash)
    eve=Coin(funding.name(),construct_cat_puzzle(CAT_MOD,tail.get_tree_hash(),inner).get_tree_hash(),uint64(1))
    from chia.wallet.util.curry_and_treehash import curry_and_treehash,calculate_hash_of_quoted_mod_hash
    reserve_hash=curry_and_treehash(calculate_hash_of_quoted_mod_hash(CAT_MOD.get_tree_hash()),
        Program.to(CAT_MOD.get_tree_hash()).get_tree_hash(),Program.to(tail.get_tree_hash()).get_tree_hash(),pool.permanent.reserve_puzzle_hash)
    return SolsSeed(inner,eve,Coin(eve.name(),reserve_hash,uint64(1)),tail)


def initialize_sols(pool: GenerationPool, tip: SingletonTip, funding_spend):
    _tip(tip,pool.launcher_id,pool.inner())
    seed=sols_seed(pool,funding_spend.coin)
    if Program.from_bytes(bytes(funding_spend.puzzle_reveal)).get_tree_hash()!=funding_spend.coin.puzzle_hash:
        raise ValueError('Sols seed funding reveal differs from its exact coin')
    outputs,_=compute_additions_with_cost(funding_spend,max_cost=MAX_NATIVE_COST)
    expected=[seed.eve]
    if funding_spend.coin.amount>1:
        expected.append(Coin(funding_spend.coin.name(),funding_spend.coin.puzzle_hash,uint64(funding_spend.coin.amount-1)))
    if sorted(outputs,key=lambda c:c.name())!=sorted(expected,key=lambda c:c.name()):
        raise ValueError('Sols seed funding changes the one-mojo issuance or unchanged-owner change')
    after=replace(pool,economics=replace(pool.economics,state_version=2))
    transition=tip.spend(pool.solution(tip.coin,'SEED_SOLS',[funding_spend.coin.name(),seed.eve.name()]))
    cat=SpendableCAT(coin=seed.eve,limitations_program_hash=seed.tail.get_tree_hash(),inner_puzzle=seed.inner,
        inner_solution=Program.to([seed.tail,pool.inner().get_tree_hash(),tip.coin.name(),seed.eve.name()]),
        limitations_program_reveal=seed.tail)
    bundle=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[cat])
    if len(bundle.coin_spends)!=1:raise ValueError('Sols seed unexpectedly produces multiple eve spends')
    operation=NativeOperation(pool.generation,'INITIALIZE_SOLS',(funding_spend,transition,*bundle.coin_spends),
        (tip.advanced(transition,after.inner()),),(seed.reserve,))
    operation.bundle()
    return operation,after,seed
