"""Native, funded first Sols issuance and permanent one-use initialization."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk,solution_for_conditions
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL,G2Element,Coin,SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_economic_reader import reconstruct_economic_successor
from solslot_puzzles.generation_sols_genesis import initialize_sols,sols_seed
from tests.test_generation_governance_native import generation,push
from tests.test_generation_transactions_native import tip


async def prepare_signed_sols_seed(c):
    from chia.consensus.default_constants import DEFAULT_CONSTANTS
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import calculate_synthetic_secret_key,DEFAULT_HIDDEN_PUZZLE_HASH
    from chia.consensus.condition_tools import conditions_dict_for_solution,pkm_pairs_for_conditions_dict
    pool=c['pool'];pc=c['pool_coin'];acs=Program.to(1)
    key=AugSchemeMPL.key_gen(b'Z'*32);wallet=puzzle_for_pk(key.get_g1())
    source=(await c['client'].get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[0].coin
    parent=Coin(source.name(),wallet.get_tree_hash(),uint64(10))
    await push(c,[make_spend(source,acs,Program.to([[51,parent.puzzle_hash,10],[51,acs.get_tree_hash(),int(source.amount)-10]]))])
    seed=sols_seed(pool,parent)
    funding=make_spend(parent,wallet,solution_for_conditions([[51,seed.eve.puzzle_hash,1],[51,parent.puzzle_hash,9]]))
    operation,after,issued=initialize_sols(pool,tip(pc),funding)
    assert seed==issued and after.economics.economics==pool.economics.economics
    assert after.economics.state_version==2 and after.component()==pool.component()
    synthetic=calculate_synthetic_secret_key(key,DEFAULT_HIDDEN_PUZZLE_HASH)
    conditions=conditions_dict_for_solution(funding.puzzle_reveal,funding.solution,11_000_000_000)
    signatures=[]
    for public,message in pkm_pairs_for_conditions_dict(conditions,parent,DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA):
        assert bytes(public)==bytes(synthetic.get_g1())
        signatures.append(AugSchemeMPL.sign(synthetic,message))
    signed=operation.with_aggregated_signature(AugSchemeMPL.aggregate(signatures))
    return signed,after,issued,parent,funding


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['pool','pool-reserve'],indirect=True)
async def test_funded_sols_anchor_is_native_conserved_and_cannot_be_reissued(generation):
    c=generation;pool=c['pool'];pc=c['pool_coin']
    signed,after,seed,parent,funding=await prepare_signed_sols_seed(c)
    assert sum(s.coin.amount for s in signed.spends)==sum(coin.amount for s in signed.spends for coin in compute_additions(s))
    for index in range(len(signed.spends)):
        partial=SpendBundle(list(signed.spends[:index]+signed.spends[index+1:]),signed.aggregated_signature)
        assert (await c['client'].push_tx(partial))[0]!=MempoolInclusionStatus.SUCCESS
    bad=make_spend(parent,Program.from_bytes(bytes(funding.puzzle_reveal)),
        solution_for_conditions([[51,seed.eve.puzzle_hash,2],[51,parent.puzzle_hash,8]]))
    with pytest.raises(ValueError,match='one-mojo issuance'):initialize_sols(pool,tip(pc),bad)
    wrong_pool=replace(pool,permanent=replace(pool.permanent,reserve_puzzle_hash=parent.puzzle_hash))
    with pytest.raises(ValueError):initialize_sols(wrong_pool,tip(pc),funding)
    assert await c['client'].push_tx(signed.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c['sim'].farm_block()
    record=await c['client'].get_coin_record_by_name(seed.reserve.name())
    assert record and not record.spent and record.coin.amount==1
    assert (await c['client'].get_coin_record_by_name(seed.eve.name())).spent
    pc.advance(signed.spends[1],after.inner())
    replay=reconstruct_economic_successor(signed.spends[1],pool)
    assert replay.after.inner()==after.inner() and replay.successor==pc.coin
    with pytest.raises(ValueError,match='untouched initial'):sols_seed(after,parent)
    with pytest.raises(ValueError):initialize_sols(after,tip(pc),funding)
    direct=pc.spend(after.solution(pc.coin,'SEED_SOLS',[parent.name(),seed.eve.name()]))
    assert (await c['client'].push_tx(SpendBundle([direct],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    assert (await c['client'].push_tx(signed.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    assert pool.permanent.permanent_rules.sols_tail_hash==after.permanent.permanent_rules.sols_tail_hash
