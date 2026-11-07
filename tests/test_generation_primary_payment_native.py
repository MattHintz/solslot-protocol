"""Funded exact primary-fee component and earned rewards, not NFT acquisition.

An ACS companion stands in for the still-unimplemented linked acquisition.
It cannot serve as a production primary/reserve receipt. Actual source, buyer
offer and backing authorization require the full composite tests separately.
"""
from dataclasses import replace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin,SpendBundle,G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_primary_payment import PrimaryFeeRouting
from solslot_puzzles.generation_rewards import RewardFeeInput,close_reward_epoch,claim_vault_reward
from tests.test_generation_rewards_native import generation,push,holdings,tip,epoch
from tests.test_generation_registry_native import b32


async def payment(c,native):
    acs=Program.to(1);await c['sim'].farm_block(acs.get_tree_hash())
    origin=(await c['client'].get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[-1].coin
    tail=GENESIS_BY_ID_MOD.curry(origin.name());asset=bytes32.zeros if native else tail.get_tree_hash()
    routing=PrimaryFeeRouting(c['bindings'],c['parameters'].launcher_id,asset,acs.get_tree_hash(),b32(95),
        10000,10100,b32(96),b32(97),c['parameters_coin'].inner.get_tree_hash(),c['parameters'].values)
    if native:
        coin=Coin(origin.name(),routing.full().get_tree_hash(),uint64(10100))
        parent=make_spend(origin,acs,Program.to([[51,coin.puzzle_hash,10100],[51,acs.get_tree_hash(),int(origin.amount)-10100]]))
        await push(c,[parent]);spend=make_spend(coin,routing.inner(),routing.solution(coin.name()))
    else:
        eve=Coin(origin.name(),construct_cat_puzzle(CAT_MOD,asset,acs).get_tree_hash(),uint64(10100))
        parent=make_spend(origin,acs,Program.to([[51,eve.puzzle_hash,10100],[51,acs.get_tree_hash(),int(origin.amount)-10100]]))
        issued=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,asset,acs,
            Program.to([[51,routing.inner().get_tree_hash(),10100],[51,[],-113,tail,[]]]),limitations_program_reveal=tail)])
        await push(c,[parent,*issued.coin_spends]);coin=Coin(eve.name(),routing.full().get_tree_hash(),uint64(10100))
        spend=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(coin,asset,routing.inner(),routing.solution(coin.name()),
            lineage_proof=LineageProof(eve.parent_coin_info,acs.get_tree_hash(),eve.amount))]).coin_spends[0]
    companion=(await c['client'].get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[0].coin
    source=make_spend(companion,acs,Program.to([[51,acs.get_tree_hash(),int(companion.amount)],*routing.source_conditions(coin.name())]))
    authority=c['parameters_coin'].spend(Program.to([b'REWARD_EVIDENCE',[coin.puzzle_hash,routing.route_id]]))
    return routing,spend,source,authority


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[False,True])
async def test_one_primary_fee_pays_exact_split_and_becomes_claimable_rewards(generation,native):
    c=generation;routing,spend,source,authority=await payment(c,native)
    assert routing.allocations()==(10000,70,30)
    outputs=compute_additions(spend)
    def ph(inner):
        from chia.wallet.util.curry_and_treehash import curry_and_treehash,calculate_hash_of_quoted_mod_hash
        return inner if native else curry_and_treehash(calculate_hash_of_quoted_mod_hash(CAT_MOD.get_tree_hash()),
            Program.to(CAT_MOD.get_tree_hash()).get_tree_hash(),Program.to(routing.asset_id).get_tree_hash(),inner)
    assert sorted((coin.puzzle_hash,coin.amount) for coin in outputs)==sorted([
        (ph(routing.principal_destination),10000),(ph(routing.treasury_destination),70),(routing.custody.full().get_tree_hash(),30)])
    for partial in ([spend,source],[spend,authority],[source,authority]):
        assert (await c['client'].push_tx(SpendBundle(partial,G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    await push(c,[spend,source,authority]);c['parameters_coin'].advance(authority,c['parameters_coin'].inner)
    fee=next(coin for coin in outputs if coin.puzzle_hash==routing.custody.full().get_tree_hash())
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    result=epoch(c,routing.custody,(RewardFeeInput(fee,spend),))
    assert [claim.amount for claim,_ in result.claims]==[10,10,10]
    await push(c,list(result.operation.spends))
    for claim,source in result.claims:
        vault=next(v for i,v in enumerate(c['vaults']) if c['owners'][i].get_tree_hash()==claim.owner)
        await push(c,list(claim_vault_reward(claim,source,vault.launcher).spends))


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[False,True])
@pytest.mark.parametrize('fault',['amount','coin','parameters','authority'])
async def test_primary_payment_rejects_unreviewed_amount_and_false_fee_authority(generation,native,fault):
    c=generation;routing,spend,source,authority=await payment(c,native)
    solution=Program.from_bytes(bytes(spend.solution));raw=(solution if native else solution.first()).as_python()
    if fault=='amount':raw[1]=10101
    elif fault=='coin':raw[0]=bytes(b32(99))
    elif fault=='parameters':raw[3][3:5]=[30,70]
    elif fault=='authority':raw[2]=bytes(b32(99))
    bad=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),
        Program.to(raw) if native else Program.to([Program.to(raw),*list(solution.as_iter())[1:]]))
    assert (await c['client'].push_tx(SpendBundle([bad,source,authority],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS


def test_primary_rounding_preserves_the_legacy_mandatory_subtotal_without_double_charging():
    from solslot_puzzles.generation_sgt import SGTBindings
    b=SGTBindings(*(b32(n) for n in (1,2,3,4,5)))
    r=PrimaryFeeRouting(b,b32(6),bytes32.zeros,b32(7),b32(8),300000,10100,b32(9),b32(10),b32(11),(86400,600,100,70,30,86400))
    assert r.subtotal_usd_minor==303000 and r.fee_usd_minor==3000 and r.allocations()==(10000,70,30)
    for amount in (101,102,10001,2**64-1):
        shares=replace(r,total_payment=amount).allocations()
        assert sum(shares)==amount and all(value>=0 for value in shares)
    # The primary fee is retained; governed share changes affect allocation,
    # never remove an already mandatory fee from the principal/subtotal.
    assert replace(r,parameters=(86400,600,100,50,50,86400)).allocations()==(10000,50,50)
    with pytest.raises(ValueError):replace(r,parameters=(86400,600,0,0,0,86400)).allocations()
    with pytest.raises(ValueError):replace(r,total_payment=True).allocations()
