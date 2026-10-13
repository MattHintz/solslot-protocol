"""Real funded CAT fee epochs, authenticated eligibility and permanent claims.

Synthetic keys and simulator time isolate consensus. The fee asset here is a
test CAT; actual fee production by the Sols pool requires separate integration.
Vault recipients use real BLS/EVM custody with no private ID stamp.
"""
from dataclasses import replace
from copy import deepcopy

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD,SpendableCAT,construct_cat_puzzle,unsigned_spend_bundle_for_spendable_cats
from chia.wallet.puzzles.tails import GENESIS_BY_ID_MOD
from chia_rs import Coin,SpendBundle,G2Element
from chia_rs.sized_ints import uint64
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.generation_ballots import CurrentHoldings
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_rewards import RewardCustody,RewardFeeInput,close_reward_epoch,claim_vault_reward,reward_allocations
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.generation_sgt import ledger_inner,SGTOutput
from solslot_puzzles.generation_holdings_reader import reconstruct_holdings_successor
from solslot_puzzles.generation_economic_reader import reconstruct_economic_successor
from solslot_puzzles.holdings import HoldingsTree,HoldingKind
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from tests.test_generation_governance_native import generation,push,open_vote,anchor
from tests.test_generation_registry_native import authorize,b32


def tip(item):return SingletonTip(item.launcher,item.inner,item.coin,item.parent)
def holdings(c):return CurrentHoldings(c['bindings'],c['tree'],c['sequence'],tip(c['ledger_coin']))


async def fee_inputs(c,amounts=(90,),*,native=False):
    acs=Program.to(1);await c['sim'].farm_block(acs.get_tree_hash())
    origin=(await c['client'].get_coin_records_by_puzzle_hash(acs.get_tree_hash(),include_spent_coins=False))[-1].coin
    if native:
        custody=RewardCustody(c['bindings'],c['parameters'].launcher_id,bytes32.zeros)
        funding=make_spend(origin,acs,Program.to([[51,custody.inner().get_tree_hash(),amount] for amount in amounts]+[
            [51,acs.get_tree_hash(),int(origin.amount)-sum(amounts)]]))
        await push(c,[funding])
        return custody,tuple(RewardFeeInput(Coin(origin.name(),custody.full().get_tree_hash(),uint64(amount)),funding) for amount in amounts)
    tail=GENESIS_BY_ID_MOD.curry(origin.name())
    custody=RewardCustody(c['bindings'],c['parameters'].launcher_id,tail.get_tree_hash())
    eve=Coin(origin.name(),construct_cat_puzzle(CAT_MOD,tail.get_tree_hash(),acs).get_tree_hash(),uint64(sum(amounts)))
    parent=make_spend(origin,acs,Program.to([[51,eve.puzzle_hash,int(eve.amount)],
        [51,acs.get_tree_hash(),int(origin.amount)-int(eve.amount)]]))
    issued=unsigned_spend_bundle_for_spendable_cats(CAT_MOD,[SpendableCAT(eve,tail.get_tree_hash(),acs,
        Program.to([[51,custody.inner().get_tree_hash(),amount] for amount in amounts]+[[51,[],-113,tail,[]]]),
        limitations_program_reveal=tail)])
    await push(c,[parent,*issued.coin_spends])
    coins=tuple(RewardFeeInput(Coin(eve.name(),custody.full().get_tree_hash(),uint64(amount)),issued.coin_spends[0]) for amount in amounts)
    return custody,coins


async def paused(c):
    reg,admin=c['registry_coin'],c['admin_coin'];after=c['registry'].paused(31)
    spend=reg.spend(inner_solution('PAUSE',reg.coin,[admin.inner.get_tree_hash(),31]))
    consent=authorize(admin,reg,Program.to([b'PAUSE_NEW_OPERATIONS',c['bindings'].generation,c['registry'].pause_epoch,31]).get_tree_hash())
    await push(c,[spend,consent]);reg.advance(spend,after.inner());admin.advance(consent,admin.inner);c['registry']=after


def epoch(c,custody,fees):
    return close_reward_epoch(custody,c['gov'],c['registry'],holdings(c),c['parameters'],tip(c['parameters_coin']),fees)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[False,True])
async def test_mature_fees_create_exact_permanent_rewards_and_claims_during_full_pause(generation,native):
    c=generation;custody,fees=await fee_inputs(c,native=native)
    result=epoch(c,custody,fees)
    assert result.eligible_supply==30000 and result.epoch_seconds==86400
    assert len(result.claims)==3 and all(claim.amount==30 for claim,_ in result.claims)
    status,error=await c['client'].push_tx(result.operation.bundle())
    assert status!=MempoolInclusionStatus.SUCCESS and 'SECONDS_RELATIVE' in error.name
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    await paused(c)
    result=epoch(c,custody,fees)
    # A missing fee, ledger or statutes input is not a valid reward epoch.
    for i in range(len(result.operation.spends)):
        bad=SpendBundle([spend for j,spend in enumerate(result.operation.spends) if j!=i],G2Element())
        assert (await c['client'].push_tx(bad))[0]==MempoolInclusionStatus.FAILED
    await push(c,list(result.operation.spends))
    ledger=reconstruct_holdings_successor(result.operation.spends[-2],c['bindings'],c['tree'],c['sequence'])
    statutes=reconstruct_economic_successor(result.operation.spends[-1],c['parameters'])
    assert ledger.tree.root==c['tree'].root and ledger.sequence==c['sequence']
    assert statutes.after.state()==c['parameters'].state()
    c['ledger_coin'].advance(result.operation.spends[-2],c['ledger_coin'].inner)
    c['parameters_coin'].advance(result.operation.spends[-1],c['parameters_coin'].inner)
    assert (await c['client'].push_tx(result.operation.bundle()))[0]==MempoolInclusionStatus.FAILED
    for claim,source in result.claims:
        index=next(i for i,owner in enumerate(c['owners']) if owner.get_tree_hash()==claim.owner)
        vault=c['vaults'][index]
        with pytest.raises(ValueError,match='unchanged'):
            claim_vault_reward(claim,source,c['vaults'][(index+1)%3].launcher)
        payment=claim_vault_reward(claim,source,vault.launcher)
        # Claims do not spend a ledger, policy, reserve, vault or fee signer.
        assert len(payment.spends)==1
        destination=puzzle_for_p2_vault(vault.launcher)
        assert payment.auxiliary_outputs[0].puzzle_hash==(destination if native else construct_cat_puzzle(
            CAT_MOD,custody.asset_id,destination)).get_tree_hash()
        await push(c,list(payment.spends))
        assert (await c['client'].push_tx(payment.bundle()))[0]==MempoolInclusionStatus.FAILED
    assert c['registry'].pause_mask==31


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['rewards'],indirect=True)
@pytest.mark.parametrize('fault',['supply','quantity','reserve','owner','missing-holder','duplicate-holder','proof','parameters','asset','missing-fee'])
@pytest.mark.parametrize('native',[False,True])
async def test_epoch_rejects_false_eligibility_and_unreviewed_funding(generation,fault,native):
    c=generation;custody,fees=await fee_inputs(c,(29,31,40),native=native)
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    result=epoch(c,custody,fees)
    spend=result.operation.spends[len(fees)]
    if fault=='asset':
        with pytest.raises(ValueError):epoch(c,replace(custody,asset_id=b32(91)),fees)
        return
    if fault=='missing-fee':
        assert (await c['client'].push_tx(SpendBundle(list(result.operation.spends[1:]),G2Element())))[0]==MempoolInclusionStatus.FAILED
        return
    full_solution=Program.from_bytes(bytes(spend.solution));raw=deepcopy((full_solution if native else full_solution.first()).as_python())
    if fault=='supply':raw[3][1]=30001
    elif fault=='quantity':raw[8][0][1][1]=10001
    elif fault=='reserve':raw[8][0][1][2]=3
    elif fault=='owner':raw[8][0][1][3]=bytes(b32(91))
    elif fault=='missing-holder':raw[8].pop()
    elif fault=='duplicate-holder':raw[8].append(raw[8][0])
    elif fault=='proof':raw[8][0][2][0][0]=bytes(b32(91))
    elif fault=='parameters':raw[7][5]=60
    altered=Program.to(raw) if native else Program.to([Program.to(raw),*list(full_solution.as_iter())[1:]])
    bad=make_spend(spend.coin,Program.from_bytes(bytes(spend.puzzle_reveal)),altered)
    spends=list(result.operation.spends);spends[len(fees)]=bad
    assert (await c['client'].push_tx(SpendBundle(spends,G2Element())))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[False,True])
async def test_locked_holder_rewards_are_preserved_and_rounding_conserves_every_unit(generation,native):
    c=generation;custody,fees=await fee_inputs(c,(101,),native=native)
    await open_vote(c,Program.to([b'REOPEN',0,1]),sponsors=(0,));await anchor(c)
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    result=epoch(c,custody,fees)
    assert result.eligible_supply==30000
    assert sorted(claim.amount for claim,_ in result.claims)==[33,34,34]
    assert sum(claim.amount for claim,_ in result.claims)==101
    await push(c,list(result.operation.spends))
    assert c['tree'].root.total==1000000 and c['tree'].root.eligible==30000


def test_multiple_holdings_of_one_owner_cannot_game_integer_reward_rounding():
    from solslot_puzzles.holdings import Holding
    owner1,owner2=b32(1),b32(2)
    whole=HoldingsTree({b32(11):Holding(b32(21),20000,HoldingKind.HOLDER,owner1),
        b32(12):Holding(b32(22),10000,HoldingKind.HOLDER,owner2)})
    split=HoldingsTree({b32(13):Holding(b32(23),5000,HoldingKind.HOLDER,owner1),
        b32(14):Holding(b32(24),15000,HoldingKind.LOCKED_HOLDER,owner1,b32(31)),
        b32(12):Holding(b32(22),10000,HoldingKind.HOLDER,owner2)})
    for amount in (1,2,3,90,101):
        assert reward_allocations(whole,amount)==reward_allocations(split,amount)
        assert sum(value for _,value in reward_allocations(split,amount))==amount


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['rewards'],indirect=True)
@pytest.mark.parametrize('native',[False,True])
async def test_full_fee_group_shares_one_native_snapshot_and_remains_under_journal_bound(generation,native):
    c=generation;custody,fees=await fee_inputs(c,tuple(range(1,65)),native=native)
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    result=epoch(c,custody,fees)
    assert len(result.operation.spends)==67
    assert len(bytes(result.operation.bundle()))<2_000_000
    assert sum(claim.amount for claim,_ in result.claims)==sum(range(1,65))
    for spend in result.operation.spends[:64]:
        solution=Program.from_bytes(bytes(spend.solution))
        assert len(list((solution if native else solution.first()).as_iter()))==5
    assert result.operation.spends[64].coin.amount==0
    await push(c,list(result.operation.spends))
