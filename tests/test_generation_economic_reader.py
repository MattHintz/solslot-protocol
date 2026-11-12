"""Native replay verifies actual outputs, including state after economic use."""
from dataclasses import replace
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element,SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_economic_reader import decode_initial_economic_inner,reconstruct_economic_successor
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_transactions import activate_upgrade,SingletonTip
from tests.test_generation_governance_native import generation,open_vote,anchor,vote,finalize,push
from tests.test_generation_mint_native import edition_for,mint_spends,approve
from tests.test_generation_registry_native import b32


def decode(s):
    return decode_initial_economic_inner(s.inner(),generation=s.generation,registry_id=s.registry_id,
        governance_id=s.governance_id,launcher_id=s.launcher_id)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['mint','parameters'],indirect=True)
async def test_economic_reader_proves_actual_update_and_rejects_stale_or_forged_input(generation):
    c=generation;s=c.get('mint') or c['parameters'];coin=c.get('mint_coin') or c['parameters_coin']
    assert decode(s).inner()==s.inner()
    if c.get('mint'):
        edition=edition_for(c);proposal=await approve(c,edition)
        spends,_=mint_spends(c,edition,proposal);change=spends[2];expected=s.minted(edition)
    else:
        values=(86400,300,100,70,30,86400);bill=s.bill(values)
        proposal=await open_vote(c,bill);await anchor(c);await vote(c,[1])
        c['sim'].pass_time(uint64(3601));await c['sim'].farm_block();await finalize(c)
        gov,gc=c['gov'],c['gov_coin']
        execute=gc.spend(inner_solution('EXECUTE',gc.coin,[proposal,bill,gov.approved.proof(gov.action_key(proposal,bill)),coin.inner.get_tree_hash(),b32(0)]))
        change=coin.spend(Program.to([b'UPDATE',[gc.inner.get_tree_hash(),0,Program.to(list(s.values)).get_tree_hash(),list(values),load_puzzle('generation_parameter_logic_v1.clsp')]]))
        spends=[execute,change];expected=s.updated(values)
    await push(c,spends)
    t=reconstruct_economic_successor(change,s)
    assert t.after.inner()==expected.inner()
    assert (await c['client'].get_coin_record_by_name(t.successor.name())).spent is False
    with pytest.raises(ValueError):reconstruct_economic_successor(change,expected)
    with pytest.raises(ValueError):decode(expected)
    with pytest.raises(ValueError):reconstruct_economic_successor(change,replace(s,registry_id=b32(99)))
    bad=make_spend(change.coin,Program.to(1),Program.to([[51,t.successor.puzzle_hash,1]]))
    with pytest.raises(ValueError):reconstruct_economic_successor(bad,s)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['mint','parameters'],indirect=True)
async def test_economic_reader_follows_real_delayed_activation_preserving_live_state(generation):
    from solslot_puzzles.generation_registry import CodeChange,UpgradePlan
    c=generation;s=c.get('mint') or c['parameters'];coin=c.get('mint_coin') or c['parameters_coin']
    # A real replacement program, wrapped to preserve the existing policy.
    old=load_puzzle('generation_mint_logic_v1.clsp' if c.get('mint') else 'generation_parameter_logic_v1.clsp')
    successor=Program.to([2,(1,old),1])
    plan=UpgradePlan(b32(81),(CodeChange(s.component_id,s.logic_hash(),successor.get_tree_hash(),2,1),))
    bill=Program.to([b'UPGRADE',c['registry'].nonce,plan.program()])
    proposal=await open_vote(c,bill);await anchor(c);await vote(c,[1])
    c['sim'].pass_time(uint64(3601));await c['sim'].farm_block();await finalize(c)
    gov,gc,reg,rc=c['gov'],c['gov_coin'],c['registry'],c['registry_coin']
    execute=gc.spend(inner_solution('EXECUTE',gc.coin,[proposal,bill,gov.approved.proof(gov.action_key(proposal,bill)),rc.inner.get_tree_hash(),b32(0)]))
    ratify=rc.spend(inner_solution('RATIFY_UPGRADE',rc.coin,[gc.inner.get_tree_hash(),plan.program()]))
    pending,ticket=reg.ratified(rc.coin,plan);executed=gov.executed(proposal,bill)
    await push(c,[execute,ratify]);gc.advance(execute,executed.inner());rc.advance(ratify,pending.inner())
    tip=lambda x:SingletonTip(x.launcher,x.inner,x.coin,x.parent)
    operation,activated,states=activate_upgrade(executed,tip(gc),pending,tip(rc),plan,ticket,((s,tip(coin)),))
    assert (await c['client'].push_tx(operation.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block()
    assert (await c['client'].push_tx(operation.bundle()))[0]==MempoolInclusionStatus.SUCCESS
    await c['sim'].farm_block()
    change=next(spend for spend in operation.spends if spend.coin==coin.coin)
    t=reconstruct_economic_successor(change,s)
    assert t.after.state()==s.state() and t.after.version==2
    assert t.after.inner()==states[0].inner() and t.after.logic_hash()==successor.get_tree_hash()
    with pytest.raises(ValueError):reconstruct_economic_successor(change,t.after)
    coin.advance(change,t.after.inner())
    read=coin.spend(Program.to([b'READ',[successor,b'VERSION']]))
    assert (await c['client'].push_tx(SpendBundle([read],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await c['sim'].farm_block()
    follow=reconstruct_economic_successor(read,t.after)
    assert follow.after.state()==s.state() and follow.after.version==2
    if c.get('mint'):
        # Use the upgraded business policy for actual governed issuance, not
        # only a version read. Current mint counter and authority survive.
        coin.advance(read,t.after.inner());c['mint']=t.after
        c['gov']=executed;c['registry']=activated
        for spend in operation.spends:
            if spend.coin==gc.coin:gc.advance(spend,executed.inner())
            if spend.coin==rc.coin:rc.advance(spend,activated.inner())
        edition=edition_for(c);proposal=await approve(c,edition)
        with pytest.raises(ValueError,match='active reviewed'):mint_spends(c,edition,proposal)
        spends,inventory=mint_spends(c,edition,proposal,policy=successor)
        await push(c,spends)
        minted=reconstruct_economic_successor(spends[2],c['mint'])
        assert minted.after.version==2 and minted.after.issued_count==25
        assert len({item.coin.name() for item in inventory})==25

