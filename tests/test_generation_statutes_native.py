"""Canonical economic facts use actual holder votes and native boundaries."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_economic_reader import decode_initial_economic_inner, reconstruct_economic_successor
from solslot_puzzles.generation_registry import CodeChange, UpgradePlan, inner_solution
from solslot_puzzles.generation_transactions import apply_statutes, apply_parameters, ratify_upgrade, activate_upgrade
from solslot_puzzles.protocol_statutes_v1 import CollectionStatute
from solslot_puzzles.protocol_statutes_driver import sols_evidence_message
from tests.test_generation_governance_native import generation, push
from tests.test_generation_transactions_native import close_bill, tip, apply
from tests.test_generation_registry_native import b32, authorize


def collection(c):
    now=int(c['sim'].timestamp)
    return CollectionStatute(b32(91),75_000_000_000,75_000_000_000,1,now-1,now+86400,1)


async def publish_collection(c):
    state=c['parameters'];record=collection(c)
    bill,next_state,entries=state.record_change('COLLECTION',(),record)
    proposal=await close_bill(c,bill)
    operation,gov,actual,actual_entries=apply_statutes(c['gov'],tip(c['gov_coin']),c['registry'],tip(c['registry_coin']),
        state,tip(c['parameters_coin']),proposal,'COLLECTION',(),record)
    assert actual==next_state and actual_entries==entries
    return state,record,operation,gov,next_state,entries,proposal


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['statutes'],indirect=True)
async def test_governed_statute_requires_exact_vote_and_native_record_transition(generation):
    c=generation;s=c['parameters'];pc=c['parameters_coin'];r=collection(c)
    assert decode_initial_economic_inner(s.inner(),generation=s.generation,registry_id=s.registry_id,
        governance_id=s.governance_id,launcher_id=s.launcher_id).state()==s.state()
    with pytest.raises(ValueError):apply_statutes(c['gov'],tip(c['gov_coin']),c['registry'],tip(c['registry_coin']),
        s,tip(pc),b32(77),'COLLECTION',(),r)
    s,r,operation,gov,next_state,entries,proposal=await publish_collection(c)
    change=operation.spends[1]
    for index,value in ((1,1),(3,b32(92)),(5,[r.as_program_value()]),(6,Program.to(1))):
        args=list(Program.from_bytes(bytes(change.solution)).as_iter())[2].as_python()
        args[1][index]=value
        bad=make_spend(change.coin,Program.from_bytes(bytes(change.puzzle_reveal)),
            Program.to([list(Program.from_bytes(bytes(change.solution)).as_iter())[0],1,args]))
        assert (await c['client'].push_tx(SpendBundle([operation.spends[0],bad],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    assert (await c['client'].push_tx(SpendBundle([change],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    await apply(c,operation);c.update(gov=gov,parameters=next_state)
    transition=reconstruct_economic_successor(change,s)
    assert transition.after.state()==next_state.state() and transition.successor==pc.coin
    assert next_state.revision==1 and next_state.values==s.values and next_state.permanent_rules==s.permanent_rules
    with pytest.raises(ValueError,match='advance exactly'):next_state.record_change('COLLECTION',entries,r)
    with pytest.raises(ValueError):reconstruct_economic_successor(change,next_state)
    assert (await c['client'].push_tx(operation.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    # Fees and property facts share one revision; a parameter action cannot
    # drop collection roots or restore the earlier parameter snapshot.
    values=(86400,300,100,70,30,86400)
    proposal=await close_bill(c,next_state.bill(values))
    op,new_gov,updated=apply_parameters(c['gov'],tip(c['gov_coin']),c['registry'],tip(c['registry_coin']),
        next_state,tip(pc),proposal,values)
    await apply(c,op);c.update(gov=new_gov,parameters=updated)
    assert updated.collections_root==next_state.collections_root and updated.revision==2
    assert reconstruct_economic_successor(op.spends[1],next_state).after.state()==updated.state()


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['statutes'],indirect=True)
async def test_statutes_evidence_uses_canonical_values_and_actual_scoped_pause(generation):
    c=generation;s,r,op,gov,state,entries,_=await publish_collection(c)
    await apply(c,op);c.update(gov=gov,parameters=state)
    rc,pc=c['registry_coin'],c['parameters_coin'];reg=c['registry'];consumer=b32(99);operation=b32(97)
    bill=Program.to([b'SOLS_EXCHANGE',consumer,r.collection_id])
    permission=rc.spend(inner_solution('AUTHORIZE_NEW',rc.coin,[4,pc.coin.puzzle_hash,operation,bill]))
    evidence=pc.spend(state.sols_evidence_solution(consumer,r.collection_id,entries,rc.inner.get_tree_hash(),operation))
    conditions=pc.inner.run(Program.to([b'SOLS_EVIDENCE',[consumer,r.collection_id,
        [r.as_program_value()],rc.inner.get_tree_hash(),operation]]))
    expected=sols_evidence_message(consumer_coin_id=consumer,collection=r,pause=None,
        parameters=state.economic_parameters(),state=state.economic_view())
    assert expected in [condition.as_python()[1] for condition in conditions.as_iter() if condition.first().as_int()==62]
    assert (await c['client'].push_tx(SpendBundle([evidence],G2Element())))[0]!=MempoolInclusionStatus.SUCCESS
    await push(c,[permission,evidence]);rc.advance(permission,reg.inner());pc.advance(evidence,state.inner())
    assert reconstruct_economic_successor(evidence,state).after.state()==state.state()
    # No expiration or statutes policy can reopen an owner-plus-one pause.
    paused=reg.paused(4)
    consent=authorize(c['admin_coin'],rc,Program.to([b'PAUSE_NEW_OPERATIONS',reg.generation,0,4]).get_tree_hash())
    pause=rc.spend(inner_solution('PAUSE',rc.coin,[c['admin_coin'].inner.get_tree_hash(),4]))
    await push(c,[consent,pause]);rc.advance(pause,paused.inner())
    with pytest.raises(ValueError):rc.inner.run(inner_solution('AUTHORIZE_NEW',rc.coin,
        [4,pc.coin.puzzle_hash,operation,bill]))
    c['sim'].pass_time(uint64(172801));await c['sim'].farm_block()
    with pytest.raises(ValueError):rc.inner.run(inner_solution('AUTHORIZE_NEW',rc.coin,
        [4,pc.coin.puzzle_hash,operation,bill]))


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['statutes'],indirect=True)
async def test_statutes_upgrade_preserves_governed_facts_and_rejects_early_activation(generation):
    c=generation;s,r,op,gov,state,entries,_=await publish_collection(c)
    await apply(c,op);c.update(gov=gov,parameters=state)
    successor=Program.to([2,(1,load_puzzle('generation_statutes_logic_v1.clsp')),1])
    plan=UpgradePlan(b32(80),(CodeChange(state.component_id,state.logic_hash(),successor.get_tree_hash(),2,1),))
    proposal=await close_bill(c,Program.to([b'UPGRADE',0,plan.program()]))
    op,gov,reg=ratify_upgrade(c['gov'],tip(c['gov_coin']),c['registry'],tip(c['registry_coin']),proposal,plan)
    ticket=op.auxiliary_outputs[0];await apply(c,op);c.update(gov=gov,registry=reg)
    op,activated,states=activate_upgrade(gov,tip(c['gov_coin']),reg,tip(c['registry_coin']),plan,ticket,
        ((state,tip(c['parameters_coin'])),))
    assert (await c['client'].push_tx(op.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    c['sim'].pass_time(uint64(86401));await c['sim'].farm_block();await apply(c,op)
    current=states[0]
    assert current.state()==state.state() and current.permanent_rules_hash==state.permanent_rules_hash
    transition=reconstruct_economic_successor(op.spends[2],state)
    assert transition.after.inner()==current.inner() and current.version==2
    assert (await c['client'].push_tx(op.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    with pytest.raises(ValueError,match='active reviewed'):apply_statutes(gov,tip(c['gov_coin']),activated,
        tip(c['registry_coin']),current,tip(c['parameters_coin']),b32(9),'COLLECTION',entries,replace(r,nav_version=2))
