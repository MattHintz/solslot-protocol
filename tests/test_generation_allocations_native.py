"""Real grant vote, reserve CAT allocation, delivery and snapshot conservation.

The fixture's administrator is a synthetic isolated authority. Actual V4
publication/custody/recovery is covered separately. Simulator time is advanced;
these tests are not evidence of the mandatory live one-hour waiting period.
"""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element,SpendBundle

from solslot_puzzles.generation_allocations import allocate_grant,deliver_escrow,grant_bill
from solslot_puzzles.generation_ballots import CurrentHoldings,SGTInput
from solslot_puzzles.generation_sgt import SGTOutput
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_holdings_reader import reconstruct_holdings_successor
from solslot_puzzles.generation_transactions import SingletonTip
from solslot_puzzles.holdings import HoldingKind,quorum
from tests.test_generation_governance_native import generation,open_vote,anchor,finalize,push
from tests.test_generation_registry_native import authorize


def tip(singleton):
    return SingletonTip(singleton.launcher,singleton.inner,singleton.coin,singleton.parent)


def holdings(c):
    return CurrentHoldings(c['bindings'],c['tree'],c['sequence'],tip(c['ledger_coin']))


@pytest.mark.asyncio
async def test_grant_is_once_only_nonvoting_until_exact_escrow_delivery(generation):
    c=generation
    reserve=SGTInput(c['issue'].coins[3],c['issue'].outputs[3],c['issue'].eve_spend)
    outputs=(SGTOutput(HoldingKind.UNDELIVERED_ESCROW,c['owners'][2].get_tree_hash(),10000),
        replace(reserve.descriptor,amount=960000))
    bill=grant_bill(c['bindings'],reserve,outputs)
    proposal=await open_vote(c,bill,sponsors=(0,1));born=await anchor(c)
    # Successful quorum does not let a grant execute before voting closes.
    with pytest.raises(ValueError,match='unapproved'):
        allocate_grant(c['gov'],tip(c['gov_coin']),holdings(c),reserve,outputs,proposal)
    c['sim'].pass_time(born+3601-int(c['sim'].timestamp));await c['sim'].farm_block();await finalize(c)
    operation=allocate_grant(c['gov'],tip(c['gov_coin']),holdings(c),reserve,outputs,proposal)
    # Neither one of the native pair nor a different recipient can spend the
    # reserve simply because a matching title/amount appears in an API record.
    for omitted in range(len(operation.operation.spends)):
        bad=SpendBundle([s for i,s in enumerate(operation.operation.spends) if i!=omitted],G2Element())
        assert (await c['client'].push_tx(bad))[0]==MempoolInclusionStatus.FAILED
    for changed in [(replace(outputs[0],owner=c['owners'][0].get_tree_hash()),outputs[1]),
                    (replace(outputs[0],amount=10001),replace(outputs[1],amount=959999))]:
        with pytest.raises(ValueError,match='unapproved'):
            allocate_grant(c['gov'],tip(c['gov_coin']),holdings(c),reserve,changed,proposal)
    await push(c,list(operation.operation.spends))
    reconstructed=reconstruct_holdings_successor(operation.operation.spends[-1],c['bindings'],c['tree'],c['sequence'])
    assert reconstructed.tree.holdings==operation.holdings.tree.holdings
    assert reconstructed.successor==operation.holdings.tip.coin
    assert operation.holdings.tree.root.total==1000000 and operation.holdings.tree.root.eligible==30000
    assert quorum(operation.holdings.tree.root.eligible)==15000
    assert sum(h.amount for h in operation.holdings.tree.holdings.values() if h.kind==HoldingKind.UNDELIVERED_ESCROW)==10000
    assert sum(h.amount for h in operation.holdings.tree.holdings.values() if h.kind==HoldingKind.RESERVE)==960000
    assert not (await c['client'].get_coin_record_by_name(operation.outputs[0].coin.name())).spent
    with pytest.raises(ValueError,match='unapproved'):
        allocate_grant(operation.governance,operation.operation.successors[0],operation.holdings,reserve,outputs,proposal)
    assert (await c['client'].push_tx(operation.operation.bundle()))[0]==MempoolInclusionStatus.FAILED

    c['gov_coin'].advance(operation.operation.spends[0],operation.governance.inner())
    c['ledger_coin'].advance(operation.operation.spends[-1],operation.holdings.tip.inner)
    c.update(gov=operation.governance,tree=operation.holdings.tree,sequence=operation.holdings.sequence)
    next_outputs=(outputs[0],replace(outputs[1],amount=950000))
    next_bill=grant_bill(c['bindings'],operation.outputs[1],next_outputs)
    await open_vote(c,next_bill,sponsors=(0,1));await anchor(c)
    assert c['gov'].active.snapshot.eligible==30000
    # Even a full new-operation pause cannot block delivery of this already
    # funded SGT entitlement to its unchanged owner.
    reg,admin=c['registry_coin'],c['admin_coin'];paused=c['registry'].paused(31)
    pause=reg.spend(inner_solution('PAUSE',reg.coin,[admin.inner.get_tree_hash(),31]))
    consent=authorize(admin,reg,Program.to([b'PAUSE_NEW_OPERATIONS',c['bindings'].generation,c['registry'].pause_epoch,31]).get_tree_hash())
    await push(c,[pause,consent]);reg.advance(pause,paused.inner());admin.advance(consent,admin.inner)
    c['registry']=paused

    # Delivery needs no vault signature or ID proof. It is a paired CAT/ledger
    # transition to the unchanged owner, not another reserve allocation.
    delivered=deliver_escrow(c['gov'],holdings(c),operation.outputs[0])
    for omitted in range(len(delivered.operation.spends)):
        bad=SpendBundle([s for i,s in enumerate(delivered.operation.spends) if i!=omitted],G2Element())
        assert (await c['client'].push_tx(bad))[0]==MempoolInclusionStatus.FAILED
    await push(c,list(delivered.operation.spends))
    reconstructed=reconstruct_holdings_successor(delivered.operation.spends[-1],c['bindings'],c['tree'],c['sequence'])
    assert reconstructed.tree.holdings==delivered.holdings.tree.holdings
    assert reconstructed.successor==delivered.holdings.tip.coin
    assert delivered.outputs[0].descriptor.owner==outputs[0].owner
    assert delivered.outputs[0].coin.amount==10000 and delivered.holdings.tree.root.total==1000000
    assert delivered.holdings.tree.root.eligible==40000 and quorum(delivered.holdings.tree.root.eligible)==20000
    assert sum(h.amount for h in delivered.holdings.tree.holdings.values() if h.kind==HoldingKind.UNDELIVERED_ESCROW)==0
    # A pre-delivery opening snapshot is immutable; its denominator is 30k.
    assert operation.holdings.tree.root.eligible==30000 and quorum(operation.holdings.tree.root.eligible)==15000
    assert delivered.governance.active.snapshot.eligible==30000 and delivered.governance.active.required_votes==15000
    with pytest.raises(ValueError,match='absent or spent'):
        deliver_escrow(operation.governance,delivered.holdings,operation.outputs[0])
    assert (await c['client'].push_tx(delivered.operation.bundle()))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('fault',['holder','locked','owner','inflation','duplicate','source','parent','too-many','zero-owner'])
async def test_grant_preparation_rejects_invalid_allocation(generation,fault):
    c=generation;reserve=SGTInput(c['issue'].coins[3],c['issue'].outputs[3],c['issue'].eve_spend)
    output=SGTOutput(HoldingKind.UNDELIVERED_ESCROW,c['owners'][2].get_tree_hash(),10000)
    outputs=(output,replace(reserve.descriptor,amount=960000))
    if fault=='holder':outputs=(replace(output,kind=HoldingKind.HOLDER),outputs[1])
    elif fault=='locked':outputs=(replace(output,kind=HoldingKind.LOCKED_HOLDER,lock_id=c['bindings'].generation),outputs[1])
    elif fault=='owner':outputs=(output,replace(outputs[1],owner=output.owner))
    elif fault=='inflation':outputs=(replace(output,amount=10001),outputs[1])
    elif fault=='duplicate':outputs=(output,output,replace(outputs[1],amount=950000))
    elif fault=='source':reserve=SGTInput(c['issue'].coins[0],c['issue'].outputs[0],c['issue'].eve_spend)
    elif fault=='parent':reserve=replace(reserve,parent=make_spend(c['issue'].eve_coin,Program.to(1),Program.to([])))
    elif fault=='too-many':outputs=(output,)*33
    elif fault=='zero-owner':outputs=(replace(output,owner=type(output.owner).zeros),outputs[1])
    with pytest.raises(ValueError):grant_bill(c['bindings'],reserve,outputs)
