"""Actual CAT/custody/governance transactions built by production helpers."""
from dataclasses import replace

import pytest
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import AugSchemeMPL, G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_ballots import CurrentHoldings, CustodyAuthorization, SGTInput, open_proposal, cast_vote, unlock_stakes
from solslot_puzzles.generation_transactions import anchor_vote, finalize_vote
from solslot_puzzles.generation_vault import signing_digest, authorization_hash
from solslot_puzzles.generation_sgt import transition_digest
from solslot_puzzles.holdings import HoldingKind, HoldingsTree
from tests.test_generation_governance_native import generation
from tests.test_generation_registry_native import b32, authorize
from tests.test_generation_transactions_native import tip


def holdings(c):
    return CurrentHoldings(c['bindings'],c['tree'],c['sequence'],tip(c['ledger_coin']))


def initial(c,index):
    return SGTInput(c['issue'].coins[index],c['issue'].outputs[index],c['issue'].eve_spend)


def authorizations(c,proposal,indices,inputs=None):
    result,signatures=[],[]
    for index in indices:
        item=inputs[index] if inputs else initial(c,index)
        vault=tip(c['vaults'][index]);expires=int(c['sim'].timestamp)+600
        out=replace(item.descriptor,kind=HoldingKind.LOCKED_HOLDER,lock_id=proposal)
        digest=transition_digest(c['bindings'],item.coin,'LOCK',(out,))
        key=c['custody_keys'][index];sig=b''
        if c['custody_types'][index]==1:
            operation=authorization_hash(c['bindings'].generation,vault.coin.name(),item.coin.name(),digest,expires)
            signatures.append(AugSchemeMPL.sign(key,bytes(operation)+vault.coin.name()+DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA))
        else:
            sig=key.sign_msg_hash(signing_digest(c['bindings'].generation,vault.coin.name(),item.coin.name(),digest,expires)).to_bytes()[:64]
        result.append(CustodyAuthorization(item,vault,expires,sig))
    return tuple(result),AugSchemeMPL.aggregate(signatures)


async def apply(c,operation,signature=G2Element()):
    signed=operation.with_aggregated_signature(signature)
    assert signed.bundle().aggregated_signature==signature
    assert await c['client'].push_tx(signed.bundle())==(MempoolInclusionStatus.SUCCESS,None)
    await c['sim'].farm_block()
    objects=[c[k] for k in ('gov_coin','registry_coin','ledger_coin','admin_coin')]+c['vaults']
    for successor in operation.successors:
        record=await c['client'].get_coin_record_by_name(successor.coin.name())
        assert record and not record.spent
        for obj in objects:
            if obj.launcher==successor.launcher_id:obj.advance(successor.parent,successor.inner)


def adopt(c,result):
    c.update(gov=result.governance,tree=result.holdings.tree,sequence=result.holdings.sequence)


def opening(c,indices=(0,),inputs=None):
    bill=Program.to([b'REOPEN',0,2]);gov=c['gov'];proposal=gov.proposal_id(bill,c['tree'])
    auth,sig=authorizations(c,proposal,indices,inputs)
    issued=int(c['sim'].timestamp)-1
    approval=authorize(c['admin_coin'],c['gov_coin'],Program.to([
        b'PUBLICATION_APPROVAL',gov.sgt.generation,proposal,issued,issued+86400]).get_tree_hash())
    args=(gov,tip(c['gov_coin']),c['registry'],tip(c['registry_coin']),holdings(c),bill,tip(c['admin_coin']),(approval,),issued)
    return open_proposal(*args,auth),auth,sig,args


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',[True],indirect=True)
async def test_production_ballot_builders_whole_coin_custody_vote_and_safe_unlock(generation):
    c=generation;snapshot=c['tree']
    c['sim'].pass_time(uint64(1000));await c['sim'].farm_block()
    opened,auth,signature,_=opening(c)
    assert opened.governance.active.yes_weight==10000 and opened.governance.active.required_votes==15000
    assert opened.holdings.tree.root.eligible==30000 and opened.holdings.tree.root.total==1000000
    await apply(c,opened.operation,signature);adopt(c,opened)
    clock=opened.operation.auxiliary_outputs[0]
    birth=int((await c['client'].get_coin_record_by_name(clock.name())).timestamp)
    operation,anchored=anchor_vote(c['gov'],tip(c['gov_coin']),clock,birth)
    await apply(c,operation);c['gov']=anchored
    auth,signature=authorizations(c,c['gov'].active.proposal_id,(1,))
    voted=cast_vote(c['gov'],tip(c['gov_coin']),holdings(c),snapshot,auth)
    await apply(c,voted.operation,signature);adopt(c,voted)
    assert c['gov'].active.opened_at==birth and c['gov'].active.voting_closes_at==birth+3600
    locked=opened.outputs+voted.outputs
    with pytest.raises(ValueError,match='closed proposal'):
        unlock_stakes(c['gov'],tip(c['gov_coin']),holdings(c),locked)
    operation,closed=finalize_vote(c['gov'],tip(c['gov_coin']))
    assert (await c['client'].push_tx(operation.bundle()))[0]!=MempoolInclusionStatus.SUCCESS
    c['sim'].pass_time(uint64(3601));await c['sim'].farm_block()
    await apply(c,operation);c['gov']=closed
    unlocked=unlock_stakes(c['gov'],tip(c['gov_coin']),holdings(c),locked)
    assert [i.descriptor.owner for i in unlocked.outputs]==[i.descriptor.owner for i in locked]
    assert [i.coin.amount for i in unlocked.outputs]==[10000,10000]
    await apply(c,unlocked.operation);adopt(c,unlocked)
    assert all(i.kind!=HoldingKind.LOCKED_HOLDER for i in c['tree'].holdings.values())
    assert (await c['client'].push_tx(unlocked.operation.bundle()))[0]!=MempoolInclusionStatus.SUCCESS


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',[True],indirect=True)
async def test_ballot_builders_reject_substituted_snapshot_holding_custody_and_consent(generation):
    c=generation;c['sim'].pass_time(uint64(1000));await c['sim'].farm_block()
    opened,auth,sig,args=opening(c)
    holding=auth[0].holding
    for bad in (replace(holding,coin=replace_coin(holding.coin,amount=9999)),
                replace(holding,parent=c['vaults'][0].parent),
                replace(holding,descriptor=replace(holding.descriptor,owner=b32(94)))):
        with pytest.raises(ValueError):open_proposal(*args,(replace(auth[0],holding=bad),))
    for bad_auth in ((auth[0],auth[0]),(replace(auth[0],vault=tip(c['vaults'][1])),),
                     (replace(auth[0],holding=initial(c,3)),),(replace(auth[0],expires_at=True),)):
        with pytest.raises(ValueError):open_proposal(*args,bad_auth)
    with pytest.raises(ValueError):open_proposal(*args[:4],replace(args[4],sequence=1),*args[5:],auth)
    with pytest.raises(ValueError):open_proposal(*args[:7],(),args[8],auth)
    # Removing either custody, CAT, snapshot, ledger or authority spend cannot
    # leave an independently spendable signed piece or count votes without locks.
    for index in range(len(opened.operation.spends)):
        bundle=SpendBundle(list(opened.operation.spends[:index]+opened.operation.spends[index+1:]),sig)
        assert (await c['client'].push_tx(bundle))[0]!=MempoolInclusionStatus.SUCCESS
    await apply(c,opened.operation,sig);adopt(c,opened)
    clock=opened.operation.auxiliary_outputs[0]
    birth=int((await c['client'].get_coin_record_by_name(clock.name())).timestamp)
    op,gov=anchor_vote(c['gov'],tip(c['gov_coin']),clock,birth)
    await apply(c,op);c['gov']=gov
    second,_=authorizations(c,gov.active.proposal_id,(1,))
    with pytest.raises(ValueError,match='exact confirmed opening snapshot'):
        cast_vote(gov,tip(c['gov_coin']),holdings(c),c['tree'],second)
    with pytest.raises(ValueError):
        cast_vote(gov,tip(c['gov_coin']),holdings(c),HoldingsTree({}),second)
    # The original sponsor input is spent; it cannot vote a second time.
    with pytest.raises(ValueError):
        cast_vote(gov,tip(c['gov_coin']),holdings(c),c['issue'].holdings,auth)


def replace_coin(coin,amount):
    from chia_rs import Coin
    return Coin(coin.parent_coin_info,coin.puzzle_hash,uint64(amount))


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',[True],indirect=True)
async def test_closed_whole_stake_can_cosponsor_next_snapshot_without_custody_pooling(generation):
    c=generation;c['sim'].pass_time(uint64(1000));await c['sim'].farm_block()
    opened,auth,sig,_=opening(c,indices=(0,1))
    assert opened.governance.active.yes_weight==20000
    await apply(c,opened.operation,sig);adopt(c,opened)
    clock=opened.operation.auxiliary_outputs[0]
    birth=int((await c['client'].get_coin_record_by_name(clock.name())).timestamp)
    op,gov=anchor_vote(c['gov'],tip(c['gov_coin']),clock,birth)
    await apply(c,op);c['gov']=gov
    c['sim'].pass_time(uint64(3601));await c['sim'].farm_block()
    op,gov=finalize_vote(c['gov'],tip(c['gov_coin']))
    await apply(c,op);c['gov']=gov
    next_open,auth,sig,_=opening(c,indices=(0,1),inputs=opened.outputs)
    assert next_open.governance.active.proposal_id!=opened.governance.active.proposal_id
    await apply(c,next_open.operation,sig)
    assert [v.descriptor.owner for v in next_open.outputs]==[v.descriptor.owner for v in opened.outputs]
