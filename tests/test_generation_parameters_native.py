"""Economic parameter proposals use the real holder-vote kernel, never admins alone."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_parameters import GenerationParameters
from solslot_puzzles.generation_governance import ballot_witnesses
from solslot_puzzles.generation_registry import inner_solution
from tests.test_generation_registry_native import b32, authorize
from tests.test_generation_governance_native import generation,open_vote,anchor,vote,finalize,push


@pytest.mark.parametrize('principal', [1, 2, 99, 100, 101, 1000, 10000, 300000, 2**64-1])
def test_generation_fee_split_is_70_protocol_30_sgt_and_conserves_rounded_fee(principal):
    p=GenerationParameters(*(b32(n) for n in range(1,6)))
    fees=p.fee_split(principal)
    # Integer-only rounding is shared with the native pool: total fee rounds
    # up; protocol rounds up within it; rewards receive the exact remainder.
    total=(principal+99)//100
    protocol=min(total,(principal*70+9999)//10000)
    assert fees.total_fee_sols_mojos==total
    assert fees.protocol_fee_sols_mojos==protocol
    assert fees.sgt_rewards_fee_sols_mojos==total-protocol
    assert fees.protocol_fee_sols_mojos+fees.sgt_rewards_fee_sols_mojos==total
    if principal%10000==0:
        assert fees.sgt_rewards_fee_sols_mojos==principal*30//10000


@pytest.mark.parametrize('principal',[0,-1,True,1.5,2**64])
def test_generation_fee_rejects_invalid_amounts(principal):
    with pytest.raises(ValueError,match='positive uint64'):
        GenerationParameters(*(b32(n) for n in range(1,6))).fee_split(principal)


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['parameters'],indirect=True)
async def test_parameter_change_requires_full_vote_closure_and_exact_single_use_approval(generation):
    c=generation;p=c['parameters'];pc=c['parameters_coin']
    values=(86400,300,100,70,30,86400);bill=p.bill(values)
    logic=load_puzzle('generation_parameter_logic_v1.clsp')
    def change(revision=0,old=None,parameters=values,program=logic):
        return pc.spend(Program.to([b'UPDATE',[c['gov_coin'].inner.get_tree_hash(),revision,
            old or Program.to(list(p.values)).get_tree_hash(),list(parameters),program]]))
    # Even owner+one publication authority cannot masquerade as a holder vote.
    message=Program.to([b'APPLY_PARAMETERS',p.generation,bill]).get_tree_hash()
    impostor=authorize(c['admin_coin'],pc,message)
    assert (await c['client'].push_tx(SpendBundle([change(),impostor],G2Element())))[0]==MempoolInclusionStatus.FAILED
    proposal=await open_vote(c,bill)
    born=await anchor(c)
    await vote(c,[1])
    assert c['gov'].active.required_votes==15000 and c['gov'].active.yes_weight==20000
    # Activation clearance is unavailable until the vote is closed, including
    # when only a different economic component would be upgraded.
    with pytest.raises(ValueError):
        c['gov_coin'].inner.run(inner_solution('ACTIVATION_CLEARANCE',c['gov_coin'].coin,
            [c['registry_coin'].inner.get_tree_hash(),b32(99)]))
    execute_args=[proposal,bill,c['gov'].approved.proof(c['gov'].action_key(proposal,bill)),pc.inner.get_tree_hash(),b32(0)]
    early=c['gov_coin'].spend(inner_solution('EXECUTE',c['gov_coin'].coin,execute_args))
    assert (await c['client'].push_tx(SpendBundle([early,change()],G2Element())))[0]==MempoolInclusionStatus.FAILED
    c['sim'].pass_time(uint64(3601));await c['sim'].farm_block();await finalize(c)
    gov=c['gov'];gc=c['gov_coin']
    execute=gc.spend(inner_solution('EXECUTE',gc.coin,[proposal,bill,
        gov.approved.proof(gov.action_key(proposal,bill)),pc.inner.get_tree_hash(),b32(0)]))
    for bad in (change(revision=1),change(old=b32(99)),change(parameters=(86400,300,101,30,71,86400)),
                change(parameters=(86400,301,100,70,30,86400)),change(program=Program.to(1))):
        assert (await c['client'].push_tx(SpendBundle([execute,bad],G2Element())))[0]==MempoolInclusionStatus.FAILED
    update=change();bundle=SpendBundle([execute,update],G2Element())
    from solslot_puzzles.generation_transactions import SingletonTip,apply_parameters
    tip=lambda coin:SingletonTip(coin.launcher,coin.inner,coin.coin,coin.parent)
    operation,_,_=apply_parameters(gov,tip(gc),c['registry'],tip(c['registry_coin']),p,tip(pc),proposal,values)
    assert operation.bundle()==bundle
    with pytest.raises(ValueError):
        apply_parameters(gov,tip(gc),c['registry'],tip(c['registry_coin']),p,tip(pc),proposal,(86400,300,100,30,70,86400))
    await push(c,list(operation.spends))
    new=p.updated(values);pc.advance(update,new.inner());gc.advance(execute,gov.executed(proposal,bill).inner())
    assert (await c['client'].get_coin_record_by_name(pc.coin.name())).spent is False
    assert new.revision==1 and new.values==values
    assert (await c['client'].push_tx(bundle))[0]==MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('generation',['parameters'],indirect=True)
async def test_unknown_parameter_authorities_and_voting_parameter_mutations_are_not_proposable(generation):
    c=generation;p=c['parameters'];gc=c['gov_coin'];reg=c['registry_coin']
    bill=p.bill((86400,300,100,70,30,86400)).as_python()
    issued=int(c['sim'].timestamp)-1
    sponsors=ballot_witnesses(c['tree'],[c['issue'].coins[0].name()],c['gov'].closed)
    def opening(candidate):
        return inner_solution('OPEN',gc.coin,[c['admin_coin'].inner.get_tree_hash(),issued,
            issued+86400,reg.inner.get_tree_hash(),c['ledger_coin'].inner.get_tree_hash(),
            c['tree'].root.program(),c['sequence'],candidate,sponsors])
    # Positive controls ensure failures below come from the mutated field,
    # rather than an unrelated missing sponsor or invalid timestamp.
    assert list(gc.inner.run(opening(bill)).as_iter())
    assert list(reg.inner.run(inner_solution('AUTHORIZE_NEW',reg.coin,
        [1,gc.coin.puzzle_hash,b32(98),bill])).as_iter())
    wrong=list(bill);wrong[2]=b32(99)
    with pytest.raises(ValueError):reg.inner.run(inner_solution('AUTHORIZE_NEW',reg.coin,[1,gc.coin.puzzle_hash,b32(98),wrong]))
    for values in ([3600,5000,10000,86400,600,100,70,30,86400], # Retired voting parameter vector.
                   [86400,600,101,30,71,86400], [86400,600,100,50,70,86400],
                   [86400,0,100,70,30,86400]):
        bad=list(bill);bad[5]=values
        # Exercise the CLVM validator directly as OPEN; no builder can sanitize
        # this attacker-controlled bill before the immutable boundary sees it.
        with pytest.raises(ValueError):gc.inner.run(opening(bad))
        with pytest.raises(ValueError):p.bill(values)
