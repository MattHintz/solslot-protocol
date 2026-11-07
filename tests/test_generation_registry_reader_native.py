"""Real simulator spends, including old-reveal/new-output upgrade regression."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import SpendBundle, G2Element
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import inner_solution
from solslot_puzzles.generation_registry_reader import decode_registry_inner, reconstruct_registry_successor
from tests.test_generation_registry_native import chain, ratify, activation_spends, authorize, b32


@pytest.mark.asyncio
async def test_reader_reconstructs_current_output_after_native_activation(chain):
    sim,client,initial,state,objects=chain
    old_coin=objects[0].coin
    pending,ticket,plan=await ratify(chain)
    record=await client.get_coin_record_by_name(old_coin.name())
    spend=await client.get_puzzle_and_solution(old_coin.name(),record.spent_block_index)
    ratified=reconstruct_registry_successor(spend,initial)
    assert ratified.after==pending
    assert ratified.successor==objects[0].coin
    assert ratified.auxiliary_outputs==(ticket,)
    sim.pass_time(uint64(86401));await sim.farm_block()
    spends=activation_spends(chain,pending,ticket,plan)
    assert await client.push_tx(SpendBundle(spends,G2Element()))==(MempoolInclusionStatus.SUCCESS,None)
    await sim.farm_block()
    result=reconstruct_registry_successor(spends[0],pending)
    assert result.after==pending.activated(plan)
    assert result.before.components[0].module_hash==load_puzzle('generation_extension_v1.clsp').get_tree_hash()
    assert result.after.components[0].module_hash==load_puzzle('generation_extension_v2.clsp').get_tree_hash()
    assert result.after.components[0].kernel_hash==result.before.components[0].kernel_hash
    assert result.after.components[0].launcher_id==result.before.components[0].launcher_id
    assert result.successor.puzzle_hash!=spends[0].coin.puzzle_hash
    assert not result.after.pending and not result.auxiliary_outputs
    # Passing the successor as if it were the reveal is the original stale-state bug.
    with pytest.raises(ValueError,match='last verified state'):
        reconstruct_registry_successor(spends[0],result.after)
    for wrong in (replace(pending,generation=b32(99)),replace(pending,launcher_id=b32(99)),
                  replace(pending,governance_id=b32(99)),replace(pending,administrator_id=b32(99))):
        with pytest.raises(ValueError):reconstruct_registry_successor(spends[0],wrong)
    fake=make_spend(spends[0].coin,Program.to(1),Program.to([]))
    with pytest.raises(ValueError,match='confirmed input'):reconstruct_registry_successor(fake,pending)


@pytest.mark.asyncio
async def test_pause_and_delayed_reopen_project_exact_native_outputs(chain):
    sim,client,current,state,objects=chain
    reg,gov,_,_,admin=objects
    mask=16
    spend=reg.spend(inner_solution('PAUSE',reg.coin,[admin.inner.get_tree_hash(),mask]))
    approval=authorize(admin,reg,Program.to([b'PAUSE_NEW_OPERATIONS',current.generation,0,mask]).get_tree_hash())
    assert (await client.push_tx(SpendBundle([spend,approval],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    paused=reconstruct_registry_successor(spend,current).after
    reg.advance(spend,paused.inner());admin.advance(approval,admin.inner)
    pending,ticket=paused.reopen_ratified(reg.coin,mask)
    spend=reg.spend(inner_solution('RATIFY_REOPEN',reg.coin,[gov.inner.get_tree_hash(),mask]))
    approval=authorize(gov,reg,paused.reopen_ratification_message(mask))
    assert (await client.push_tx(SpendBundle([spend,approval],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    assert reconstruct_registry_successor(spend,paused).after==pending
    reg.advance(spend,pending.inner());gov.advance(approval,gov.inner)
    sim.pass_time(uint64(86401));await sim.farm_block()
    spend=reg.spend(inner_solution('REOPEN',reg.coin,[]))
    mature=make_spend(ticket,pending.ticket_puzzle(pending.reopening[0]),Program.to([reg.inner.get_tree_hash()]))
    assert (await client.push_tx(SpendBundle([spend,mature],G2Element())))[0]==MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    reopened=reconstruct_registry_successor(spend,pending)
    assert reopened.after==pending.reopened() and reopened.after.pause_mask==0
    assert reopened.after.pause_epoch==1


@pytest.mark.asyncio
async def test_decoder_checks_module_hash_and_exact_state_not_full_puzzle_hash(chain):
    _,_,state,_,_=chain
    args=dict(generation=state.generation,launcher_id=state.launcher_id,
              governance_id=state.governance_id,administrator_id=state.administrator_id)
    assert decode_registry_inner(state.inner(),**args)==state
    with pytest.raises(ValueError,match='frozen kernel'):
        decode_registry_inner(Program.to(1),**args)
    module,curried=state.inner().uncurry()
    values=list(curried.as_iter())
    values[0]=Program.to(state.inner().get_tree_hash())
    with pytest.raises(ValueError,match='binding changed'):
        decode_registry_inner(module.curry(*values),**args)
