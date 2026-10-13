"""Exercise production transaction builders against native SpendSim admission."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_governance import ProposalSet
from solslot_puzzles.generation_registry import CodeChange, UpgradePlan, inner_solution
from solslot_puzzles.generation_transactions import (
    SingletonTip, anchor_vote, finalize_vote, ratify_upgrade, activate_upgrade,
    ratify_reopening, reopen_operations,
)
from tests.test_generation_governance_native import generation, open_vote, vote, push, unlock_all
from tests.test_generation_registry_native import b32, authorize


def tip(value):
    return SingletonTip(value.launcher, value.inner, value.coin, value.parent)


async def apply(c, operation):
    before = operation.commitment
    assert await c['client'].push_tx(operation.bundle()) == (MempoolInclusionStatus.SUCCESS, None)
    await c['sim'].farm_block()
    for successor in operation.successors:
        record = await c['client'].get_coin_record_by_name(successor.coin.name())
        assert record and not record.spent and record.confirmed_block_index > 0
        for key in ('gov_coin', 'registry_coin', 'parameters_coin', 'mint_coin'):
            obj = c.get(key)
            if obj is not None and obj.launcher == successor.launcher_id:
                obj.advance(successor.parent, successor.inner)
                assert obj.coin == successor.coin
    assert before == operation.commitment  # Reconciliation cannot rebuild it.


async def close_bill(c, bill):
    proposal = await open_vote(c, bill)
    birth = int((await c['client'].get_coin_record_by_name(c['clock'].name())).timestamp)
    operation, updated = anchor_vote(c['gov'], tip(c['gov_coin']), c['clock'], birth)
    await apply(c, operation); c['gov'] = updated
    await vote(c, [1])
    operation, updated = finalize_vote(c['gov'], tip(c['gov_coin']))
    early = await c['client'].push_tx(operation.bundle())
    assert early[0] != MempoolInclusionStatus.SUCCESS and 'SECONDS_ABSOLUTE' in early[1].name
    c['sim'].pass_time(uint64(3601)); await c['sim'].farm_block()
    await apply(c, operation); c['gov'] = updated
    return proposal


@pytest.mark.asyncio
@pytest.mark.parametrize('generation', [True, 'parameters'], indirect=True, ids=['real-custodies', 'atomic-components'])
async def test_builders_upgrade_preserve_state_and_enforce_native_delay(generation):
    c = generation
    next_logic = load_puzzle('generation_extension_v2.clsp').get_tree_hash()
    changes = [CodeChange(c['gov'].component_id, c['gov'].module_hash, next_logic, 2, 1)]
    if c['parameters']:
        # A genuinely different executable wrapper; permanent parameter bounds
        # remain in the unchanged kernel regardless of replacement policy.
        policy = Program.to([2, (1, load_puzzle('generation_parameter_logic_v1.clsp')), 1])
        changes.append(CodeChange(c['parameters'].component_id, c['parameters'].logic_hash(), policy.get_tree_hash(), 2, 1))
    plan = UpgradePlan(b32(51), tuple(changes))
    proposal = await close_bill(c, Program.to([b'UPGRADE', 0, plan.program()]))
    operation, gov, registry = ratify_upgrade(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']), proposal, plan)
    ticket = operation.auxiliary_outputs[0]
    # Publication or a different approved bill cannot stand in for ratification.
    with pytest.raises(ValueError):
        ratify_upgrade(c['gov'], tip(c['gov_coin']), c['registry'], tip(c['registry_coin']), b32(97), plan)
    await apply(c, operation); c.update(gov=gov, registry=registry)
    state_before = gov.state()
    targets = [(gov, tip(c['gov_coin']))]
    if c['parameters']: targets.append((c['parameters'], tip(c['parameters_coin'])))
    args = (gov, tip(c['gov_coin']), registry, tip(c['registry_coin']), plan, ticket)
    for bad_targets in ((), tuple(targets) * 2, tuple(reversed(targets)) if len(targets) > 1 else ()):
        with pytest.raises(ValueError): activate_upgrade(*args, bad_targets)
    with pytest.raises(ValueError):
        activate_upgrade(*args[:-1], Coin(ticket.parent_coin_info, ticket.puzzle_hash, uint64(1)), tuple(targets))
    operation, activated, updated = activate_upgrade(*args, tuple(targets))
    independently_read=replace(gov,closed=ProposalSet(gov.closed.keys),approved=ProposalSet(gov.approved.keys))
    rebuilt=activate_upgrade(*args,((independently_read,tip(c['gov_coin'])),*targets[1:]))[0]
    assert rebuilt.bundle()==operation.bundle()
    early = await c['client'].push_tx(operation.bundle())
    assert early[0] != MempoolInclusionStatus.SUCCESS and 'SECONDS_RELATIVE' in early[1].name
    c['sim'].pass_time(uint64(86401)); await c['sim'].farm_block()
    for missing in range(len(operation.spends)):
        result = await c['client'].push_tx(SpendBundle(list(operation.spends[:missing] + operation.spends[missing+1:]), G2Element()))
        assert result[0] != MempoolInclusionStatus.SUCCESS
    await apply(c, operation)
    c.update(registry=activated, gov=updated[0])
    assert c['gov'].state() == state_before
    if c['parameters']:
        assert updated[1].state() == c['parameters'].state()
        c['parameters'] = updated[1]
    read = c['gov_coin'].spend(inner_solution('READ', c['gov_coin'].coin,
        [load_puzzle('generation_extension_v2.clsp'), b'PROVE_STATE']))
    await push(c, [read]); c['gov_coin'].advance(read, c['gov'].inner())
    await unlock_all(c, proposal)
    assert c['tree'].root.total == 1_000_000 and c['tree'].root.eligible == 30_000
    assert (await c['client'].push_tx(operation.bundle()))[0] != MempoolInclusionStatus.SUCCESS


@pytest.mark.asyncio
async def test_reopening_builder_retains_native_pause_and_delay_boundaries(generation):
    c = generation
    registry, reg, admin = c['registry'], c['registry_coin'], c['admin_coin']
    scope = 3
    pause = reg.spend(inner_solution('PAUSE', reg.coin, [admin.inner.get_tree_hash(), scope]))
    consent = authorize(admin, reg, Program.to([b'PAUSE_NEW_OPERATIONS', registry.generation, registry.pause_epoch, scope]).get_tree_hash())
    await push(c, [pause, consent])
    c['registry'] = registry.paused(scope)
    reg.advance(pause, c['registry'].inner()); admin.advance(consent, admin.inner)
    proposal = await close_bill(c, Program.to([b'REOPEN', c['registry'].pause_epoch, scope]))
    operation, gov, pending = ratify_reopening(c['gov'], tip(c['gov_coin']), c['registry'], tip(reg), proposal, scope)
    ticket = operation.auxiliary_outputs[0]
    await apply(c, operation); c.update(gov=gov, registry=pending)
    # Stakes can unlock during a pause and during the reopening delay.
    await unlock_all(c, proposal)
    operation, opened = reopen_operations(pending, tip(reg), ticket)
    early = await c['client'].push_tx(operation.bundle())
    assert early[0] != MempoolInclusionStatus.SUCCESS and 'SECONDS_RELATIVE' in early[1].name
    c['sim'].pass_time(uint64(86401)); await c['sim'].farm_block()
    await apply(c, operation)
    assert opened.pause_mask == 0 and not opened.reopening
    with pytest.raises(ValueError): reopen_operations(opened, tip(reg), ticket)


@pytest.mark.asyncio
async def test_tip_rejects_wrong_lineage_and_state_before_review(generation):
    c = generation; current = tip(c['gov_coin'])
    for corrupt in (replace(current, launcher_id=b32(87)), replace(current, parent=c['registry_coin'].parent),
                    replace(current, inner=c['registry'].inner())):
        with pytest.raises(ValueError): corrupt.validate()
    current.validate()
