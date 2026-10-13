"""Native consensus tests of the registry boundary, with synthetic authorities.

The authority fixture can issue arbitrary messages and is simulator-only. These
tests do not claim to test holder ratification; that requires the governance
integration suite. No provider, live key or production state is used here.
"""
from dataclasses import replace

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol, lineage_proof_for_coinsol,
    puzzle_for_singleton, solution_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import (
    CodeChange, Component, Registry, UpgradePlan, inner_solution,
)


def b32(n):
    return bytes32(bytes([n]) * 32)


class Singleton:
    def __init__(self, inner, launch_spend):
        self.launcher = launch_spend.coin.name()
        self.inner = inner
        self.parent = launch_spend
        self.coin = compute_additions(launch_spend)[0]

    def spend(self, solution):
        return make_spend(self.coin, puzzle_for_singleton(self.launcher, self.inner),
                          solution_for_singleton(lineage_proof_for_coinsol(self.parent),
                                                 uint64(1), solution))

    def advance(self, spend, inner):
        self.coin = next(c for c in compute_additions(spend) if c.amount == 1)
        assert self.coin.puzzle_hash == puzzle_for_singleton(self.launcher, inner).get_tree_hash()
        self.inner, self.parent = inner, spend


@pytest_asyncio.fixture
async def chain():
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client = SimClient(sim)
        acs = Program.to(1)
        for _ in range(4):
            await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(
            acs.get_tree_hash(), include_spent_coins=False)]
        launchers = [Coin(c.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name() for c in origins[:5]]
        kernel = load_puzzle("generation_component_v1.clsp").get_tree_hash()
        old = load_puzzle("generation_extension_v1.clsp").get_tree_hash()
        components = tuple(Component(b32(i + 10), launchers[i + 2], kernel, old, 1, 1) for i in range(2))
        registry = Registry(b32(1), launchers[0], launchers[1], launchers[4], components)
        # State includes an arbitrary asset commitment. Extension logic cannot
        # change it. Asset custody is tested by the separate economic kernels.
        state = Program.to([b"state", b32(30), 30_000, 970_000])
        inners = [registry.inner(), acs] + [registry.component_inner(c, state) for c in components] + [acs]
        spends, objects = [], []
        for origin, inner in zip(origins, inners):
            conditions, launch = launch_conditions_and_coinsol(origin, inner, [], uint64(1))
            conditions.append(Program.to([51, acs.get_tree_hash(), int(origin.amount) - 1]))
            spends.extend([make_spend(origin, acs, Program.to(conditions)), launch])
            objects.append(Singleton(inner, launch))
        result = await client.push_tx(SpendBundle(spends, G2Element()))
        assert result == (MempoolInclusionStatus.SUCCESS, None)
        await sim.farm_block()
        yield sim, client, registry, state, objects


def plan_for(registry):
    new = load_puzzle("generation_extension_v2.clsp").get_tree_hash()
    return UpgradePlan(b32(40), tuple(CodeChange(c.component_id, c.module_hash, new, 2, 1)
                                      for c in registry.components))


def authorize(authority, target, message):
    return authority.spend(Program.to([[66, 18, message, target.coin.puzzle_hash],
                                      [51, authority.inner.get_tree_hash(), 1]]))


async def ratify(chain):
    sim, client, registry, state, objects = chain
    reg, gov, *_ = objects
    plan = plan_for(registry)
    pending, ticket = registry.ratified(reg.coin, plan)
    spend = reg.spend(inner_solution("RATIFY_UPGRADE", reg.coin,
                                     [gov.inner.get_tree_hash(), plan.program()]))
    approval = authorize(gov, reg, registry.ratification_message(plan))
    assert await client.push_tx(SpendBundle([spend, approval], G2Element())) == (
        MempoolInclusionStatus.SUCCESS, None)
    await sim.farm_block()
    reg.advance(spend, pending.inner())
    gov.advance(approval, gov.inner)
    return pending, ticket, plan


def activation_spends(chain, pending, ticket, plan, *, omit=None, change_state=False):
    sim, client, _, state, objects = chain
    reg, gov, first, second, admin = objects
    spends = [reg.spend(inner_solution("ACTIVATE", reg.coin,
                        [plan.program(), [[c.component_id, state] for c in pending.components], gov.inner.get_tree_hash()])),
              make_spend(ticket, pending.ticket_puzzle(pending.pending[0]),
                         Program.to([reg.inner.get_tree_hash()]))]
    for component, coin, change in zip(pending.components, [first, second], plan.changes):
        if omit == component.component_id:
            continue
        if change_state:
            # Revealing a different current state must fail the coin puzzle hash.
            coin = Singleton(pending.component_inner(component, Program.to([b"changed"])), coin.parent)
        spends.append(coin.spend(Program.to([b"UPGRADE", [reg.inner.get_tree_hash(),
            pending.pending[0], change.new_module_hash, change.next_version, change.compatibility]])))
    spends.append(authorize(gov,reg,Program.to([b'ACTIVATION_CLEARANCE',pending.generation,pending.pending[0]]).get_tree_hash()))
    return spends


@pytest.mark.asyncio
async def test_real_delay_atomic_activation_state_preservation_and_replay(chain):
    sim, client, _, state, objects = chain
    pending, ticket, plan = await ratify(chain)
    spends = activation_spends(chain, pending, ticket, plan)
    status, error = await client.push_tx(SpendBundle(spends, G2Element()))
    assert status != MempoolInclusionStatus.SUCCESS
    assert error is not None and "SECONDS_RELATIVE" in error.name
    sim.pass_time(uint64(86_401))
    await sim.farm_block()
    assert await client.push_tx(SpendBundle(spends, G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
    await sim.farm_block()
    active = pending.activated(plan)
    objects[0].advance(spends[0], active.inner())
    for component, obj, spend in zip(active.components, objects[2:4], spends[2:]):
        obj.advance(spend, active.component_inner(component, state))
        before = load_puzzle("generation_extension_v1.clsp")
        after = load_puzzle("generation_extension_v2.clsp")
        with pytest.raises(ValueError):
            before.run(Program.to([b"PROVE_STATE"]))
        assert after.run(Program.to([b"PROVE_STATE"])).as_int() == 1
        obj.inner.run(Program.to([b"READ", [after, b"PROVE_STATE"]]))
    assert (await client.get_coin_record_by_name(ticket.name())).spent
    assert (await client.push_tx(SpendBundle(spends, G2Element())))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["missing_component", "changed_state", "wrong_source", "old_ticket", "wrong_generation", "no_proposal_clearance"])
async def test_activation_adversaries_fail_consensus(chain, attack):
    sim, client, _, state, objects = chain
    pending, ticket, plan = await ratify(chain)
    sim.pass_time(uint64(90_000))
    await sim.farm_block()
    if attack == "wrong_source":
        plan = replace(plan, source_manifest_hash=b32(99))
    if attack == "wrong_generation":
        pending = replace(pending, generation=b32(99))
    if attack == "old_ticket":
        ticket = Coin(b32(99), ticket.puzzle_hash, uint64(0))
    spends = activation_spends(chain, pending, ticket, plan,
                              omit=pending.components[0].component_id if attack == "missing_component" else None,
                              change_state=attack == "changed_state")
    if attack == 'no_proposal_clearance':spends.pop()
    assert (await client.push_tx(SpendBundle(spends, G2Element())))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize("authority", ["missing", "administrator", "wrong_message"])
async def test_admin_cannot_ratify_code(chain, authority):
    _, client, registry, _, objects = chain
    reg, gov, _, _, admin = objects
    plan = plan_for(registry)
    selected = admin if authority == "administrator" else gov
    spend = reg.spend(inner_solution("RATIFY_UPGRADE", reg.coin,
                                    [gov.inner.get_tree_hash(), plan.program()]))
    extras = [] if authority == "missing" else [authorize(
        selected, reg, b32(55) if authority == "wrong_message" else registry.ratification_message(plan))]
    assert (await client.push_tx(SpendBundle([spend, *extras], G2Element())))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
async def test_pending_upgrade_cannot_be_replaced_and_can_be_paused(chain):
    sim, client, registry, _, objects = chain
    pending, _, plan = await ratify(chain)
    reg, gov, _, _, admin = objects
    with pytest.raises(ValueError):
        reg.inner.run(inner_solution("RATIFY_UPGRADE", reg.coin, [gov.inner.get_tree_hash(), plan.program()]))
    pause = reg.spend(inner_solution("PAUSE", reg.coin, [admin.inner.get_tree_hash(), 16]))
    approved = authorize(admin, reg, Program.to([b"PAUSE_NEW_OPERATIONS", pending.generation, 0, 16]).get_tree_hash())
    assert await client.push_tx(SpendBundle([pause, approved], G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
    await sim.farm_block()
    paused = replace(pending, pause_mask=16, pause_epoch=1)
    reg.advance(pause, paused.inner())
    with pytest.raises(ValueError, match="paused"):
        paused.activated(plan)


@pytest.mark.asyncio
async def test_pause_cannot_include_protected_operations(chain):
    _, _, registry, _, objects = chain
    reg, gov, _, _, admin = objects
    for mask in [0, -1, 32, 63, 2**64]:
        with pytest.raises(ValueError):
            reg.inner.run(inner_solution("PAUSE", reg.coin, [admin.inner.get_tree_hash(), mask]))


@pytest.mark.asyncio
async def test_reopening_has_own_real_delay_and_single_use_ticket(chain):
    sim, client, registry, _, objects = chain
    reg, gov, _, _, admin = objects
    pause = reg.spend(inner_solution('PAUSE', reg.coin, [admin.inner.get_tree_hash(), 3]))
    consent = authorize(admin, reg, Program.to([b'PAUSE_NEW_OPERATIONS', registry.generation, 0, 3]).get_tree_hash())
    assert (await client.push_tx(SpendBundle([pause, consent], G2Element())))[0] == MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    paused = registry.paused(3)
    reg.advance(pause, paused.inner()); admin.advance(consent, admin.inner)
    # Business remains paused; its typed reopening vote remains possible.
    with pytest.raises(ValueError):
        reg.inner.run(inner_solution('AUTHORIZE_NEW', reg.coin, [1, gov.coin.puzzle_hash, b32(42),
                            [b'MINT_TEST_ONLY', b32(50), b32(51), 25]]))
    reg.inner.run(inner_solution('AUTHORIZE_NEW', reg.coin, [1, gov.coin.puzzle_hash, b32(42), [b'REOPEN', 1, 3]]))
    pending, ticket = paused.reopen_ratified(reg.coin, 3)
    ratification = reg.spend(inner_solution('RATIFY_REOPEN', reg.coin, [gov.inner.get_tree_hash(), 3]))
    # Administrator consent cannot substitute for holder ratification.
    wrong = authorize(admin, reg, paused.reopen_ratification_message(3))
    assert (await client.push_tx(SpendBundle([ratification, wrong], G2Element())))[0] == MempoolInclusionStatus.FAILED
    right = authorize(gov, reg, paused.reopen_ratification_message(3))
    assert (await client.push_tx(SpendBundle([ratification, right], G2Element())))[0] == MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    reg.advance(ratification, pending.inner()); gov.advance(right, gov.inner)
    reopen = reg.spend(inner_solution('REOPEN', reg.coin, []))
    clock = make_spend(ticket, pending.ticket_puzzle(pending.reopening[0]), Program.to([reg.inner.get_tree_hash()]))
    bundle = SpendBundle([reopen, clock], G2Element())
    status, error = await client.push_tx(bundle)
    assert status != MempoolInclusionStatus.SUCCESS and 'SECONDS_RELATIVE' in error.name
    sim.pass_time(uint64(86_401)); await sim.farm_block()
    assert (await client.push_tx(bundle))[0] == MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    reg.advance(reopen, pending.reopened().inner())
    assert pending.reopened().pause_mask == 0
    assert (await client.push_tx(bundle))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
async def test_new_pause_invalidates_older_reopening_even_after_clock_matures(chain):
    sim, client, registry, _, objects = chain
    reg, gov, _, _, admin = objects
    pause = reg.spend(inner_solution('PAUSE', reg.coin, [admin.inner.get_tree_hash(), 2]))
    consent = authorize(admin, reg, Program.to([b'PAUSE_NEW_OPERATIONS', registry.generation, 0, 2]).get_tree_hash())
    assert (await client.push_tx(SpendBundle([pause, consent], G2Element())))[0] == MempoolInclusionStatus.SUCCESS
    await sim.farm_block()
    paused = registry.paused(2); reg.advance(pause, paused.inner()); admin.advance(consent, admin.inner)
    pending, ticket = paused.reopen_ratified(reg.coin, 2)
    ratify = reg.spend(inner_solution('RATIFY_REOPEN', reg.coin, [gov.inner.get_tree_hash(), 2]))
    approve = authorize(gov, reg, paused.reopen_ratification_message(2))
    assert (await client.push_tx(SpendBundle([ratify, approve], G2Element())))[0] == MempoolInclusionStatus.SUCCESS
    await sim.farm_block(); reg.advance(ratify, pending.inner())
    pause = reg.spend(inner_solution('PAUSE', reg.coin, [admin.inner.get_tree_hash(), 4]))
    consent = authorize(admin, reg, Program.to([b'PAUSE_NEW_OPERATIONS', registry.generation, 1, 4]).get_tree_hash())
    assert (await client.push_tx(SpendBundle([pause, consent], G2Element())))[0] == MempoolInclusionStatus.SUCCESS
    await sim.farm_block(); reg.advance(pause, pending.paused(4).inner())
    sim.pass_time(uint64(86_401)); await sim.farm_block()
    with pytest.raises(ValueError):
        reg.inner.run(inner_solution('REOPEN', reg.coin, []))
    assert not (await client.get_coin_record_by_name(ticket.name())).spent


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["downgrade", "same_module", "compatibility", "stale_module", "duplicate"])
async def test_invalid_changes_rejected_in_clvm(chain, mutation):
    _, _, registry, _, objects = chain
    plan = plan_for(registry).program()
    change = plan[1][0]
    if mutation == "downgrade": change[3] = 1
    if mutation == "same_module": change[2] = change[1]
    if mutation == "compatibility": change[4] = 2
    if mutation == "stale_module": change[1] = b32(90)
    if mutation == "duplicate": plan[1].append(change)
    with pytest.raises(ValueError):
        objects[0].inner.run(inner_solution("RATIFY_UPGRADE", objects[0].coin,
                                           [objects[1].inner.get_tree_hash(), plan]))
