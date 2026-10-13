"""Real CAT issuance/transfers and authenticated ledger updates in SpendSim."""
from dataclasses import replace

import pytest
import pytest_asyncio
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, SpendableCAT, construct_cat_puzzle, unsigned_spend_bundle_for_spendable_cats
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, launch_conditions_and_coinsol
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_sgt import (
    SGTBindings, SGTOutput, GenesisIssuancePlan, build_initial_issuance, ledger_inner, transition_digest, transition_witness,
)
from solslot_puzzles.holdings import HoldingKind, HoldingsTree, quorum
from solslot_puzzles.generation_holdings_reader import reconstruct_holdings_successor
from tests.test_generation_registry_native import Singleton, b32


@pytest_asyncio.fixture
async def sgt_chain():
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client = SimClient(sim)
        acs = Program.to(1)
        for _ in range(3): await sim.farm_block(acs.get_tree_hash())
        origins = [r.coin for r in await client.get_coin_records_by_puzzle_hash(
            acs.get_tree_hash(), include_spent_coins=False)]
        genesis, ledger_origin = origins[:2]
        launcher = Coin(ledger_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        owners = [acs, Program.to([2, (1, 1), 1]), Program.to([2, (1, [2, (1, 1), 1]), 1])]
        plan = GenesisIssuancePlan(genesis.name(), b32(1), launcher, b32(2), b32(3),
                                  tuple(p.get_tree_hash() for p in owners), b32(88))
        bindings, issue = plan.bindings(), build_initial_issuance(plan)
        inner = ledger_inner(bindings, issue.holdings, 0)
        conditions, launch = launch_conditions_and_coinsol(ledger_origin, inner, [], uint64(1))
        conditions.append(Program.to([51, acs.get_tree_hash(), int(ledger_origin.amount) - 1]))
        funding = make_spend(genesis, acs, Program.to([
            [51, issue.eve_coin.puzzle_hash, 1_000_000],
            [51, acs.get_tree_hash(), int(genesis.amount) - 1_000_000]]))
        spends = [funding, issue.eve_spend, make_spend(ledger_origin, acs, Program.to(conditions)), launch]
        ledger = Singleton(inner, launch)
        initialization = ledger.spend(issue.ledger_initialization())
        spends.append(initialization)
        assert await client.push_tx(SpendBundle(spends, G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
        await sim.farm_block()
        ledger.advance(initialization, inner)
        yield sim, client, bindings, issue, owners, ledger


def cat_spend(bindings, issue, owners, ledger, index, action, outputs, *, coin=None, descriptor=None, lineage=None):
    coin = coin or issue.coins[index]
    descriptor = descriptor or issue.outputs[index]
    if lineage is None:
        eve_inner = list(Program.from_bytes(bytes(issue.eve_spend.puzzle_reveal)).uncurry()[1].as_iter())[2]
        lineage = LineageProof(issue.eve_coin.parent_coin_info, eve_inner.get_tree_hash(), issue.eve_coin.amount)
    digest = transition_digest(bindings, coin, action, outputs)
    solution = Program.to([action.encode(), coin.name(), coin.amount, ledger.inner.get_tree_hash(),
                           owners[index % 3], [[1, b"SGT_AUTHORIZE", digest]], b"",
                           [v.descriptor() for v in outputs]])
    return SpendableCAT(coin=coin, limitations_program_hash=bindings.tail_hash,
                        inner_puzzle=descriptor.inner(bindings), inner_solution=solution, lineage_proof=lineage)


@pytest.mark.asyncio
async def test_genesis_exact_grants_no_id_gate_supply_and_bootstrap_replay(sgt_chain):
    _, client, bindings, issue, _, ledger = sgt_chain
    assert [c.amount for c in issue.coins] == [10_000, 10_000, 10_000, 970_000]
    assert issue.holdings.root.total == 1_000_000
    assert issue.holdings.root.eligible == 30_000
    assert quorum(issue.holdings.root.eligible) == 15_000
    for coin in issue.coins:
        record = await client.get_coin_record_by_name(coin.name())
        assert record is not None and not record.spent
    assert (await client.push_tx(SpendBundle([issue.eve_spend], G2Element())))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
async def test_transfer_split_then_merge_preserves_authenticated_supply(sgt_chain):
    sim, client, bindings, issue, owners, ledger = sgt_chain
    split = (replace(issue.outputs[0], amount=4_000), replace(issue.outputs[0], amount=6_000))
    witness, next_tree = transition_witness(bindings, issue.holdings, issue.coins[0], issue.outputs[0], "TRANSFER", split)
    cats = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [cat_spend(bindings, issue, owners, ledger, 0, "TRANSFER", split)])
    led_spend = ledger.spend(Program.to([b"UPDATE", [witness]]))
    assert await client.push_tx(SpendBundle([*cats.coin_spends, led_spend], G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
    await sim.farm_block()
    indexed = reconstruct_holdings_successor(led_spend,bindings,issue.holdings,0)
    assert indexed.tree.holdings == next_tree.holdings and indexed.sequence == 1
    assert indexed.consumed == (issue.coins[0].name(),) and len(indexed.created) == 2
    with pytest.raises(ValueError,match='last confirmed state'):
        reconstruct_holdings_successor(led_spend,bindings,next_tree,1)
    with pytest.raises(ValueError,match='last confirmed state'):
        reconstruct_holdings_successor(led_spend,replace(bindings,generation=b32(98)),issue.holdings,0)
    ledger.advance(led_spend, ledger_inner(bindings, next_tree, 1))
    assert indexed.successor == ledger.coin
    assert next_tree.root.eligible == 30_000 and next_tree.root.total == 1_000_000
    assert issue.coins[0].name() not in next_tree.holdings
    lineage = LineageProof(issue.coins[0].parent_coin_info, issue.outputs[0].inner(bindings).get_tree_hash(), issue.coins[0].amount)
    child_coins = [v.coin(bindings, issue.coins[0].name()) for v in split]
    witnesses, spends = [], []
    for coin, value, outputs in zip(child_coins, split, [(issue.outputs[0],), ()]):
        witness, next_tree = transition_witness(bindings, next_tree, coin, value, "TRANSFER", outputs)
        witnesses.append(witness)
        spends.append(cat_spend(bindings, issue, owners, ledger, 0, "TRANSFER", outputs,
                               coin=coin, descriptor=value, lineage=lineage))
    cats = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, spends)
    led_spend = ledger.spend(Program.to([b"UPDATE", witnesses]))
    assert await client.push_tx(SpendBundle([*cats.coin_spends, led_spend], G2Element())) == (MempoolInclusionStatus.SUCCESS, None)
    await sim.farm_block()
    merged = reconstruct_holdings_successor(led_spend,bindings,indexed.tree,indexed.sequence)
    assert merged.tree.holdings == next_tree.holdings and merged.sequence == 2
    assert len(merged.consumed) == 2 and len(merged.created) == 1
    ledger.advance(led_spend, ledger_inner(bindings, next_tree, 2))
    assert merged.successor == ledger.coin
    assert next_tree.root.eligible == 30_000 and next_tree.root.total == 1_000_000


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["missing_ledger", "missing_cat", "false_sum", "fake_coin", "wrong_generation", "duplicate_input", "overwrite_output"])
async def test_ledger_transfer_adversaries(sgt_chain, attack):
    _, client, bindings, issue, owners, ledger = sgt_chain
    outputs = (replace(issue.outputs[0], owner=issue.outputs[1].owner),)
    witness, _ = transition_witness(bindings, issue.holdings, issue.coins[0], issue.outputs[0], "TRANSFER", outputs)
    cat = cat_spend(bindings, issue, owners, ledger, 0, "TRANSFER", outputs)
    cats = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [cat])
    if attack == "false_sum": witness[4][0][1] += 1
    if attack == "fake_coin": witness[0] = b32(77)
    if attack == "wrong_generation":
        witness[1][0] = outputs[0].full(replace(bindings, generation=b32(99))).get_tree_hash()
    if attack == "overwrite_output": witness[5][0] = issue.holdings.proof(issue.coins[1].name())
    led_spend = ledger.spend(Program.to([b"UPDATE", [witness] * (2 if attack == "duplicate_input" else 1)]))
    spends = ([] if attack == "missing_cat" else list(cats.coin_spends))
    if attack != "missing_ledger": spends.append(led_spend)
    assert (await client.push_tx(SpendBundle(spends, G2Element())))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,action", [(HoldingKind.RESERVE, "LOCK"), (HoldingKind.RESERVE, "TRANSFER"),
                                        (HoldingKind.UNDELIVERED_ESCROW, "LOCK")])
async def test_reserve_and_escrow_cannot_vote(sgt_chain, kind, action):
    _, _, bindings, issue, owners, ledger = sgt_chain
    source = replace(issue.outputs[3], kind=kind)
    locked = (replace(source, kind=HoldingKind.LOCKED_HOLDER, lock_id=b32(55)),)
    with pytest.raises(ValueError):
        source.inner(bindings).run(Program.to([action.encode(), issue.coins[3].name(), source.amount,
            ledger.inner.get_tree_hash(), owners[0], [], b32(66), [v.descriptor() for v in locked]]))


def test_invalid_recipient_set_rejected():
    with pytest.raises(ValueError, match="distinct"):
        GenesisIssuancePlan(b32(5), b32(1), b32(2), b32(3), b32(4), (b32(6),) * 3, b32(88))
    with pytest.raises(ValueError, match="non-reserve"):
        GenesisIssuancePlan(b32(5), b32(1), b32(2), b32(3), b32(4), (b32(6), b32(7), b32(4)), b32(88))


@pytest.mark.asyncio
@pytest.mark.parametrize('attack', ['omit_initialization', 'inflate_holder_supply', 'wrong_sequence'])
async def test_genesis_must_authenticate_exact_initial_holdings_in_the_same_bundle(attack):
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client, acs = SimClient(sim), Program.to(1)
        await sim.farm_block(acs.get_tree_hash())
        origins = await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())
        origin, ledger_origin = origins[0].coin, origins[1].coin
        launcher = Coin(ledger_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        plan = GenesisIssuancePlan(origin.name(), b32(1), launcher, b32(2), b32(3),
                                  (b32(4), b32(5), b32(6)), b32(7))
        bindings, issue = plan.bindings(), build_initial_issuance(plan)
        funding = make_spend(origin, acs, Program.to([[51, issue.eve_coin.puzzle_hash, 1_000_000],
            [51, acs.get_tree_hash(), int(origin.amount)-1_000_000]]))
        def launch_bundle(tree, sequence=0, initialize=True):
            inner = ledger_inner(bindings, tree, sequence)
            conditions, launch = launch_conditions_and_coinsol(ledger_origin, inner, [], uint64(1))
            conditions.append(Program.to([51, acs.get_tree_hash(), int(ledger_origin.amount)-1]))
            ledger = Singleton(inner, launch)
            init = ledger.spend(issue.ledger_initialization())
            spends = [funding, issue.eve_spend, make_spend(ledger_origin, acs, Program.to(conditions)), launch]
            if initialize: spends.append(init)
            return SpendBundle(spends, G2Element()), ledger, init
        forged = issue.holdings
        if attack == 'inflate_holder_supply':
            forged = HoldingsTree({coin: replace(holding, kind=HoldingKind.HOLDER)
                for coin, holding in issue.holdings.holdings.items()})
        bad, _, _ = launch_bundle(forged, int(attack == 'wrong_sequence'), attack != 'omit_initialization')
        assert (await client.push_tx(bad))[0] == MempoolInclusionStatus.FAILED
        good, ledger, init = launch_bundle(issue.holdings)
        assert await client.push_tx(good) == (MempoolInclusionStatus.SUCCESS, None)
        await sim.farm_block()
        ledger.advance(init, ledger.inner)
        # Even with the same immutable root, the launch-only handshake cannot
        # be replayed on the successor singleton output.
        replay = ledger.spend(issue.ledger_initialization())
        assert (await client.push_tx(SpendBundle([replay], G2Element())))[0] == MempoolInclusionStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize('attack', ['redirect', 'amount', 'alternate_eve', 'extra_eve', 'manifest', 'generation'])
async def test_tail_enforces_committed_genesis_not_only_builder(attack):
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client, acs = SimClient(sim), Program.to(1)
        await sim.farm_block(acs.get_tree_hash())
        origins = await client.get_coin_records_by_puzzle_hash(acs.get_tree_hash())
        origin, ledger_origin = origins[0].coin, origins[1].coin
        ledger_id = Coin(ledger_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        plan = GenesisIssuancePlan(origin.name(), b32(1), ledger_id, b32(3), b32(4),
                                  (b32(5), b32(6), b32(7)), b32(88))
        bindings, issue = plan.bindings(), build_initial_issuance(plan)
        inner = list(Program.from_bytes(bytes(issue.eve_spend.puzzle_reveal)).uncurry()[1].as_iter())[2]
        tail, amount = plan.tail(), 1_000_000
        if attack == 'redirect':
            inner = load_puzzle('generation_sgt_eve_v1.clsp').curry(bindings.program(),
                        [b32(99), b32(6), b32(7)], load_puzzle('generation_sgt_coin_v1.clsp').get_tree_hash(),
                        load_puzzle('generation_holdings_ledger_v1.clsp').get_tree_hash())
        if attack == 'generation':
            inner = load_puzzle('generation_sgt_eve_v1.clsp').curry(
                replace(bindings, generation=b32(99)).program(), list(plan.recipient_owners),
                load_puzzle('generation_sgt_coin_v1.clsp').get_tree_hash(),
                load_puzzle('generation_holdings_ledger_v1.clsp').get_tree_hash())
        if attack == 'amount': amount = 2_000_000
        if attack == 'manifest': tail = replace(plan, preparation_manifest_hash=b32(99)).tail()
        if attack in {'alternate_eve', 'extra_eve'}:
            # Same output conditions under a different inner program must not
            # allow a second eve identity from the same genesis parent.
            conditions = list(inner.run(Program.to([tail, issue.eve_coin.name(), issue.insertion_proofs])).as_iter())
            inner = Program.to((1, [[1, b'extra']] + conditions))
        eve = Coin(origin.name(), construct_cat_puzzle(CAT_MOD, bindings.tail_hash, inner).get_tree_hash(), uint64(amount))
        # Construct the adversarial CAT solution directly; the friendly CAT
        # builder evaluates inner puzzles and would reject some attacks first.
        evil = make_spend(eve, construct_cat_puzzle(CAT_MOD, bindings.tail_hash, inner), Program.to([
            [tail, eve.name(), issue.insertion_proofs], [], eve.name(),
            [eve.parent_coin_info, eve.puzzle_hash, amount],
            [eve.parent_coin_info, inner.get_tree_hash(), amount], 0, 1_000_000 - amount]))
        outputs = [[51, eve.puzzle_hash, amount]]
        spends = [evil]
        if attack == 'extra_eve':
            outputs.append([51, issue.eve_coin.puzzle_hash, 1_000_000])
            spends.append(issue.eve_spend)
        outputs.append([51, acs.get_tree_hash(), int(origin.amount) - sum(row[2] for row in outputs)])
        funding = make_spend(origin, acs, Program.to(outputs))
        li = ledger_inner(bindings, issue.holdings, 0)
        conditions, launch = launch_conditions_and_coinsol(ledger_origin, li, [], uint64(1))
        conditions.append(Program.to([51, acs.get_tree_hash(), int(ledger_origin.amount)-1]))
        ledger = Singleton(li, launch)
        init = ledger.spend(issue.ledger_initialization())
        assert (await client.push_tx(SpendBundle([funding, *spends,
            make_spend(ledger_origin, acs, Program.to(conditions)), launch, init], G2Element())))[0] == MempoolInclusionStatus.FAILED
