"""Reconstruct the real chain, including opening time across votes and upgrade."""
from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs import Coin
from chia_rs.sized_ints import uint64

from solslot_puzzles.generation_governance_reader import reconstruct_governance_successor
from tests.test_generation_governance_native import generation, perform_upgrade, unlock_all
from tests.test_generation_registry_native import b32


@pytest.mark.asyncio
async def test_replay_confirmed_vote_upgrade_and_unlock(generation):
    c = generation
    initial, start = c['gov'], c['gov_coin'].coin
    proposal = await perform_upgrade(c)
    await unlock_all(c, proposal)
    state, coin, actions, deadlines = initial, start, [], []
    while True:
        record = await c['client'].get_coin_record_by_name(coin.name())
        if not record.spent:
            break
        spend = await c['client'].get_puzzle_and_solution(coin.name(), record.spent_block_index)
        transition = reconstruct_governance_successor(spend, state)
        actions.append(transition.action)
        assert transition.successor == Coin(coin.name(), puzzle_for_singleton(
            initial.sgt.governance_launcher_id, transition.after.inner()).get_tree_hash(), uint64(1))
        if transition.action == 'OPEN':
            assert transition.publication_expires_at - transition.publication_issued_at == 86400
            assert transition.after.active.snapshot.eligible == 30000
            assert transition.after.active.required_votes == 15000
            assert transition.after.active.yes_weight == 10000
            assert transition.after.active.opened_at == 0
        if transition.after.active and transition.after.active.opened_at:
            deadlines.append(transition.after.active.voting_closes_at)
        if transition.action == 'UPGRADE':
            assert transition.before.state() == transition.after.state()
            assert transition.before.module_hash != transition.after.module_hash
            assert transition.after.version == 2
        with pytest.raises(ValueError, match='last verified state'):
            reconstruct_governance_successor(spend, replace(state, nonce=state.nonce + 100))
        with pytest.raises(ValueError):
            reconstruct_governance_successor(spend, replace(state, sgt=replace(state.sgt, generation=b32(99))))
        with pytest.raises(ValueError, match='confirmed singleton'):
            reconstruct_governance_successor(make_spend(coin, Program.to(1), Program.to([])), state)
        state, coin = transition.after, transition.successor
    assert actions == ['OPEN', 'ANCHOR', 'VOTE', 'FINALIZE', 'EXECUTE', 'UPGRADE', 'READ', 'UNLOCK']
    assert len(deadlines) == 2 and len(set(deadlines)) == 1
    assert state.inner() == c['gov'].inner() and coin == c['gov_coin'].coin
    assert proposal in state.closed.keys and not state.approved.keys
