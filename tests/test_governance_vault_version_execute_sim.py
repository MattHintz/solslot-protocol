"""chia-sim end-to-end proof: a governance EXECUTE of a vault-version bill,
co-spent with the vault_version_registry, actually advances the registry to the
ratified version on a simulated blockchain (Brick 3.5c-2).

``test_governance_vault_version_routine.py`` proves the announcement *ids* pair
at the puzzle level.  This goes the final step: it launches BOTH singletons on
``SpendSim``, co-spends the governance tracker (EXECUTE) and the registry
(SPEND_CODE_ROUTINE) in one bundle, pushes it through real mempool validation,
and confirms the registry's next on-chain coin is the new ``(code, params,
version)`` — and that the registry CANNOT advance without the governance
co-spend (the missing announcement is rejected by consensus).

The governance tracker is launched *directly* into its EXECUTE-ready state
(an active vault-version proposal already at quorum).  EXECUTE is indifferent to
how that state was reached — PROPOSE/VOTE are exercised elsewhere
(``test_governance_v2_lifecycle.py``) — so this isolates the EXECUTE -> registry
binding as a genuine consensus event.
"""
from __future__ import annotations

from typing import AsyncGenerator, Tuple

import pytest
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    launch_conditions_and_coinsol,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import vault_version_registry_driver as vvr
from solslot_puzzles.sgt_driver import (
    bill_vault_version,
    build_tracker_execute_coin_spend,
    proposal_hash_from_bill,
    proposal_tracker_inner_puzzle,
)

# ── Registry state ──────────────────────────────────────────────────────────
ADMIN_AUTHORITY_LAUNCHER_ID = bytes32(b"\xa1" * 32)
CUR_CODE = bytes32(b"\xc3" * 32)
CUR_PARAMS = bytes32(b"\xd4" * 32)
CUR_VERSION = 1

# The ratified vault-version bill: a CODE change to v2.
NEW_CODE = bytes32(b"\x10" * 32)
NEW_PARAMS = bytes32(b"\x20" * 32)
NEW_VERSION = 2

# ── Tracker immutable params (the VAULT_VERSION EXECUTE dispatch uses none of
# the SGT/DID/pool params, so these are inert sentinels) ─────────────────────
SGT_FREE_MOD_HASH = bytes32(b"\x31" * 32)
SGT_LOCKED_MOD_HASH = bytes32(b"\x32" * 32)
CAT_MOD_HASH = bytes32(b"\x33" * 32)
SGT_TAIL_HASH = bytes32(b"\x34" * 32)
DID_PUZHASH = bytes32(b"\x35" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (bytes32(b"\xc0" * 32), SINGLETON_LAUNCHER_HASH))
)
QUORUM_BPS = 5000
VOTING_WINDOW = 300
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000

# Voting deadline: must be <= the sim block timestamp at spend time.  The fixture
# farms genesis at ts=1; each test advances 10_000s before farming, so 5_000 is
# safely in the past for EXECUTE's ASSERT_SECONDS_ABSOLUTE.
DEADLINE = 5000
TIME_SKIP = uint64(10_000)


def _tracker_struct(launcher_id: bytes32) -> Program:
    return Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))


def _tracker_inner(
    launcher_id: bytes32, *, proposal_hash: int, bill: int, vote_tally: int, deadline: int
) -> Program:
    return proposal_tracker_inner_puzzle(
        _tracker_struct(launcher_id),
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH,
        SGT_TAIL_HASH,
        DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        SGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        proposal_hash=proposal_hash,
        bill_operation=bill,
        vote_tally=vote_tally,
        voting_deadline=deadline,
    )


@pytest.mark.asyncio
@pytest.fixture()
async def sim_chain() -> AsyncGenerator[Tuple[SpendSim, SimClient], None]:
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client: SimClient = SimClient(sim)
        await sim.farm_block()
        yield sim, client


@pytest.mark.asyncio
async def test_governance_execute_advances_registry_to_new_version(
    sim_chain: Tuple[SpendSim, SimClient]
):
    sim, client = sim_chain
    acs = Program.to(1)
    acs_ph = bytes32(acs.get_tree_hash())

    # Advance time (so EXECUTE's deadline is in the past) and farm two reward
    # coins to act as the two singleton launch origins.
    sim.pass_time(TIME_SKIP)
    await sim.farm_block(acs_ph)
    coins = [
        r.coin
        for r in await client.get_coin_records_by_puzzle_hash(
            acs_ph, include_spent_coins=False
        )
    ]
    assert len(coins) >= 2
    tracker_origin, registry_origin = coins[0], coins[1]

    # ── Governance tracker: launch directly into the EXECUTE-ready state ────
    bill = bill_vault_version(NEW_CODE, NEW_PARAMS, NEW_VERSION)
    tracker_launcher_id = bytes32(
        Coin(tracker_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
    )
    tracker_inner = _tracker_inner(
        tracker_launcher_id,
        proposal_hash=proposal_hash_from_bill(bill),
        bill=bill,
        vote_tally=SGT_TOTAL_SUPPLY,  # 100% > quorum
        deadline=DEADLINE,
    )
    trk_conds, trk_launcher_spend = launch_conditions_and_coinsol(
        tracker_origin, tracker_inner, [], uint64(1)
    )
    assert bytes32(trk_launcher_spend.coin.name()) == tracker_launcher_id
    trk_eve = compute_additions(trk_launcher_spend)[0]
    trk_origin_spend = make_spend(tracker_origin, acs, Program.to(trk_conds))
    trk_execute_spend = build_tracker_execute_coin_spend(
        tracker_coin=trk_eve,
        tracker_inner_puzzle=tracker_inner,
        tracker_launcher_id=tracker_launcher_id,
        lineage_proof=lineage_proof_for_coinsol(trk_launcher_spend),
    )

    # ── Registry: launch at v1, authorized by THIS governance launcher ──────
    registry_inner = vvr.make_inner_puzzle(
        admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
        governance_launcher_id=tracker_launcher_id,
        vault_inner_mod_hash=CUR_CODE,
        canonical_params_hash=CUR_PARAMS,
        vault_version=CUR_VERSION,
    )
    reg_conds, reg_launcher_spend = launch_conditions_and_coinsol(
        registry_origin, registry_inner, [], uint64(1)
    )
    reg_eve = compute_additions(reg_launcher_spend)[0]
    reg_launcher_id = bytes32(reg_launcher_spend.coin.name())
    reg_origin_spend = make_spend(registry_origin, acs, Program.to(reg_conds))
    reg_routine_spend, art = vvr.build_routine_coin_spend(
        registry_coin=reg_eve,
        current=vvr.parse_inner_puzzle(registry_inner),
        registry_launcher_id=reg_launcher_id,
        lineage_proof=lineage_proof_for_coinsol(reg_launcher_spend),
        authorizer_inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
        new_vault_inner_mod_hash=NEW_CODE,
        new_canonical_params_hash=NEW_PARAMS,
        new_vault_version=NEW_VERSION,
    )

    bundle = SpendBundle(
        [
            trk_origin_spend,
            trk_launcher_spend,
            reg_origin_spend,
            reg_launcher_spend,
            trk_execute_spend,
            reg_routine_spend,
        ],
        G2Element(),
    )
    status, err = await client.push_tx(bundle)
    assert err is None, f"governance+registry co-spend rejected: {err}"
    assert status == MempoolInclusionStatus.SUCCESS
    await sim.farm_block()

    # ── The registry's next coin is the ratified (code, params, version) ────
    v2_full_ph = bytes32(
        vvr.make_full_puzzle(
            launcher_id=reg_launcher_id,
            admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
            governance_launcher_id=tracker_launcher_id,
            vault_inner_mod_hash=NEW_CODE,
            canonical_params_hash=NEW_PARAMS,
            vault_version=NEW_VERSION,
        ).get_tree_hash()
    )
    v2_recs = await client.get_coin_records_by_puzzle_hash(
        v2_full_ph, include_spent_coins=False
    )
    assert len(v2_recs) == 1, "registry did not advance to the v2 state coin"
    assert v2_recs[0].coin.amount == 1
    assert bytes32(v2_recs[0].coin.parent_coin_info) == bytes32(reg_eve.name())

    # The old registry coin was consumed.
    old_reg = await client.get_coin_record_by_name(bytes32(reg_eve.name()))
    assert old_reg is not None and old_reg.spent

    # The tracker reset to IDLE (proposal cleared) and continues as a singleton.
    idle_inner = _tracker_inner(
        tracker_launcher_id, proposal_hash=0, bill=0, vote_tally=0, deadline=0
    )
    idle_ph = bytes32(
        puzzle_for_singleton(tracker_launcher_id, idle_inner).get_tree_hash()
    )
    idle_recs = await client.get_coin_records_by_puzzle_hash(
        idle_ph, include_spent_coins=False
    )
    assert len(idle_recs) == 1, "tracker did not reset to IDLE"


@pytest.mark.asyncio
async def test_registry_routine_rejected_without_governance_cospend(
    sim_chain: Tuple[SpendSim, SimClient]
):
    """The registry's SPEND_CODE_ROUTINE asserts a governance puzzle
    announcement.  Spending it WITHOUT co-spending the authorizing tracker
    leaves that assertion unsatisfied — consensus rejects the bundle, so a code
    change can never ship without SGT ratification."""
    sim, client = sim_chain
    acs = Program.to(1)
    acs_ph = bytes32(acs.get_tree_hash())
    sim.pass_time(TIME_SKIP)
    await sim.farm_block(acs_ph)
    origin = (
        await client.get_coin_records_by_puzzle_hash(acs_ph, include_spent_coins=False)
    )[0].coin

    registry_inner = vvr.make_inner_puzzle(
        admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
        governance_launcher_id=bytes32(b"\xb0" * 32),  # some governance singleton
        vault_inner_mod_hash=CUR_CODE,
        canonical_params_hash=CUR_PARAMS,
        vault_version=CUR_VERSION,
    )
    reg_conds, reg_launcher_spend = launch_conditions_and_coinsol(
        origin, registry_inner, [], uint64(1)
    )
    reg_eve = compute_additions(reg_launcher_spend)[0]
    reg_launcher_id = bytes32(reg_launcher_spend.coin.name())
    reg_origin_spend = make_spend(origin, acs, Program.to(reg_conds))
    reg_routine_spend, _ = vvr.build_routine_coin_spend(
        registry_coin=reg_eve,
        current=vvr.parse_inner_puzzle(registry_inner),
        registry_launcher_id=reg_launcher_id,
        lineage_proof=lineage_proof_for_coinsol(reg_launcher_spend),
        authorizer_inner_puzzle_hash=bytes32(b"\x77" * 32),
        new_vault_inner_mod_hash=NEW_CODE,
        new_canonical_params_hash=NEW_PARAMS,
        new_vault_version=NEW_VERSION,
    )
    bundle = SpendBundle(
        [reg_origin_spend, reg_launcher_spend, reg_routine_spend], G2Element()
    )
    status, err = await client.push_tx(bundle)
    assert err is not None, "registry advanced without the governance co-spend!"
    assert status == MempoolInclusionStatus.FAILED
