"""Consensus simulation for the complete governance-approved deed launch.

The execute bundle contains every trust-bearing spend required by a mint:
governance, protocol DID, property registry, proposal state, and the exact
pre-created deed launcher.  No assertion in this test is satisfied by a
synthetic announcement; SpendSim evaluates the complete multi-coin bundle.
"""
from __future__ import annotations

import pytest
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.cat_wallet.cat_utils import CAT_MOD_HASH
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    launch_conditions_and_coinsol,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, Coin, G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles import mint_proposal_v2_driver as proposal_driver
from solslot_puzzles import property_registry_driver as registry_driver
from solslot_puzzles.mint_publish_driver import (
    build_mint_publish_artifacts,
    deed_launcher_puzzle_hash,
)
from solslot_puzzles.protocol_deployment import (
    build_quorum_did_mint_coin_spend,
    quorum_did_inner_puzzle,
    singleton_struct,
)
from solslot_puzzles.sgt_driver import (
    build_tracker_execute_coin_spend,
    kos_mint_execute_signing_message,
    proposal_tracker_inner_puzzle,
    sgt_free_inner_mod,
    sgt_locked_inner_mod,
)


QUORUM_BPS = 5000
VOTING_WINDOW = 300
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000
DEADLINE = 5000


@pytest.mark.asyncio
async def test_complete_mint_execute_bundle_passes_consensus() -> None:
    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client = SimClient(sim)
        acs = Program.to(1)
        acs_hash = bytes32(acs.get_tree_hash())
        await sim.farm_block()
        sim.pass_time(uint64(10_000))
        for _ in range(3):
            await sim.farm_block(acs_hash)
        origins = [
            record.coin
            for record in await client.get_coin_records_by_puzzle_hash(
                acs_hash, include_spent_coins=False
            )
        ]
        assert len(origins) >= 5
        tracker_origin, did_origin, registry_origin, proposal_origin, deed_origin = origins[:5]

        tracker_launcher_id = bytes32(
            Coin(tracker_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        )
        tracker_struct = singleton_struct(tracker_launcher_id)

        did_launcher_id = bytes32(
            Coin(did_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        )
        did_struct = singleton_struct(did_launcher_id)
        did_inner = quorum_did_inner_puzzle(tracker_launcher_id)
        did_full_hash = bytes32(
            puzzle_for_singleton(did_launcher_id, did_inner).get_tree_hash()
        )

        registry_sk = AugSchemeMPL.key_gen(b"solslot-property-registry-sim-key")
        registry_pk = bytes(registry_sk.get_g1())
        kos_sk = AugSchemeMPL.key_gen(b"solslot-mint-execute-cosigner-sim-key")
        kos_pk = bytes(kos_sk.get_g1())
        registry_launcher_id = bytes32(
            Coin(registry_origin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)).name()
        )
        registry_inner = registry_driver.make_inner_puzzle(
            registry_pk,
            registry_version=0,
        )
        registry_full_hash = bytes32(
            puzzle_for_singleton(registry_launcher_id, registry_inner).get_tree_hash()
        )

        property_id = registry_driver.canonicalise_property_id("TEST-DEED-0001")
        collection_id = bytes32(b"\xc1" * 32)
        owner_member_hash = bytes32(b"\xa1" * 32)
        gov_member_hash = bytes32(b"\xa2" * 32)
        pool_launcher_id = bytes32(b"\xb4" * 32)
        artifacts = build_mint_publish_artifacts(
            property_id_canon=property_id,
            collection_id_canon=collection_id,
            share_ppm=1_000_000,
            par_value_mojos=1_000_000,
            asset_class=1,
            jurisdiction=b"US",
            royalty_puzhash=bytes32(b"\xa3" * 32),
            royalty_bps=100,
            quorum_threshold=2,
            owner_member_hash=owner_member_hash,
            gov_member_hash=gov_member_hash,
            deed_launcher_parent_coin_name=bytes32(deed_origin.name()),
            proposal_launcher_parent_coin_name=bytes32(proposal_origin.name()),
            protocol_did_singleton_struct=did_struct,
            protocol_did_puzhash=did_full_hash,
            protocol_did_inner_puzhash=bytes32(did_inner.get_tree_hash()),
            governance_singleton_struct=tracker_struct,
            pool_singleton_launcher_id=pool_launcher_id,
            pool_singleton_launcher_puzzle_hash=SINGLETON_LAUNCHER_HASH,
            p2_pool_mod_hash=bytes32(load_puzzle("p2_pool_v2.clsp").get_tree_hash()),
            p2_vault_mod_hash=bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
            property_registry_puzzle_hash=registry_full_hash,
        )

        pool_struct = Program.to(
            (
                SINGLETON_MOD_HASH,
                (pool_launcher_id, SINGLETON_LAUNCHER_HASH),
            )
        )
        tracker_inner = proposal_tracker_inner_puzzle(
            tracker_struct,
            bytes32(sgt_free_inner_mod().get_tree_hash()),
            bytes32(sgt_locked_inner_mod().get_tree_hash()),
            CAT_MOD_HASH,
            bytes32(b"\xb5" * 32),
            did_full_hash,
            pool_struct,
            QUORUM_BPS,
            VOTING_WINDOW,
            SGT_TOTAL_SUPPLY,
            MIN_PROPOSAL_STAKE,
            kos_pk,
            proposal_hash=artifacts.proposal_hash,
            bill_operation=artifacts.bill_op_program,
            vote_tally=SGT_TOTAL_SUPPLY,
            voting_deadline=DEADLINE,
        )
        proposal_inner = proposal_driver.make_inner_puzzle(
            owner_member_hash=owner_member_hash,
            gov_member_hash=gov_member_hash,
            proposal_data_hash=artifacts.proposal_data_hash,
            governance_singleton_struct=tracker_struct,
            governance_proposal_hash=artifacts.proposal_hash,
            deed_launcher_id=artifacts.deed_launcher_id,
            did_inner_puzzle_hash=bytes32(did_inner.get_tree_hash()),
            deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            proposal_state=proposal_driver.STATE_DRAFT,
            state_version=0,
        )
        assert bytes32(proposal_inner.get_tree_hash()) == artifacts.eve_inner_puzhash

        tracker_conditions, tracker_launcher_spend = launch_conditions_and_coinsol(
            tracker_origin, tracker_inner, [], uint64(1)
        )
        did_conditions, did_launcher_spend = launch_conditions_and_coinsol(
            did_origin, did_inner, [], uint64(1)
        )
        registry_conditions, registry_launcher_spend = launch_conditions_and_coinsol(
            registry_origin, registry_inner, [], uint64(1)
        )
        proposal_conditions, proposal_launcher_spend = launch_conditions_and_coinsol(
            proposal_origin, proposal_inner, [], uint64(1)
        )
        assert bytes32(proposal_launcher_spend.coin.name()) == artifacts.proposal_singleton_launcher_id

        custom_launcher_hash = deed_launcher_puzzle_hash(
            protocol_did_singleton_struct=did_struct
        )
        deed_launcher_coin = Coin(
            deed_origin.name(), custom_launcher_hash, uint64(1)
        )
        assert bytes32(deed_launcher_coin.name()) == artifacts.deed_launcher_id

        launch_bundle = SpendBundle(
            [
                make_spend(tracker_origin, acs, Program.to(tracker_conditions)),
                tracker_launcher_spend,
                make_spend(did_origin, acs, Program.to(did_conditions)),
                did_launcher_spend,
                make_spend(registry_origin, acs, Program.to(registry_conditions)),
                registry_launcher_spend,
                make_spend(proposal_origin, acs, Program.to(proposal_conditions)),
                proposal_launcher_spend,
                make_spend(
                    deed_origin,
                    acs,
                    Program.to([[51, custom_launcher_hash, 1]]),
                ),
            ],
            G2Element(),
        )
        launch_status, launch_error = await client.push_tx(launch_bundle)
        assert launch_error is None
        assert launch_status == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()

        tracker_coin = compute_additions(tracker_launcher_spend)[0]
        did_coin = compute_additions(did_launcher_spend)[0]
        registry_coin = compute_additions(registry_launcher_spend)[0]
        proposal_coin = compute_additions(proposal_launcher_spend)[0]

        tracker_execute = build_tracker_execute_coin_spend(
            tracker_coin=tracker_coin,
            tracker_inner_puzzle=tracker_inner,
            tracker_launcher_id=tracker_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(tracker_launcher_spend),
        )
        did_execute = build_quorum_did_mint_coin_spend(
            did_coin=did_coin,
            did_inner_puzzle=did_inner,
            did_launcher_id=did_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(did_launcher_spend),
            deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            governance_inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
        )
        registration = registry_driver.build_registration_coin_spend(
            registry_coin=registry_coin,
            registry_inner_puzzle=registry_inner,
            registry_launcher_id=registry_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(registry_launcher_spend),
            property_id_canon=property_id,
        )
        proposal_execute = proposal_driver.build_execute_coin_spend(
            proposal_coin=proposal_coin,
            proposal_inner_puzzle=proposal_inner,
            proposal_launcher_id=artifacts.proposal_singleton_launcher_id,
            lineage_proof=lineage_proof_for_coinsol(proposal_launcher_spend),
            governance_inner_puzzle_hash=bytes32(tracker_inner.get_tree_hash()),
        )
        custom_launcher = load_puzzle("singleton_launcher_with_did.clsp").curry(
            did_struct
        )
        deed_launch = make_spend(
            deed_launcher_coin,
            custom_launcher,
            Program.to(
                [
                    did_inner.get_tree_hash(),
                    artifacts.deed_full_puzhash,
                    1,
                    [],
                ]
            ),
        )

        registry_message = (
            bytes(registration.inner.agg_sig_me_message)
            + bytes(registry_coin.name())
            + bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA)
        )
        registry_signature = AugSchemeMPL.sign(registry_sk, registry_message)
        unsigned_kos_execute_bundle = SpendBundle(
            [
                tracker_execute,
                did_execute,
                registration.coin_spend,
                proposal_execute,
                deed_launch,
            ],
            registry_signature,
        )
        unsigned_status, unsigned_error = await client.push_tx(unsigned_kos_execute_bundle)
        assert unsigned_status != MempoolInclusionStatus.SUCCESS
        assert unsigned_error is not None

        kos_message = kos_mint_execute_signing_message(
            governance_singleton_struct=tracker_struct,
            governance_coin_id=bytes32(tracker_coin.name()),
            proposal_hash=artifacts.proposal_hash,
            agg_sig_me_additional_data=bytes(DEFAULT_CONSTANTS.AGG_SIG_ME_ADDITIONAL_DATA),
        )
        kos_signature = AugSchemeMPL.sign(kos_sk, kos_message)
        execute_bundle = SpendBundle(
            unsigned_kos_execute_bundle.coin_spends,
            AugSchemeMPL.aggregate([registry_signature, kos_signature]),
        )
        execute_status, execute_error = await client.push_tx(execute_bundle)
        assert execute_error is None, f"complete mint execute rejected: {execute_error}"
        assert execute_status == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()

        deed_records = await client.get_coin_records_by_puzzle_hash(
            artifacts.deed_full_puzhash,
            include_spent_coins=False,
        )
        assert len(deed_records) == 1
        assert deed_records[0].coin.parent_coin_info == artifacts.deed_launcher_id

        did_records = await client.get_coin_records_by_puzzle_hash(
            did_full_hash,
            include_spent_coins=False,
        )
        assert len(did_records) == 1, "protocol DID was not recreated"

        idle_tracker = proposal_tracker_inner_puzzle(
            tracker_struct,
            bytes32(sgt_free_inner_mod().get_tree_hash()),
            bytes32(sgt_locked_inner_mod().get_tree_hash()),
            CAT_MOD_HASH,
            bytes32(b"\xb5" * 32),
            did_full_hash,
            pool_struct,
            QUORUM_BPS,
            VOTING_WINDOW,
            SGT_TOTAL_SUPPLY,
            MIN_PROPOSAL_STAKE,
            kos_pk,
        )
        idle_records = await client.get_coin_records_by_puzzle_hash(
            bytes32(puzzle_for_singleton(tracker_launcher_id, idle_tracker).get_tree_hash()),
            include_spent_coins=False,
        )
        assert len(idle_records) == 1

        executed_proposal = proposal_driver.make_inner_puzzle(
            owner_member_hash=owner_member_hash,
            gov_member_hash=gov_member_hash,
            proposal_data_hash=artifacts.proposal_data_hash,
            governance_singleton_struct=tracker_struct,
            governance_proposal_hash=artifacts.proposal_hash,
            deed_launcher_id=artifacts.deed_launcher_id,
            did_inner_puzzle_hash=bytes32(did_inner.get_tree_hash()),
            deed_full_puzzle_hash=artifacts.deed_full_puzhash,
            proposal_state=proposal_driver.STATE_EXECUTED,
            state_version=1,
        )
        executed_records = await client.get_coin_records_by_puzzle_hash(
            bytes32(
                puzzle_for_singleton(
                    artifacts.proposal_singleton_launcher_id,
                    executed_proposal,
                ).get_tree_hash()
            ),
            include_spent_coins=False,
        )
        assert len(executed_records) == 1

        next_registry_inner = registry_driver.make_inner_puzzle(
            registry_pk,
            registry_version=1,
            registered_ids_root=registration.inner.new_registered_ids_root,
        )
        next_registry_records = await client.get_coin_records_by_puzzle_hash(
            bytes32(
                puzzle_for_singleton(
                    registry_launcher_id,
                    next_registry_inner,
                ).get_tree_hash()
            ),
            include_spent_coins=False,
        )
        assert len(next_registry_records) == 1
