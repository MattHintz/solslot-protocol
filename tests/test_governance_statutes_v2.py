from __future__ import annotations

import hashlib

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_puzzles.protocol_statutes_v1 import (
    BillTag,
    BridgeRoute,
    CollectionStatute,
    LiquidityVenue,
    MutationKind,
    OracleRound,
    ProtocolParameters,
    ScopedPause,
    StatuteMutation,
)
from solslot_puzzles.protocol_statutes_driver import governance_evidence_message
from solslot_puzzles.protocol_deployment import singleton_full_puzzle_hash
from solslot_puzzles.sgt_driver import (
    TEST_KOS_MINT_EXECUTE_PUBKEY,
    admin_governance_proposal_message,
    bill_sgt_grant,
    bill_sgt_sale,
    cat_sgt_free_puzzle_hash,
    proposal_tracker_v2_inner_puzzle,
    proposal_tracker_v2_mod,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


TRACKER_STRUCT = Program.to(
    (
        SINGLETON_MOD_HASH,
        (b32(0xA0), SINGLETON_LAUNCHER_HASH),
    )
)
POOL_STRUCT = Program.to(
    (
        SINGLETON_MOD_HASH,
        (b32(0xA1), SINGLETON_LAUNCHER_HASH),
    )
)
ADMIN_STRUCT = Program.to(
    (
        SINGLETON_MOD_HASH,
        (b32(0xA2), SINGLETON_LAUNCHER_HASH),
    )
)
STATUTES_STRUCT = Program.to(
    (
        SINGLETON_MOD_HASH,
        (b32(0xA3), SINGLETON_LAUNCHER_HASH),
    )
)
PARAMETERS = [300, 5_000, 10_000, 86_400, 600, 100, 30, 70, 86_400]


def tracker(
    *,
    proposal_hash: int | bytes32 = 0,
    bill: int | Program = 0,
    vote_tally: int = 0,
    deadline: int = 0,
    quorum_bps: int = 5_000,
    voting_window_seconds: int = 300,
    min_proposal_stake: int = 10_000,
) -> Program:
    return proposal_tracker_v2_inner_puzzle(
        TRACKER_STRUCT,
        b32(0x01),
        b32(0x02),
        b32(0x03),
        b32(0x04),
        b32(0x05),
        POOL_STRUCT,
        ADMIN_STRUCT,
        STATUTES_STRUCT,
        quorum_bps,
        voting_window_seconds,
        1_000_000,
        min_proposal_stake,
        TEST_KOS_MINT_EXECUTE_PUBKEY,
        proposal_hash,
        bill,
        vote_tally,
        deadline,
    )


def mutation(kind: MutationKind) -> StatuteMutation:
    key: int | bytes32 = 3 if kind == MutationKind.PARAMETER else b32(0x20 + kind)
    value: int | object
    if kind == MutationKind.PARAMETER:
        value = 172_800
    elif kind == MutationKind.COLLECTION:
        value = CollectionStatute(
            collection_id=key,
            nav_micro_usd=100,
            allocation_ceiling_micro_usd=200,
            nav_version=1,
            valid_after=10,
            valid_until=20,
            status=1,
        )
    elif kind == MutationKind.ORACLE:
        value = OracleRound(
            asset_id=key,
            price_micro_usd=1_000_000,
            observed_at=10,
            valid_until=20,
            round_id=1,
            source_root=b32(0x28),
            source_count=2,
            haircut_bps=0,
            stable_min_bps=9_800,
            stable_max_bps=10_200,
        )
    elif kind == MutationKind.ROUTE:
        value = BridgeRoute(
            route_id=key,
            source_chain_id=b32(0x29),
            destination_chain_id=b32(0x2A),
            asset_id=b32(0x2B),
            remote_asset_id=b32(0x2C),
            decimals=3,
            active=1,
        )
    elif kind == MutationKind.LIQUIDITY:
        value = LiquidityVenue(
            venue_id=key,
            chain_id=b32(0x29),
            protocol_id=b32(0x2A),
            factory_id=b32(0x2B),
            pool_id=b32(0x2C),
            base_asset_id=b32(0x2D),
            quote_asset_id=b32(0x2E),
            pool_code_hash=b32(0x2F),
            active=1,
        )
    else:
        value = ScopedPause(
            scope_id=key,
            paused=1,
            expires_at=20,
            reason_hash=b32(0x2D),
        )
    return StatuteMutation(
        kind=kind,
        key=key,
        value=value,
        old_root=b32(0x31),
        new_root=b32(0x32),
        old_version=1,
        new_version=2,
        old_state_hash=b32(0x33),
        new_state_hash=b32(0x34),
    )


def execute_conditions(item: StatuteMutation) -> list[Program]:
    bill = item.bill_program()
    inner = tracker(
        proposal_hash=item.proposal_hash,
        bill=bill,
        vote_tally=500_000,
        deadline=100,
    )
    solution = Program.to(
        [
            b32(0x41),
            inner.get_tree_hash(),
            1,
            3,
            [],
        ]
    )
    return list(inner.run(solution).as_iter())


def test_v2_governance_module_compiles() -> None:
    assert len(proposal_tracker_v2_mod().as_bin()) > 0


def test_proposal_requires_exact_admin_authority_approval() -> None:
    item = mutation(MutationKind.PARAMETER)
    bill = item.bill_program()
    inner = tracker()
    admin_inner = Program.to(1)
    solution = Program.to(
        [
            b32(0x41),
            inner.get_tree_hash(),
            1,
            1,
            [
                item.proposal_hash,
                bill,
                b32(0x42),
                10_000,
                300,
                [admin_inner.get_tree_hash(), b32(0x44), PARAMETERS],
            ],
        ]
    )

    conditions = list(inner.run(solution).as_iter())
    announcement_assertions = [
        condition.rest().first().as_atom()
        for condition in conditions
        if condition.first().as_int() == 63
    ]
    admin_full_puzzle_hash = puzzle_for_singleton(
        b32(0xA2),
        admin_inner,
    ).get_tree_hash()
    expected_admin_assertion = hashlib.sha256(
        bytes(admin_full_puzzle_hash)
        + admin_governance_proposal_message(item.proposal_hash)
    ).digest()

    statutes_full_puzzle_hash = singleton_full_puzzle_hash(
        b32(0xA3),
        b32(0x44),
    )
    expected_statutes_assertion = hashlib.sha256(
        bytes(statutes_full_puzzle_hash)
        + governance_evidence_message(
            ProtocolParameters.from_sequence(PARAMETERS)
        )
    ).digest()

    assert len(announcement_assertions) == 3
    assert expected_admin_assertion in announcement_assertions
    assert expected_statutes_assertion in announcement_assertions


def test_proposal_snapshots_governed_quorum_window_and_stake() -> None:
    item = mutation(MutationKind.PARAMETER)
    governed = [900, 6_000, 20_000, 86_400, 600, 100, 30, 70, 86_400]
    inner = tracker()
    solution = Program.to(
        [
            b32(0x41),
            inner.get_tree_hash(),
            1,
            1,
            [
                item.proposal_hash,
                item.bill_program(),
                b32(0x42),
                20_000,
                900,
                [b32(0x43), b32(0x44), governed],
            ],
        ]
    )
    conditions = list(inner.run(solution).as_iter())
    created = next(
        condition
        for condition in conditions
        if condition.first().as_int() == 51
    )
    expected = tracker(
        proposal_hash=item.proposal_hash,
        bill=item.bill_program(),
        vote_tally=20_000,
        deadline=900,
        quorum_bps=6_000,
        voting_window_seconds=900,
        min_proposal_stake=20_000,
    )
    assert created.rest().first().as_atom() == expected.get_tree_hash()


@pytest.mark.parametrize(
    "kind",
    [
        MutationKind.PARAMETER,
        MutationKind.COLLECTION,
        MutationKind.ORACLE,
        MutationKind.ROUTE,
        MutationKind.LIQUIDITY,
        MutationKind.PAUSE,
    ],
)
def test_each_statute_bill_dispatches_exact_governance_message(
    kind: MutationKind,
) -> None:
    item = mutation(kind)
    conditions = execute_conditions(item)
    send = next(condition for condition in conditions if condition.first().as_int() == 66)
    assert send.rest().first().as_int() == 0x10
    assert send.rest().rest().first().as_atom() == item.governance_message_body
    assert not any(condition.first().as_int() == 50 for condition in conditions)


def test_statute_tags_are_distinct_and_stable() -> None:
    assert [int(tag) for tag in BillTag] == [
        0x50,
        0x4E,
        0x4F,
        0x52,
        0x55,
        0x4C,
    ]


def test_malformed_statute_bill_cannot_enter_open_state() -> None:
    malformed = Program.to(
        [
            int(BillTag.PARAMETER),
            3,
            172_800,
            b32(0x31),
            b32(0x32),
            1,
            2,
            b32(0x33),
            # Missing new_state_hash.
        ]
    )
    proposal_hash = bytes32(malformed.get_tree_hash())
    inner = tracker()
    solution = Program.to(
        [
            b32(0x41),
            inner.get_tree_hash(),
            1,
            1,
            [
                proposal_hash,
                malformed,
                b32(0x42),
                10_000,
                300,
                [b32(0x43), b32(0x44), PARAMETERS],
            ],
        ]
    )
    with pytest.raises(Exception):
        inner.run(solution)


@pytest.mark.parametrize(
    "bill",
    [
        bill_sgt_sale(
            sale_id=b32(0x61),
            sgt_amount=25_000,
            recipient_vault_launcher_id=b32(0x62),
            payment_rail=1,
            payment_asset_id=bytes32.zeros,
            payment_amount=1_000_000,
            company_treasury_puzzle_hash=b32(0x63),
            expires_at=1_900_000_000,
            reserve_owner_inner_puzzle_hash=b32(0x66),
        ),
        bill_sgt_sale(
            sale_id=b32(0x68),
            sgt_amount=750,
            recipient_vault_launcher_id=b32(0x69),
            payment_rail=3,
            payment_asset_id=bytes32.zeros,
            payment_amount=101_000,
            company_treasury_puzzle_hash=b32(0x6A),
            expires_at=1_900_000_000,
            reserve_owner_inner_puzzle_hash=b32(0x6B),
            purchase_artifact_hash=b32(0x6C),
        ),
        bill_sgt_grant(
            grant_id=b32(0x64),
            sgt_amount=10_000,
            recipient_vault_launcher_id=b32(0x65),
            reason_hash=b32(0x66),
            reserve_owner_inner_puzzle_hash=b32(0x67),
        ),
    ],
)
def test_sgt_allocation_bills_enter_and_execute_through_canonical_tracker(
    bill: Program,
) -> None:
    proposal_hash = bytes32(bill.get_tree_hash())
    idle = tracker()
    propose = Program.to(
        [
            b32(0x41),
            idle.get_tree_hash(),
            1,
            1,
            [
                proposal_hash,
                bill,
                b32(0x42),
                500_000,
                300,
                [b32(0x43), b32(0x44), PARAMETERS],
            ],
        ]
    )
    assert list(idle.run(propose).as_iter())

    active = tracker(
        proposal_hash=proposal_hash,
        bill=bill,
        vote_tally=500_000,
        deadline=100,
    )
    execute = Program.to(
        [b32(0x45), active.get_tree_hash(), 1, 3, []]
    )
    conditions = list(active.run(execute).as_iter())
    assert any(condition.first().as_int() == 62 for condition in conditions)
    concurrent = [
        list(condition.as_iter())
        for condition in conditions
        if condition.first().as_int() == 65
    ]
    bill_values = list(bill.as_iter())
    reserve_owner = bytes32(
        bill_values[9 if bill_values[0].as_atom() == b"Y" else 5].as_atom()
    )
    expected_reserve_puzzle = cat_sgt_free_puzzle_hash(
        TRACKER_STRUCT,
        b32(0x01),
        b32(0x02),
        b32(0x03),
        b32(0x04),
        reserve_owner,
    )
    assert len(concurrent) == 1
    assert bytes32(concurrent[0][1].as_atom()) == expected_reserve_puzzle
    assert not any(condition.first().as_int() == 66 for condition in conditions)


def test_statute_bill_rejects_non_exact_version_increment() -> None:
    item = mutation(MutationKind.COLLECTION)
    malformed = Program.to(
        [
            int(BillTag.COLLECTION),
            item.key,
            item.value_program(),
            item.old_root,
            item.new_root,
            1,
            3,
            item.old_state_hash,
            item.new_state_hash,
        ]
    )
    inner = tracker()
    solution = Program.to(
        [
            b32(0x41),
            inner.get_tree_hash(),
            1,
            1,
            [
                bytes32(malformed.get_tree_hash()),
                malformed,
                b32(0x42),
                10_000,
                300,
                [b32(0x43), b32(0x44), PARAMETERS],
            ],
        ]
    )
    with pytest.raises(Exception):
        inner.run(solution)
