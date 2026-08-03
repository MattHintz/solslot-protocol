"""Consensus fixtures for governed permanent SmartDeed redemption offers."""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia.wallet.trading.offer import Offer
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.funded_redemption_v1 import (
    CANONICAL_DEED_SETTLEMENT_INNER,
    FundedRedemptionAllocation,
    aggregate_direct_redemption,
    build_direct_redemption_acceptance,
    build_funded_redemption_plan,
    build_permanent_redemption_offer,
    puzzle_for_deed_redemption_v1,
    redemption_funding_puzzle,
    redemption_leaf_conditions,
    redemption_payment_memos,
)
from solslot_puzzles.mint_publish_driver import deed_singleton_struct
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    ZKPASSPORT_EMPTY_ATTEST_ROOT,
    puzzle_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import puzzle_for_vault_v2_inner
from solslot_puzzles.primary_purchase_v2_driver import (
    chia_cat_driver,
    smart_deed_singleton_driver,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    deed_launcher_puzzle_hash_from_struct,
)
from solslot_puzzles.redemption_treasury_v1 import (
    fund_redemption_leaves,
    redemption_treasury_inner_puzzle,
    redemption_treasury_puzzle,
    redemption_treasury_solution,
)
from solslot_puzzles.sgt_driver import (
    PROTOCOL_PREFIX,
    bill_funded_redemption,
    funded_redemption_message_hash,
)


ASSERT_PUZZLE_ANNOUNCEMENT = 63
CREATE_COIN = 51
RECEIVE_MESSAGE = 67
ASSERT_MY_COIN_ID = 70
ASSERT_MY_PARENT_ID = 71
ASSERT_MY_PUZZLEHASH = 72
ASSERT_MY_AMOUNT = 73
REMARK = 1

COLLECTION_ID = bytes32(b"\x11" * 32)
SETTLEMENT_ID = bytes32(b"\x12" * 32)
PAYMENT_ASSET_ID = bytes32(b"\x13" * 32)
GOVERNANCE_LAUNCHER_ID = bytes32(b"\x14" * 32)
GOVERNANCE_INNER_HASH = bytes32(b"\x15" * 32)
DEED_A = bytes32(b"\x21" * 32)
DEED_B = bytes32(b"\x22" * 32)
DEED_C = bytes32(b"\x23" * 32)
COMMITMENT_A = bytes32(b"\x31" * 32)
COMMITMENT_B = bytes32(b"\x32" * 32)
COMMITMENT_C = bytes32(b"\x33" * 32)
VAULT_LAUNCHER_ID = bytes32(b"\x34" * 32)
POOL_LAUNCHER_ID = bytes32(b"\x35" * 32)
MEMBERS_ROOT = bytes32(b"\x36" * 32)
IDENTITY_ROOT = bytes32(b"\x37" * 32)
BRIDGE_POLICY = bytes32(b"\x38" * 32)
PAYMENT_RECIPIENT = bytes32(b"\x39" * 32)


def opcode(condition: list[object]) -> int:
    value = condition[0]
    return int.from_bytes(value, "big") if isinstance(value, bytes) else int(value)


def amount(value: object) -> int:
    return int.from_bytes(value, "big") if isinstance(value, bytes) else int(value)


def plan():
    return build_funded_redemption_plan(
        collection_id=COLLECTION_ID,
        settlement_id=SETTLEMENT_ID,
        payment_asset_id=PAYMENT_ASSET_ID,
        total_payment_amount=1_000_001,
        deed_shares_ppm={
            DEED_A: 500_000,
            DEED_B: 300_000,
            DEED_C: 200_000,
        },
        deed_commitments={
            DEED_A: COMMITMENT_A,
            DEED_B: COMMITMENT_B,
            DEED_C: COMMITMENT_C,
        },
    )


def governance_struct() -> Program:
    return Program.to(
        (
            SINGLETON_MOD_HASH,
            (GOVERNANCE_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH),
        )
    )


def smart_deed_struct(deed_launcher_id: bytes32) -> Program:
    return deed_singleton_struct(
        deed_launcher_id=deed_launcher_id,
        protocol_did_singleton_struct=governance_struct(),
    )


def smart_deed_driver(deed_launcher_id: bytes32):
    struct = smart_deed_struct(deed_launcher_id)
    launcher_hash = deed_launcher_puzzle_hash_from_struct(
        struct,
        deed_launcher_id,
    )
    return smart_deed_singleton_driver(deed_launcher_id, launcher_hash)


def smart_deed_launcher_hash(deed_launcher_id: bytes32 = DEED_A) -> bytes32:
    return deed_launcher_puzzle_hash_from_struct(
        smart_deed_struct(deed_launcher_id),
        deed_launcher_id,
    )


def allocation(deed_id: bytes32 = DEED_A) -> FundedRedemptionAllocation:
    return next(
        item for item in plan().allocations if item.deed_launcher_id == deed_id
    )


def funding_coin(item: FundedRedemptionAllocation | None = None) -> Coin:
    chosen = item or allocation()
    full = redemption_funding_puzzle(
        payment_asset_id=PAYMENT_ASSET_ID,
        collection_id=COLLECTION_ID,
        settlement_id=SETTLEMENT_ID,
        allocation=chosen,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(
            chosen.deed_launcher_id
        ),
    )
    return Coin(
        bytes32(b"\x41" * 32),
        bytes32(full.get_tree_hash()),
        uint64(chosen.payment_amount),
    )


def test_largest_remainder_allocation_is_exact_and_deterministic():
    current = plan()
    assert [item.deed_launcher_id for item in current.allocations] == [
        DEED_A,
        DEED_B,
        DEED_C,
    ]
    assert [item.payment_amount for item in current.allocations] == [
        500_001,
        300_000,
        200_000,
    ]
    assert sum(item.share_ppm for item in current.allocations) == 1_000_000
    assert sum(item.payment_amount for item in current.allocations) == 1_000_001


def test_governance_bill_binds_asset_total_count_and_allocation_root():
    current = plan()
    bill = bill_funded_redemption(
        collection_id=current.collection_id,
        settlement_id=current.settlement_id,
        payment_asset_id=current.payment_asset_id,
        total_payment_amount=current.total_payment_amount,
        deed_count=current.deed_count,
        allocations_root=current.allocations_root,
    )
    assert bill.get_tree_hash() != bill_funded_redemption(
        collection_id=current.collection_id,
        settlement_id=current.settlement_id,
        payment_asset_id=current.payment_asset_id,
        total_payment_amount=current.total_payment_amount + 1,
        deed_count=current.deed_count,
        allocations_root=current.allocations_root,
    ).get_tree_hash()


def test_permanent_leaf_asserts_exact_deed_and_offers_exact_wusdc():
    current = plan()
    chosen = allocation()
    coin = funding_coin(chosen)
    conditions = redemption_leaf_conditions(
        funding_coin=coin,
        plan=current,
        allocation=chosen,
        deed_singleton_struct=smart_deed_struct(chosen.deed_launcher_id),
    )
    assert [opcode(condition) for condition in conditions] == [
        ASSERT_PUZZLE_ANNOUNCEMENT,
        CREATE_COIN,
        ASSERT_MY_PARENT_ID,
        ASSERT_MY_PUZZLEHASH,
        ASSERT_MY_AMOUNT,
        REMARK,
    ]
    assert amount(conditions[1][2]) == chosen.payment_amount
    assert conditions[2][1] == bytes(coin.parent_coin_info)
    assert conditions[3][1] == bytes(coin.puzzle_hash)
    assert amount(conditions[4][1]) == chosen.payment_amount

    requested = {
        chosen.deed_launcher_id: [
            CreateCoin(
                CANONICAL_DEED_SETTLEMENT_INNER,
                uint64(1),
                redemption_payment_memos(
                    collection_id=current.collection_id,
                    settlement_id=current.settlement_id,
                    allocation=chosen,
                ),
            )
        ]
    }
    notarized = Offer.notarize_payments(requested, [coin])
    expected = Offer.calculate_announcements(
        notarized,
        {
            chosen.deed_launcher_id: smart_deed_driver(chosen.deed_launcher_id)
        },
    )[0].to_program().as_python()
    assert conditions[0][1] == expected[1]


def test_permanent_leaf_has_no_timeout_or_withdrawal_solution():
    chosen = allocation()
    coin = funding_coin(chosen)
    leaf = puzzle_for_deed_redemption_v1(
        payment_asset_id=PAYMENT_ASSET_ID,
        collection_id=COLLECTION_ID,
        settlement_id=SETTLEMENT_ID,
        allocation=chosen,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(
            chosen.deed_launcher_id
        ),
    )
    with pytest.raises(Exception):
        leaf.run(
            Program.to(
                [
                    coin.parent_coin_info,
                    coin.puzzle_hash,
                    chosen.payment_amount - 1,
                ]
            )
        ).as_python()
    with pytest.raises(Exception):
        leaf.run(Program.to([bytes32.zeros, 1])).as_python()


def test_treasury_only_splits_exact_governed_funding():
    current = plan()
    inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    full = redemption_treasury_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    coin = Coin(
        bytes32(b"\x51" * 32),
        bytes32(full.get_tree_hash()),
        uint64(current.total_payment_amount),
    )
    conditions = inner.run(
        redemption_treasury_solution(
            treasury_coin=coin,
            governance_inner_puzzle_hash=GOVERNANCE_INNER_HASH,
            plan=current,
        )
    ).as_python()
    create_conditions = [
        condition
        for condition in conditions
        if opcode(condition) == CREATE_COIN
    ]
    assert len(create_conditions) == current.deed_count
    assert [amount(condition[2]) for condition in create_conditions] == [
        item.payment_amount for item in current.allocations
    ]
    receive = next(
        condition
        for condition in conditions
        if opcode(condition) == RECEIVE_MESSAGE
    )
    assert receive[2] == (
        PROTOCOL_PREFIX
        + bytes(
            funded_redemption_message_hash(
                collection_id=current.collection_id,
                settlement_id=current.settlement_id,
                payment_asset_id=current.payment_asset_id,
                total_payment_amount=current.total_payment_amount,
                deed_count=current.deed_count,
                allocations_root=current.allocations_root,
            )
        )
    )
    assert [opcode(condition) for condition in conditions[-3:]] == [
        ASSERT_MY_COIN_ID,
        ASSERT_MY_AMOUNT,
        REMARK,
    ]


def test_treasury_rejects_altered_allocation_and_has_no_change_path():
    current = plan()
    inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    full = redemption_treasury_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    coin = Coin(
        bytes32(b"\x61" * 32),
        bytes32(full.get_tree_hash()),
        uint64(current.total_payment_amount),
    )
    solution = redemption_treasury_solution(
        treasury_coin=coin,
        governance_inner_puzzle_hash=GOVERNANCE_INNER_HASH,
        plan=current,
    ).as_python()
    solution[7] = bytes32(b"\xff" * 32)
    with pytest.raises(Exception):
        inner.run(Program.to(solution)).as_python()

    larger = Coin(
        coin.parent_coin_info,
        coin.puzzle_hash,
        uint64(current.total_payment_amount + 1),
    )
    with pytest.raises(Exception):
        inner.run(
            redemption_treasury_solution(
                treasury_coin=larger,
                governance_inner_puzzle_hash=GOVERNANCE_INNER_HASH,
                plan=current,
            )
        ).as_python()


def test_drivers_build_funding_and_permanent_offer_without_fee():
    current = plan()
    treasury_inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    treasury_full = redemption_treasury_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    treasury_coin = Coin(
        bytes32(b"\x71" * 32),
        bytes32(treasury_full.get_tree_hash()),
        uint64(current.total_payment_amount),
    )
    funded = fund_redemption_leaves(
        treasury_coin=treasury_coin,
        treasury_lineage_proof=LineageProof(
            bytes32(b"\x72" * 32),
            bytes32(treasury_inner.get_tree_hash()),
            uint64(current.total_payment_amount),
        ),
        governance_singleton_struct=governance_struct(),
        governance_inner_puzzle_hash=GOVERNANCE_INNER_HASH,
        plan=current,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    assert len(funded.leaf_coins) == current.deed_count

    chosen = current.allocations[0]
    offer, _ = build_permanent_redemption_offer(
        funding_coin=funded.leaf_coins[0],
        funding_lineage_proof=funded.leaf_lineage_proof,
        plan=current,
        allocation=chosen,
        deed_singleton_struct=smart_deed_struct(chosen.deed_launcher_id),
    )
    assert offer.fees() == 0
    assert offer.get_offered_amounts()[PAYMENT_ASSET_ID] == (
        chosen.payment_amount
    )
    assert set(offer.requested_payments) == {chosen.deed_launcher_id}
    assert offer.driver_dict[PAYMENT_ASSET_ID].info == chia_cat_driver(
        PAYMENT_ASSET_ID
    ).info


def _holder_acceptance_kwargs():
    chosen = allocation()
    owner = bytes(G1Element.generator())
    vault_inner = puzzle_for_vault_v2_inner(
        vault_launcher_id=VAULT_LAUNCHER_ID,
        owner_pubkey=owner,
        auth_type=AUTH_TYPE_BLS,
        members_merkle_root=MEMBERS_ROOT,
        pool_launcher_id=POOL_LAUNCHER_ID,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=BRIDGE_POLICY,
    )
    vault_parent = Coin(
        bytes32(b"\x81" * 32),
        bytes32(
            puzzle_for_singleton(
                VAULT_LAUNCHER_ID,
                vault_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    vault_coin = Coin(
        vault_parent.name(),
        vault_parent.puzzle_hash,
        uint64(1),
    )
    deed_inner = puzzle_for_p2_vault(VAULT_LAUNCHER_ID)
    deed_parent = Coin(
        bytes32(b"\x82" * 32),
        bytes32(
            SINGLETON_MOD.curry(
                smart_deed_struct(chosen.deed_launcher_id),
                deed_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    deed_coin = Coin(
        deed_parent.name(),
        deed_parent.puzzle_hash,
        uint64(1),
    )
    return {
        "vault_coin": vault_coin,
        "vault_launcher_id": VAULT_LAUNCHER_ID,
        "vault_lineage_proof": LineageProof(
            vault_parent.parent_coin_info,
            bytes32(vault_inner.get_tree_hash()),
            uint64(1),
        ),
        "vault_owner_pubkey": owner,
        "vault_auth_type": AUTH_TYPE_BLS,
        "vault_members_merkle_root": MEMBERS_ROOT,
        "pool_launcher_id": POOL_LAUNCHER_ID,
        "identity_attest_root": IDENTITY_ROOT,
        "zkpassport_bridge_policy_hash": BRIDGE_POLICY,
        "deed_coin": deed_coin,
        "deed_lineage_proof": LineageProof(
            deed_parent.parent_coin_info,
            bytes32(deed_inner.get_tree_hash()),
            uint64(1),
        ),
        "deed_current_inner_puzzle_hash": bytes32(
            deed_inner.get_tree_hash()
        ),
        "deed_singleton_struct": smart_deed_struct(
            chosen.deed_launcher_id
        ),
        "payment_recipient_inner_puzzle_hash": PAYMENT_RECIPIENT,
        "plan": plan(),
        "allocation": chosen,
    }


def _funded_maker_offer():
    current = plan()
    treasury_inner = redemption_treasury_inner_puzzle(
        governance_singleton_struct=governance_struct(),
        payment_asset_id=PAYMENT_ASSET_ID,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    treasury_coin = Coin(
        bytes32(b"\x88" * 32),
        bytes32(
            redemption_treasury_puzzle(
                governance_singleton_struct=governance_struct(),
                payment_asset_id=PAYMENT_ASSET_ID,
                deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
            ).get_tree_hash()
        ),
        uint64(current.total_payment_amount),
    )
    funded = fund_redemption_leaves(
        treasury_coin=treasury_coin,
        treasury_lineage_proof=LineageProof(
            bytes32(b"\x89" * 32),
            bytes32(treasury_inner.get_tree_hash()),
            uint64(current.total_payment_amount),
        ),
        governance_singleton_struct=governance_struct(),
        governance_inner_puzzle_hash=GOVERNANCE_INNER_HASH,
        plan=current,
        deed_launcher_puzzle_hash=smart_deed_launcher_hash(),
    )
    chosen = allocation()
    index = current.allocations.index(chosen)
    return build_permanent_redemption_offer(
        funding_coin=funded.leaf_coins[index],
        funding_lineage_proof=funded.leaf_lineage_proof,
        plan=current,
        allocation=chosen,
        deed_singleton_struct=smart_deed_struct(chosen.deed_launcher_id),
    )[0]


def test_enrolled_holder_accepts_exact_permanent_redemption_offer():
    current = plan()
    chosen = allocation()
    maker_offer = _funded_maker_offer()
    acceptance = build_direct_redemption_acceptance(
        **_holder_acceptance_kwargs()
    )
    aggregate = aggregate_direct_redemption(
        maker_offer=maker_offer,
        acceptance=acceptance,
    )
    assert aggregate.is_valid()
    assert aggregate.fees() == 0
    payment = acceptance.taker_offer.requested_payments[
        current.payment_asset_id
    ][0]
    assert payment.puzzle_hash == PAYMENT_RECIPIENT
    assert int(payment.amount) == chosen.payment_amount


def test_unenrolled_or_redirected_holder_redemption_fails_closed():
    kwargs = _holder_acceptance_kwargs()
    with pytest.raises(ValueError, match="zkPassport"):
        build_direct_redemption_acceptance(
            **{
                **kwargs,
                "identity_attest_root": ZKPASSPORT_EMPTY_ATTEST_ROOT,
            }
        )
    accepted = build_direct_redemption_acceptance(**kwargs)
    redirected = build_direct_redemption_acceptance(
        **{
            **kwargs,
            "payment_recipient_inner_puzzle_hash": bytes32(b"\x87" * 32),
        }
    )
    assert redirected.operation_hash != accepted.operation_hash
