from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, construct_cat_puzzle
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia.wallet.trading.offer import OFFER_MOD_HASH
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.payment_artifacts_v2 import PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    build_external_settlement_receipt_v1,
    build_sgt_purchase_artifact_v3,
)
from solslot_puzzles.sgt_driver import (
    bill_sgt_grant,
    bill_sgt_sale,
    proposal_hash_from_bill,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
    sgt_locked_inner_puzzle,
)
from solslot_puzzles.sgt_reserve_driver import (
    SGTAllocationRail,
    SGTReserveMode,
    SGTSaleMode,
    SGTSaleTermsV1,
    build_reserve_lock_coin_spend,
    build_reserve_execute_spends,
    build_sgt_sale_return_spend,
    prepare_sgt_sale_offer,
    sgt_cat_puzzle,
    sgt_reserve_inner_puzzle,
    sgt_sale_inner_puzzle,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    StripeSettlementTermsV1,
    curry_stripe_settlement_receipt,
    stripe_receipt_settlement_message,
    stripe_settlement_receipt_solution,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


TRACKER = singleton_struct(b32(1))
ADMIN = singleton_struct(b32(2))
TAIL = b32(3)
TREASURY = b32(4)
RECIPIENT_VAULT_LAUNCHER = b32(5)
RECIPIENT = puzzle_hash_for_p2_vault(RECIPIENT_VAULT_LAUNCHER)
WUSDC_B = b32(7)
SALE_ID = b32(6)
EXPIRES = 1_900_000_000
SGT_AMOUNT = 25_000
PAYMENT_AMOUNT = 9_500_000
EXTERNAL_ARTIFACT = b32(42)
BASE_USDC = bytes32.fromhex(
    "000000000000000000000000036cbd53842c5426634e7929541ec2318f3dcf7e"
)
VALIDATORS = tuple(
    bytes(AugSchemeMPL.key_gen(bytes([seed]) * 32).get_g1())
    for seed in (41, 42, 43)
)


def atom_int(value: Program) -> int:
    return value.as_int()


def atom_bytes(value: Program) -> bytes:
    assert value.atom is not None
    return bytes(value.atom)


def opcode(value: ConditionOpcode) -> int:
    return int.from_bytes(value.value, "big", signed=True)


def conditions(output: Program) -> list[list[Program]]:
    return [list(item.as_iter()) for item in output.as_iter()]


def sale_bill(*, rail: SGTAllocationRail = SGTAllocationRail.XCH) -> Program:
    asset = bytes32.zeros
    if rail is SGTAllocationRail.CAT:
        asset = WUSDC_B
    elif rail is SGTAllocationRail.BASE_USDC:
        asset = BASE_USDC
    return bill_sgt_sale(
        sale_id=SALE_ID,
        sgt_amount=SGT_AMOUNT,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        payment_rail=int(rail),
        payment_asset_id=asset,
        payment_amount=PAYMENT_AMOUNT,
        company_treasury_puzzle_hash=TREASURY,
        expires_at=EXPIRES,
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        purchase_artifact_hash=(
            EXTERNAL_ARTIFACT
            if rail in {SGTAllocationRail.STRIPE, SGTAllocationRail.BASE_USDC}
            else bytes32.zeros
        ),
    )


def terms(*, rail: SGTAllocationRail = SGTAllocationRail.XCH) -> SGTSaleTermsV1:
    bill = sale_bill(rail=rail)
    asset = bytes32.zeros
    if rail is SGTAllocationRail.CAT:
        asset = WUSDC_B
    elif rail is SGTAllocationRail.BASE_USDC:
        asset = BASE_USDC
    return SGTSaleTermsV1(
        sale_id=SALE_ID,
        proposal_hash=proposal_hash_from_bill(bill),
        sgt_amount=SGT_AMOUNT,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        payment_rail=rail,
        payment_asset_id=asset,
        payment_amount=PAYMENT_AMOUNT,
        company_treasury_puzzle_hash=TREASURY,
        expires_at=EXPIRES,
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        purchase_artifact_hash=(
            EXTERNAL_ARTIFACT
            if rail in {SGTAllocationRail.STRIPE, SGTAllocationRail.BASE_USDC}
            else bytes32.zeros
        ),
    )


def reserve() -> Program:
    return sgt_reserve_inner_puzzle(
        proposal_tracker_struct=TRACKER,
        admin_authority_struct=ADMIN,
        sgt_tail_hash=TAIL,
        wusdc_b_asset_id=WUSDC_B,
        company_treasury_puzzle_hash=TREASURY,
    )


def test_sale_bill_binds_every_business_term() -> None:
    bill = sale_bill()
    values = list(bill.as_iter())
    assert atom_bytes(values[0]) == b"Y"
    assert atom_bytes(values[1]) == SALE_ID
    assert atom_int(values[2]) == SGT_AMOUNT
    assert atom_bytes(values[3]) == RECIPIENT_VAULT_LAUNCHER
    assert atom_int(values[4]) == int(SGTAllocationRail.XCH)
    assert atom_bytes(values[5]) == bytes32.zeros
    assert atom_int(values[6]) == PAYMENT_AMOUNT
    assert atom_bytes(values[7]) == TREASURY
    assert atom_int(values[8]) == EXPIRES
    assert atom_bytes(values[9]) == bytes32(reserve().get_tree_hash())
    assert atom_bytes(values[10]) == bytes32.zeros


def test_sale_recipient_uses_the_existing_smartdeed_vault_boundary() -> None:
    assert RECIPIENT == puzzle_hash_for_p2_vault(RECIPIENT_VAULT_LAUNCHER)
    assert atom_bytes(list(sale_bill().as_iter())[3]) == RECIPIENT_VAULT_LAUNCHER


def test_sale_bill_rejects_unknown_rail_and_unbound_external_artifact() -> None:
    with pytest.raises(ValueError, match="payment_rail"):
        bill_sgt_sale(
            sale_id=SALE_ID,
            sgt_amount=1,
            recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
            payment_rail=5,
            payment_asset_id=bytes32.zeros,
            payment_amount=1,
            company_treasury_puzzle_hash=TREASURY,
            expires_at=1,
            reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        )
    with pytest.raises(ValueError, match="purchase artifact"):
        bill_sgt_sale(
            sale_id=SALE_ID,
            sgt_amount=1,
            recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
            payment_rail=int(SGTAllocationRail.STRIPE),
            payment_asset_id=bytes32.zeros,
            payment_amount=101,
            company_treasury_puzzle_hash=TREASURY,
            expires_at=EXPIRES,
            reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        )


def test_reserve_rejects_a_lookalike_cat_instead_of_wusdc_b() -> None:
    wrong_cat_bill = bill_sgt_sale(
        sale_id=SALE_ID,
        sgt_amount=SGT_AMOUNT,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        payment_rail=int(SGTAllocationRail.CAT),
        payment_asset_id=b32(99),
        payment_amount=PAYMENT_AMOUNT,
        company_treasury_puzzle_hash=TREASURY,
        expires_at=EXPIRES,
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
    )

    with pytest.raises(Exception):
        reserve().run(
            Program.to(
                [
                    int(SGTReserveMode.SALE),
                    100_000,
                    [wrong_cat_bill, b32(98)],
                ]
            )
        )


def test_reserve_lock_rejects_non_allocation_governance_bill() -> None:
    invalid_bill = Program.to([b"M", b32(29), 1])
    with pytest.raises(Exception):
        reserve().run(
            Program.to(
                [
                    int(SGTReserveMode.LOCK),
                    100_000,
                    [
                        proposal_hash_from_bill(invalid_bill),
                        invalid_bill,
                        EXPIRES,
                        b32(30),
                    ],
                ]
            )
        )

    with pytest.raises(
        ValueError,
        match="only SGT_SALE, SGT_GRANT, or funded redemption",
    ):
        build_reserve_lock_coin_spend(
            reserve_coin=Coin(b32(31), b32(32), uint64(100_000)),
            reserve_lineage_proof=LineageProof(
                b32(33), b32(34), uint64(100_000)
            ),
            proposal_tracker_struct=TRACKER,
            admin_authority_struct=ADMIN,
            sgt_tail_hash=TAIL,
            wusdc_b_asset_id=WUSDC_B,
            company_treasury_puzzle_hash=TREASURY,
            bill=invalid_bill,
            deadline=EXPIRES,
            admin_authority_inner_puzzle_hash=b32(35),
        )
    with pytest.raises(ValueError, match="XCH"):
        bill_sgt_sale(
            sale_id=SALE_ID,
            sgt_amount=1,
            recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
            payment_rail=1,
            payment_asset_id=b32(7),
            payment_amount=1,
            company_treasury_puzzle_hash=TREASURY,
            expires_at=1,
            reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        )


def test_executed_sale_splits_exact_allocation_and_remainder() -> None:
    bill = sale_bill()
    tracker_inner = b32(8)
    amount = 100_000
    out = reserve().run(
        Program.to(
            [
                int(SGTReserveMode.SALE),
                amount,
                [bill, tracker_inner],
            ]
        )
    )
    conds = conditions(out)
    creates = [
        item for item in conds
        if atom_int(item[0]) == opcode(ConditionOpcode.CREATE_COIN)
    ]
    assert sorted(atom_int(item[2]) for item in creates) == [
        SGT_AMOUNT,
        amount - SGT_AMOUNT,
    ]
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT)
        for item in conds
    )


def test_executed_grant_has_no_payment_or_discretionary_destination() -> None:
    grant = bill_sgt_grant(
        grant_id=b32(9),
        sgt_amount=12_500,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        reason_hash=b32(10),
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
    )
    out = reserve().run(
        Program.to(
            [int(SGTReserveMode.GRANT), 100_000, [grant, b32(11)]]
        )
    )
    creates = [
        item for item in conditions(out)
        if atom_int(item[0]) == opcode(ConditionOpcode.CREATE_COIN)
    ]
    assert any(
        atom_bytes(item[1]) == RECIPIENT and atom_int(item[2]) == 12_500
        for item in creates
    )
    assert len(creates) == 2


def test_sale_take_requires_exact_payment_announcement_and_recipient() -> None:
    sale_terms = terms()
    puzzle = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=bytes32(reserve().get_tree_hash()),
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    full = sgt_cat_puzzle(
        proposal_tracker_struct=TRACKER,
        sgt_tail_hash=TAIL,
        owner_inner_puzzle=puzzle,
    )
    parent = b32(12)
    out = puzzle.run(
        Program.to(
            [
                int(SGTSaleMode.TAKE),
                parent,
                full.get_tree_hash(),
                SGT_AMOUNT,
                bytes32.zeros,
                bytes32.zeros,
            ]
        )
    )
    conds = conditions(out)
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.ASSERT_BEFORE_SECONDS_ABSOLUTE)
        and atom_int(item[1]) == EXPIRES
        for item in conds
    )
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT)
        for item in conds
    )
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.CREATE_COIN)
        and atom_bytes(item[1]) == RECIPIENT
        and atom_int(item[2]) == SGT_AMOUNT
        for item in conds
    )


@pytest.mark.parametrize(
    "rail",
    [SGTAllocationRail.STRIPE, SGTAllocationRail.BASE_USDC],
)
def test_external_sale_requires_exact_receipt_and_keeps_vault_destination(
    rail: SGTAllocationRail,
) -> None:
    sale_terms = terms(rail=rail)
    puzzle = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=bytes32(reserve().get_tree_hash()),
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    full = sgt_cat_puzzle(
        proposal_tracker_struct=TRACKER,
        sgt_tail_hash=TAIL,
        owner_inner_puzzle=puzzle,
    )
    out = puzzle.run(
        Program.to(
            [
                int(SGTSaleMode.EXTERNAL_TAKE),
                b32(43),
                full.get_tree_hash(),
                SGT_AMOUNT,
                b32(44),
                b32(45),
            ]
        )
    )
    conds = conditions(out)
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT)
        for item in conds
    )
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.CREATE_COIN)
        and atom_bytes(item[1]) == RECIPIENT
        and atom_int(item[2]) == SGT_AMOUNT
        for item in conds
    )
    with pytest.raises(Exception):
        puzzle.run(
            Program.to(
                [
                    int(SGTSaleMode.EXTERNAL_TAKE),
                    b32(43),
                    full.get_tree_hash(),
                    SGT_AMOUNT,
                    bytes32.zeros,
                    b32(45),
                ]
            )
        )


@pytest.mark.parametrize(
    ("sale_rail", "artifact_rail", "chain_id", "asset_id", "decimals"),
    [
        (
            SGTAllocationRail.STRIPE,
            PaymentRail.STRIPE,
            0,
            bytes32.zeros,
            2,
        ),
        (
            SGTAllocationRail.BASE_USDC,
            PaymentRail.EVM_TEST_USD,
            84532,
            BASE_USDC,
            6,
        ),
    ],
)
def test_external_sgt_sale_matches_the_shared_receipt_protocol(
    sale_rail: SGTAllocationRail,
    artifact_rail: PaymentRail,
    chain_id: int,
    asset_id: bytes32,
    decimals: int,
) -> None:
    base_minor = 10_000
    gross_minor = 10_100
    result_hash = (
        b32(52)
        if artifact_rail is PaymentRail.EVM_TEST_USD
        else bytes32.zeros
    )
    artifact = build_sgt_purchase_artifact_v3(
        network="testnet11",
        sgt_asset_id=TAIL,
        sale_id=SALE_ID,
        sgt_amount=SGT_AMOUNT,
        base_usd_amount_minor=base_minor,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=TREASURY,
        zkpassport_root=b32(53),
        rail=artifact_rail,
        rail_chain_id=chain_id,
        rail_asset_id=asset_id,
        rail_asset_decimals=decimals,
        vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        vault_p2_puzzle_hash=RECIPIENT,
        authorization_nonce=b32(54),
        authorization_expires_at=1_800_000_600,
        quote_expires_at=1_800_000_300,
    )
    receipt = build_external_settlement_receipt_v1(
        artifact=artifact,
        provider_id=b32(55),
        external_reference_hash=b32(56),
        evidence_hash=b32(57),
        observed_at=1_800_000_100,
        result_authorization_puzzle_hash=result_hash,
    )
    receipt_terms = StripeSettlementTermsV1(
        receipt=receipt,
        validator_pubkeys=VALIDATORS,  # type: ignore[arg-type]
    )
    receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
    receipt_coin = Coin(
        b32(58),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    receipt_conditions = conditions(
        receipt_puzzle.run(
            stripe_settlement_receipt_solution(
                receipt_coin=receipt_coin,
                signer_indices=(0, 2),
            )
        )
    )
    receipt_message = stripe_receipt_settlement_message(receipt)
    assert any(
        atom_int(item[0])
        == opcode(ConditionOpcode.CREATE_COIN_ANNOUNCEMENT)
        and atom_bytes(item[1]) == receipt_message
        for item in receipt_conditions
    )

    bill = bill_sgt_sale(
        sale_id=SALE_ID,
        sgt_amount=SGT_AMOUNT,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        payment_rail=int(sale_rail),
        payment_asset_id=asset_id,
        payment_amount=(
            gross_minor
            if artifact_rail is PaymentRail.STRIPE
            else gross_minor * 10_000
        ),
        company_treasury_puzzle_hash=TREASURY,
        expires_at=EXPIRES,
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        purchase_artifact_hash=artifact.artifact_hash,
    )
    sale_terms = SGTSaleTermsV1(
        sale_id=SALE_ID,
        proposal_hash=proposal_hash_from_bill(bill),
        sgt_amount=SGT_AMOUNT,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        payment_rail=sale_rail,
        payment_asset_id=asset_id,
        payment_amount=artifact.rail_amount,
        company_treasury_puzzle_hash=TREASURY,
        expires_at=EXPIRES,
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
        purchase_artifact_hash=artifact.artifact_hash,
    )
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=bytes32(reserve().get_tree_hash()),
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    sale_full = sgt_cat_puzzle(
        proposal_tracker_struct=TRACKER,
        sgt_tail_hash=TAIL,
        owner_inner_puzzle=sale_inner,
    )
    sale_conditions = conditions(
        sale_inner.run(
            Program.to(
                [
                    int(SGTSaleMode.EXTERNAL_TAKE),
                    b32(59),
                    sale_full.get_tree_hash(),
                    SGT_AMOUNT,
                    receipt_coin.name(),
                    receipt.receipt_hash,
                ]
            )
        )
    )
    expected_announcement_id = hashlib.sha256(
        bytes(receipt_coin.name()) + bytes(receipt_message)
    ).digest()
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT)
        and atom_bytes(item[1]) == expected_announcement_id
        for item in sale_conditions
    )
    assert any(
        atom_int(item[0]) == opcode(ConditionOpcode.CREATE_COIN)
        and atom_bytes(item[1]) == RECIPIENT
        and atom_int(item[2]) == SGT_AMOUNT
        for item in sale_conditions
    )
def test_sale_offer_requests_only_exact_company_payment() -> None:
    sale_terms = terms(rail=SGTAllocationRail.CAT)
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=bytes32(reserve().get_tree_hash()),
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    full = sgt_cat_puzzle(
        proposal_tracker_struct=TRACKER,
        sgt_tail_hash=TAIL,
        owner_inner_puzzle=sale_inner,
    )
    coin = Coin(b32(13), bytes32(full.get_tree_hash()), uint64(SGT_AMOUNT))
    offer = prepare_sgt_sale_offer(
        sale_coin=coin,
        sale_lineage_proof=LineageProof(b32(14), b32(15), uint64(SGT_AMOUNT)),
        proposal_tracker_struct=TRACKER,
        reserve_owner_inner_hash=bytes32(reserve().get_tree_hash()),
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    assert set(offer.requested_payments) == {WUSDC_B}
    payment = offer.requested_payments[WUSDC_B][0]
    assert payment.puzzle_hash == TREASURY
    assert int(payment.amount) == PAYMENT_AMOUNT
    assert payment.memos == [SALE_ID, sale_terms.proposal_hash]


def test_expired_sale_returns_to_reserve() -> None:
    sale_terms = terms()
    reserve_hash = bytes32(reserve().get_tree_hash())
    sale_inner = sgt_sale_inner_puzzle(
        reserve_owner_inner_hash=reserve_hash,
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    full = sgt_cat_puzzle(
        proposal_tracker_struct=TRACKER,
        sgt_tail_hash=TAIL,
        owner_inner_puzzle=sale_inner,
    )
    coin = Coin(b32(16), bytes32(full.get_tree_hash()), uint64(SGT_AMOUNT))
    spend = build_sgt_sale_return_spend(
        sale_coin=coin,
        sale_lineage_proof=LineageProof(b32(17), b32(18), uint64(SGT_AMOUNT)),
        proposal_tracker_struct=TRACKER,
        reserve_owner_inner_hash=reserve_hash,
        sgt_tail_hash=TAIL,
        terms=sale_terms,
    )
    assert spend.coin == coin
    assert spend.puzzle_reveal.get_tree_hash() == full.get_tree_hash()


def test_execute_spends_release_and_allocate_in_one_ephemeral_cat_ring() -> None:
    bill = sale_bill()
    reserve_inner = reserve()
    locked_inner = sgt_locked_inner_puzzle(
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        TRACKER,
        bytes32(reserve_inner.get_tree_hash()),
        proposal_hash_from_bill(bill),
        EXPIRES,
    )
    locked_full = construct_cat_puzzle(CAT_MOD, TAIL, locked_inner)
    locked_coin = Coin(b32(19), bytes32(locked_full.get_tree_hash()), uint64(100_000))

    locked_spend, allocation_spend = build_reserve_execute_spends(
        locked_reserve_coin=locked_coin,
        locked_reserve_lineage_proof=LineageProof(b32(20), b32(21), uint64(100_000)),
        proposal_tracker_struct=TRACKER,
        admin_authority_struct=ADMIN,
        sgt_tail_hash=TAIL,
        wusdc_b_asset_id=WUSDC_B,
        company_treasury_puzzle_hash=TREASURY,
        bill=bill,
        voting_deadline=EXPIRES,
        tracker_inner_puzzle_hash=b32(22),
    )

    assert locked_spend.coin == locked_coin
    assert allocation_spend.coin.parent_coin_info == locked_coin.name()
    assert allocation_spend.coin.amount == locked_coin.amount
    assert {spend.coin.name() for spend in (locked_spend, allocation_spend)} == {
        locked_coin.name(),
        allocation_spend.coin.name(),
    }


def test_execute_spends_reject_a_locked_coin_for_another_bill() -> None:
    bill = sale_bill()
    wrong_bill = bill_sgt_grant(
        grant_id=b32(23),
        sgt_amount=1,
        recipient_vault_launcher_id=RECIPIENT_VAULT_LAUNCHER,
        reason_hash=b32(24),
        reserve_owner_inner_puzzle_hash=bytes32(reserve().get_tree_hash()),
    )
    reserve_inner = reserve()
    locked_inner = sgt_locked_inner_puzzle(
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        TRACKER,
        bytes32(reserve_inner.get_tree_hash()),
        proposal_hash_from_bill(wrong_bill),
        EXPIRES,
    )
    locked_full = construct_cat_puzzle(CAT_MOD, TAIL, locked_inner)
    locked_coin = Coin(b32(25), bytes32(locked_full.get_tree_hash()), uint64(100_000))

    with pytest.raises(ValueError, match="does not match"):
        build_reserve_execute_spends(
            locked_reserve_coin=locked_coin,
            locked_reserve_lineage_proof=LineageProof(b32(26), b32(27), uint64(100_000)),
            proposal_tracker_struct=TRACKER,
            admin_authority_struct=ADMIN,
            sgt_tail_hash=TAIL,
            wusdc_b_asset_id=WUSDC_B,
            company_treasury_puzzle_hash=TREASURY,
            bill=bill,
            voting_deadline=EXPIRES,
            tracker_inner_puzzle_hash=b32(28),
        )
