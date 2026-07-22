from __future__ import annotations

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v1 import (
    PresalePhase,
    VoucherPaymentRail,
    VoucherPresaleError,
    VoucherPresaleTermsV1,
    VoucherRecordV1,
    validate_launch,
    validate_purchase,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def terms() -> VoucherPresaleTermsV1:
    return VoucherPresaleTermsV1(
        series_id=b32(1),
        property_id=b32(2),
        collection_id=b32(3),
        metadata_root=b32(4),
        metadata_anchor_id=b32(5),
        identity_attest_root=b32(6),
        bridge_policy_hash=b32(7),
        admin_authority_launcher_id=b32(8),
        governance_launcher_id=b32(9),
        voucher_collection_launcher_id=b32(10),
        inventory_cap=10,
        xch_price_mojos=2_000_000_000,
        base_usdc_price_units=250_000_000,
        sale_open=100,
        sale_close=200,
        launch_deadline=300,
    )


def voucher(phase: PresalePhase = PresalePhase.PRESALE) -> VoucherRecordV1:
    return VoucherRecordV1(
        terms_hash=terms().terms_hash,
        serial=3,
        payment_rail=VoucherPaymentRail.BASE_SEPOLIA_USDC,
        payment_principal=250_000_000,
        vault_launcher_id=b32(11),
        holder_member_hash=b32(12),
        base_depositor_commitment=b32(13),
        global_payment_id=b32(14),
        phase=phase,
    )


def test_terms_hash_is_deterministic_and_quorum_is_fifty_percent() -> None:
    assert terms().terms_hash == terms().terms_hash
    assert terms().quorum_required == 500_000


def test_purchase_requires_open_window_exact_rail_price_and_available_serial() -> None:
    validate_purchase(
        terms=terms(),
        serial=9,
        rail=VoucherPaymentRail.CHIA_XCH,
        principal=2_000_000_000,
        now_seconds=100,
    )
    with pytest.raises(VoucherPresaleError, match="not open"):
        validate_purchase(
            terms=terms(),
            serial=0,
            rail=VoucherPaymentRail.CHIA_XCH,
            principal=2_000_000_000,
            now_seconds=200,
        )
    with pytest.raises(VoucherPresaleError, match="inventory"):
        validate_purchase(
            terms=terms(),
            serial=10,
            rail=VoucherPaymentRail.CHIA_XCH,
            principal=2_000_000_000,
            now_seconds=150,
        )
    with pytest.raises(VoucherPresaleError, match="principal"):
        validate_purchase(
            terms=terms(),
            serial=0,
            rail=VoucherPaymentRail.BASE_SEPOLIA_USDC,
            principal=1,
            now_seconds=150,
        )


def test_voucher_is_always_bound_to_original_member_vault_custody() -> None:
    record = voucher()
    assert record.custody_puzzle_hash == puzzle_hash_for_p2_vault(b32(11))
    assert record.refund().custody_puzzle_hash == record.custody_puzzle_hash
    live = voucher(PresalePhase.LIVE)
    assert live.redeem().custody_puzzle_hash == live.custody_puzzle_hash


def test_refund_and_redemption_phases_are_restricted() -> None:
    record = voucher()
    assert record.refund().phase == PresalePhase.CANCELED
    with pytest.raises(VoucherPresaleError, match="only live"):
        record.redeem()
    live = voucher(PresalePhase.LIVE)
    assert live.redeem().phase == PresalePhase.CANCELED
    with pytest.raises(VoucherPresaleError, match="only presale"):
        live.refund()


def test_launch_requires_admin_quorum_and_deadline() -> None:
    validate_launch(terms=terms(), now_seconds=200, vote_tally=500_000, admin_approved=True)
    with pytest.raises(VoucherPresaleError, match="admin"):
        validate_launch(terms=terms(), now_seconds=200, vote_tally=500_000, admin_approved=False)
    with pytest.raises(VoucherPresaleError, match="quorum"):
        validate_launch(terms=terms(), now_seconds=200, vote_tally=499_999, admin_approved=True)
    with pytest.raises(VoucherPresaleError, match="deadline"):
        validate_launch(terms=terms(), now_seconds=301, vote_tally=500_000, admin_approved=True)
