from __future__ import annotations

from dataclasses import replace

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    DeedAllocationCommitmentV2,
    VoucherCommitmentV2,
    VoucherPaymentRail,
    VoucherSeriesTermsV2,
    VoucherState,
    VoucherV2Error,
    allocation_root,
    technology_fee_minor,
    validate_purchase,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def allocation() -> tuple[DeedAllocationCommitmentV2, ...]:
    return (
        DeedAllocationCommitmentV2(b32(1), 600_000, 60, b32(2)),
        DeedAllocationCommitmentV2(b32(3), 400_000, 40, b32(4)),
    )


def series() -> VoucherSeriesTermsV2:
    return VoucherSeriesTermsV2(
        series_singleton_id=b32(5),
        collection_id=b32(6),
        metadata_root=b32(7),
        metadata_anchor_id=b32(8),
        allocation_root=allocation_root(allocation()),
        trusted_protocol_treasury=b32(9),
        base_return_puzzle_hash=b32(60),
        inventory_cap=2,
        sale_open=100,
        sale_close=200,
        refund_deadline=300,
        launch_deadline=400,
        validator_pubkeys=(bytes([10]) * 48, bytes([11]) * 48, bytes([12]) * 48),
    )


def voucher() -> VoucherCommitmentV2:
    terms = series()
    launcher = b32(13)
    base = 12_345
    fee = technology_fee_minor(base, 250)
    return VoucherCommitmentV2(
        series_terms_hash=terms.terms_hash,
        series_singleton_id=terms.series_singleton_id,
        collection_id=terms.collection_id,
        metadata_root=terms.metadata_root,
        allocation_root=terms.allocation_root,
        serial=0,
        payment_rail=VoucherPaymentRail.CHIA_XCH,
        payment_chain_id=0,
        payment_asset_id=bytes32.zeros,
        payment_asset_decimals=12,
        external_escrow_contract=bytes32.zeros,
        base_price_minor=base,
        technology_fee_bps=250,
        technology_fee_minor=fee,
        gross_price_minor=base + fee,
        payment_principal=600_000_000_000,
        original_payer=b32(14),
        approved_vault_launcher_id=launcher,
        approved_vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(launcher),
        refund_deadline=terms.refund_deadline,
        delivery_window_seconds=DELIVERY_WINDOW_SECONDS,
        trusted_protocol_treasury=terms.trusted_protocol_treasury,
        deed_launcher_id=allocation()[0].deed_launcher_id,
        smart_deed_inner_hash=b32(15),
        purchase_artifact_hash=b32(17),
        global_payment_id=b32(16),
    )


def test_fee_rounds_up_and_is_capped() -> None:
    assert technology_fee_minor(1, 1) == 1
    assert technology_fee_minor(10_000, 1_000) == 1_000
    with pytest.raises(VoucherV2Error, match="1000"):
        technology_fee_minor(10_000, 1_001)


def test_allocation_is_order_independent_and_exact() -> None:
    rows = allocation()
    assert allocation_root(rows) == allocation_root(reversed(rows))
    with pytest.raises(VoucherV2Error, match="1,000,000"):
        allocation_root((replace(rows[0], share_ppm=599_999), rows[1]))
    with pytest.raises(VoucherV2Error, match="unique"):
        allocation_root((rows[0], replace(rows[1], deed_id=rows[0].deed_id)))


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("series_singleton_id", bytes32.zeros, "cannot be zero"),
        ("metadata_root", b32(22), "differs from series"),
        ("allocation_root", b32(23), "differs from series"),
        ("trusted_protocol_treasury", b32(24), "differs from series"),
        ("serial", 2, "exceeds inventory"),
    ],
)
def test_purchase_rejects_changed_immutable_terms(field: str, value: object, message: str) -> None:
    item = voucher()
    if field == "series_singleton_id":
        with pytest.raises(VoucherV2Error, match=message):
            replace(item, **{field: value})
        return
    changed = replace(item, **{field: value})
    with pytest.raises(VoucherV2Error, match=message):
        validate_purchase(series=series(), voucher=changed, now_seconds=150)


def test_vault_fee_and_delivery_window_are_intrinsic() -> None:
    item = voucher()
    with pytest.raises(VoucherV2Error, match="canonical p2_vault"):
        replace(item, approved_vault_p2_puzzle_hash=b32(25))
    with pytest.raises(VoucherV2Error, match="ceil fee"):
        replace(item, technology_fee_minor=item.technology_fee_minor + 1)
    with pytest.raises(VoucherV2Error, match="48 hours"):
        replace(item, delivery_window_seconds=DELIVERY_WINDOW_SECONDS - 1)
    assert item.delivery_deadline(700) == 700 + DELIVERY_WINDOW_SECONDS
    assert item.delivery_is_overdue(
        launched_at=700, now_seconds=700 + DELIVERY_WINDOW_SECONDS
    )


def test_refund_and_redemption_are_terminal_state_machines() -> None:
    item = voucher()
    assert item.begin_refund().finish_refund().state == VoucherState.REFUNDED
    assert item.begin_redemption().finish_redemption().state == VoucherState.REDEEMED
    with pytest.raises(VoucherV2Error):
        item.begin_refund().begin_redemption()


def test_purchase_window_is_fail_closed() -> None:
    validate_purchase(series=series(), voucher=voucher(), now_seconds=150)
    with pytest.raises(VoucherV2Error, match="not open"):
        validate_purchase(series=series(), voucher=voucher(), now_seconds=200)
