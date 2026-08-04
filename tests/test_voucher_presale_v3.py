from __future__ import annotations

from dataclasses import replace

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentAttestationV1,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.payment_artifacts_v3 import (
    STRIPE_PAYMENT_PROVIDER_ID,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    StripeSettlementReceiptV1,
    build_stripe_pending_attestation,
    build_stripe_purchase_artifact,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import VoucherSeriesTermsV2
from solslot_puzzles.voucher_presale_v3 import (
    VoucherV3Error,
    build_stripe_voucher_commitment,
    validate_stripe_voucher_purchase,
    voucher_commitment_v3_from_json,
    voucher_commitment_v3_to_json,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def terms() -> VoucherSeriesTermsV2:
    return VoucherSeriesTermsV2(
        series_singleton_id=b32(1),
        collection_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        allocation_root=b32(5),
        trusted_protocol_treasury=b32(6),
        base_return_puzzle_hash=b32(7),
        inventory_cap=25,
        sale_open=1_700_000_000,
        sale_close=1_700_010_000,
        refund_deadline=1_700_020_000,
        launch_deadline=1_700_030_000,
        validator_pubkeys=(bytes([1]) * 48, bytes([2]) * 48, bytes([3]) * 48),
    )


def receipt(
    *,
    processing_charge: int = 0,
    quote_expires_at: int = 1_700_010_000,
) -> StripeSettlementReceiptV1:
    series = terms()
    vault = b32(8)
    artifact = build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=series.collection_id,
        deed_launcher_id=b32(9),
        metadata_root=series.metadata_root,
        metadata_anchor_id=series.metadata_anchor_id,
        share_ppm=40_000,
        base_amount_minor=22_900,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=series.trusted_protocol_treasury,
        zkpassport_root=b32(10),
        vault_launcher_id=vault,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault),
        authorization_nonce=b32(11),
        authorization_expires_at=1_800_000_000,
        quote_expires_at=quote_expires_at,
        presale_terms_hash=series.terms_hash,
    )
    evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_rc24",
        livemode=False,
        payment_intent_id="pi_presale_rc24",
        event_id="evt_presale_rc24",
        amount_minor=artifact.subtotal_minor + processing_charge,
        currency="usd",
        method_family=StripeMethodFamily.CARD,
        funding_type=(
            StripeFundingType.CREDIT
            if processing_charge
            else StripeFundingType.DEBIT
        ),
        processing_charge_minor=processing_charge,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=1_700_000_100,
    )
    pending = build_stripe_pending_attestation(
        artifact=artifact,
        evidence=evidence,
        observed_at=1_700_000_000,
    )
    succeeded = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=STRIPE_PAYMENT_PROVIDER_ID,
        external_reference_hash=evidence.payment_reference_hash,
        evidence_hash=evidence.evidence_hash,
        previous_attestation_hash=pending.attestation_hash,
        observed_at=evidence.observed_at,
    )
    return StripeSettlementReceiptV1(
        artifact=artifact,
        evidence=evidence,
        attestation=succeeded,
        validator_roster_root=b32(12),
        validator_threshold=2,
        receipt_nonce=b32(13),
        expires_at=evidence.observed_at + 48 * 60 * 60,
    )


def voucher(*, processing_charge: int = 0):
    stripe_receipt = receipt(processing_charge=processing_charge)
    item = build_stripe_voucher_commitment(
        series=terms(),
        allocation_root=terms().allocation_root,
        serial=3,
        original_payer=b32(14),
        smart_deed_inner_hash=bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        ),
        artifact=stripe_receipt.artifact,
        receipt=stripe_receipt,
    )
    return item, stripe_receipt


def test_stripe_voucher_binds_full_charge_without_exposing_payment_intent() -> None:
    item, stripe_receipt = voucher(processing_charge=300)
    assert item.processing_charge_minor == 300
    assert item.payment_principal == item.gross_price_minor + 300
    assert item.stripe_reference_hash == stripe_receipt.evidence.payment_reference_hash
    assert b"pi_presale_rc24" not in bytes(item.to_program())


def test_stripe_voucher_round_trip_rederives_commitment() -> None:
    item, _stripe_receipt = voucher()
    payload = voucher_commitment_v3_to_json(item)
    assert voucher_commitment_v3_from_json(payload) == item
    payload["processingChargeMinor"] = 1
    with pytest.raises(VoucherV3Error):
        voucher_commitment_v3_from_json(payload)


def test_stripe_voucher_rejects_wrong_receipt_and_late_quote() -> None:
    item, stripe_receipt = voucher()
    validate_stripe_voucher_purchase(
        series=terms(),
        voucher=item,
        artifact=stripe_receipt.artifact,
        receipt=stripe_receipt,
        expected_original_payer=b32(14),
        expected_smart_deed_inner_hash=item.smart_deed_inner_hash,
        now_seconds=terms().sale_open,
    )
    with pytest.raises(VoucherV3Error, match="canonical"):
        validate_stripe_voucher_purchase(
            series=terms(),
            voucher=replace(item, original_payer=b32(15)),
            artifact=stripe_receipt.artifact,
            receipt=stripe_receipt,
            expected_original_payer=b32(14),
            expected_smart_deed_inner_hash=item.smart_deed_inner_hash,
            now_seconds=terms().sale_open,
        )
    late_receipt = receipt(quote_expires_at=terms().sale_close + 1)
    late_artifact = late_receipt.artifact
    late_item = build_stripe_voucher_commitment(
        series=terms(),
        allocation_root=terms().allocation_root,
        serial=3,
        original_payer=b32(14),
        smart_deed_inner_hash=item.smart_deed_inner_hash,
        artifact=late_artifact,
        receipt=late_receipt,
    )
    with pytest.raises(VoucherV3Error, match="quote"):
        validate_stripe_voucher_purchase(
            series=terms(),
            voucher=late_item,
            artifact=late_artifact,
            receipt=late_receipt,
            expected_original_payer=b32(14),
            expected_smart_deed_inner_hash=item.smart_deed_inner_hash,
            now_seconds=terms().sale_close,
        )


def test_stripe_voucher_accepts_delayed_ach_settlement_for_live_quote() -> None:
    item, stripe_receipt = voucher()
    validate_stripe_voucher_purchase(
        series=terms(),
        voucher=item,
        artifact=stripe_receipt.artifact,
        receipt=stripe_receipt,
        expected_original_payer=b32(14),
        expected_smart_deed_inner_hash=item.smart_deed_inner_hash,
        now_seconds=terms().sale_close + 5 * 24 * 60 * 60,
    )


def test_direct_stripe_artifact_cannot_become_a_voucher() -> None:
    stripe_receipt = receipt()
    direct = replace(
        stripe_receipt.artifact,
        purchase_kind=type(stripe_receipt.artifact.purchase_kind).DIRECT,
        presale_terms_hash=bytes32.zeros,
    )
    with pytest.raises(VoucherV3Error, match="presale"):
        build_stripe_voucher_commitment(
            series=terms(),
            allocation_root=terms().allocation_root,
            serial=3,
            original_payer=b32(14),
            smart_deed_inner_hash=b32(16),
            artifact=direct,
            receipt=stripe_receipt,
        )
