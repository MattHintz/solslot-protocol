"""Strict parsing of historical and current non-Stripe voucher purchases.

Voucher and purchase schemas are independent. Never rehash a historical purchase
as V3: the original artifact is part of the paid voucher commitment.
"""
from typing import Any, Mapping

from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError, PaymentRail, PurchaseArtifactV2, purchase_artifact_from_json,
)
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3, PurchaseDeliveryKind, PurchaseKind, purchase_artifact_v3_from_json,
)
from solslot_puzzles.primary_purchase_v2_driver import BASE_SEPOLIA_USDC_ASSET_ID
from solslot_puzzles.voucher_presale_v2 import VoucherCommitmentV2, VoucherPaymentRail, VoucherSeriesTermsV2


def require_current_base_presale(purchase: PurchaseArtifactV3) -> None:
    if not isinstance(purchase, PurchaseArtifactV3) or (
        purchase.network != "testnet11"
        or purchase.rail != PaymentRail.EVM_TEST_USD
        or purchase.rail_chain_id != 84532
        or purchase.rail_asset_id != BASE_SEPOLIA_USDC_ASSET_ID
        or purchase.rail_asset_decimals != 6
        or purchase.purchase_kind != PurchaseKind.PRESALE
        or purchase.delivery_kind != PurchaseDeliveryKind.SMARTDEED
    ):
        raise PaymentArtifactError("current Base voucher requires a Testnet11 Base Sepolia USDC SmartDeed presale")


def voucher_purchase_from_json(value: Mapping[str, Any]) -> PurchaseArtifactV2 | PurchaseArtifactV3:
    if value.get("schema") == "solslot.purchase-artifact.v3":
        purchase = purchase_artifact_v3_from_json(value)
        require_current_base_presale(purchase)
        return purchase
    return purchase_artifact_from_json(value)


def validate_base_voucher_purchase(
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2 | PurchaseArtifactV3,
    series: VoucherSeriesTermsV2 | None = None,
) -> None:
    if (
        voucher.payment_rail != VoucherPaymentRail.BASE_SEPOLIA_USDC
        or purchase.rail != PaymentRail.EVM_TEST_USD
        or voucher.payment_chain_id != 84532 or purchase.rail_chain_id != 84532
        or voucher.payment_asset_id != BASE_SEPOLIA_USDC_ASSET_ID
        or purchase.rail_asset_id != BASE_SEPOLIA_USDC_ASSET_ID
        or voucher.payment_asset_decimals != 6 or purchase.rail_asset_decimals != 6
    ):
        raise PaymentArtifactError("Base voucher requires official six-decimal Base Sepolia USDC")
    comparisons = (
        (purchase.collection_id, voucher.collection_id),
        (purchase.deed_launcher_id, voucher.deed_launcher_id),
        (purchase.metadata_root, voucher.metadata_root),
        (purchase.vault_launcher_id, voucher.approved_vault_launcher_id),
        (purchase.vault_p2_puzzle_hash, voucher.approved_vault_p2_puzzle_hash),
    )
    if any(left != right for left, right in comparisons):
        raise PaymentArtifactError("purchase artifact differs from voucher commitments")
    if (purchase.usd_amount_minor != voucher.gross_price_minor
        or purchase.rail_amount != voucher.payment_principal
        or purchase.artifact_hash != voucher.purchase_artifact_hash):
        raise PaymentArtifactError("purchase price differs from voucher commitments")
    if isinstance(purchase, PurchaseArtifactV3):
        require_current_base_presale(purchase)
        if (purchase.presale_terms_hash != voucher.series_terms_hash
            or purchase.base_amount_minor != voucher.base_price_minor
            or purchase.technology_fee_bps != voucher.technology_fee_bps
            or purchase.technology_fee_minor != voucher.technology_fee_minor
            or purchase.protocol_treasury_puzzle_hash != voucher.trusted_protocol_treasury):
            raise PaymentArtifactError("current Base purchase differs from governed presale economics")
        if series is not None and (
            purchase.presale_terms_hash != series.terms_hash
            or purchase.metadata_anchor_id != series.metadata_anchor_id
            or not series.sale_open < purchase.quote_expires_at <= series.sale_close
        ):
            raise PaymentArtifactError("current Base purchase differs from governed series or sale window")
