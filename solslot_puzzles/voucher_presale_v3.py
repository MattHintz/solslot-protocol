"""RC24 Stripe voucher commitments layered on the frozen RC20 series.

The V2 series state machine and atomic purchase launcher intentionally remain
unchanged.  This module adds the Stripe-specific immutable fields needed for
an asynchronously settled, refundable presale voucher.  No Stripe identifier
is placed on chain in clear text.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any, Final, Mapping

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3,
    PurchaseKind,
    StripeSettlementReceiptV1,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    VoucherSeriesTermsV2,
    VoucherState,
    technology_fee_minor,
)


VOUCHER_V3_DOMAIN: Final[bytes] = b"SOLSLOT_REFUNDABLE_VOUCHER_V3"
STRIPE_GLOBAL_PAYMENT_DOMAIN: Final[bytes] = b"SOLSLOT_STRIPE_VOUCHER_PAYMENT_V1"
STRIPE_ORIGINAL_PAYER_DOMAIN: Final[bytes] = b"SOLSLOT_STRIPE_ORIGINAL_PAYER_V1"


class VoucherV3Error(ValueError):
    pass


class VoucherPaymentRailV3(IntEnum):
    BASE_SEPOLIA_USDC = 1
    CHIA_XCH = 2
    STRIPE_USD = 3


@dataclass(frozen=True)
class VoucherCommitmentV3:
    series_terms_hash: bytes32
    series_singleton_id: bytes32
    collection_id: bytes32
    metadata_root: bytes32
    allocation_root: bytes32
    serial: int
    payment_rail: VoucherPaymentRailV3
    payment_chain_id: int
    payment_asset_id: bytes32
    payment_asset_decimals: int
    external_escrow_contract: bytes32
    base_price_minor: int
    technology_fee_bps: int
    technology_fee_minor: int
    gross_price_minor: int
    processing_charge_minor: int
    payment_principal: int
    original_payer: bytes32
    approved_vault_launcher_id: bytes32
    approved_vault_p2_puzzle_hash: bytes32
    refund_deadline: int
    delivery_window_seconds: int
    trusted_protocol_treasury: bytes32
    deed_launcher_id: bytes32
    smart_deed_inner_hash: bytes32
    purchase_artifact_hash: bytes32
    stripe_reference_hash: bytes32
    stripe_evidence_hash: bytes32
    payment_attestation_hash: bytes32
    stripe_receipt_hash: bytes32
    global_payment_id: bytes32
    state: VoucherState = VoucherState.ESCROWED

    def __post_init__(self) -> None:
        for name in (
            "series_terms_hash",
            "series_singleton_id",
            "collection_id",
            "metadata_root",
            "allocation_root",
            "original_payer",
            "approved_vault_launcher_id",
            "approved_vault_p2_puzzle_hash",
            "trusted_protocol_treasury",
            "deed_launcher_id",
            "smart_deed_inner_hash",
            "purchase_artifact_hash",
            "global_payment_id",
        ):
            _b32(getattr(self, name), name, nonzero=True)
        for name in (
            "payment_asset_id",
            "external_escrow_contract",
            "stripe_reference_hash",
            "stripe_evidence_hash",
            "payment_attestation_hash",
            "stripe_receipt_hash",
        ):
            _b32(getattr(self, name), name)
        for name in (
            "serial",
            "payment_chain_id",
            "payment_asset_decimals",
            "base_price_minor",
            "technology_fee_bps",
            "technology_fee_minor",
            "gross_price_minor",
            "processing_charge_minor",
            "payment_principal",
            "refund_deadline",
            "delivery_window_seconds",
        ):
            _u64(
                getattr(self, name),
                name,
                positive=name
                not in {
                    "serial",
                    "payment_chain_id",
                    "technology_fee_bps",
                    "technology_fee_minor",
                    "processing_charge_minor",
                },
            )
        if self.payment_asset_decimals > 18:
            raise VoucherV3Error("payment_asset_decimals exceeds 18")
        if self.payment_rail != VoucherPaymentRailV3.STRIPE_USD:
            raise VoucherV3Error(
                "RC24 Voucher V3 is reserved for the Stripe USD rail"
            )
        if (
            self.payment_chain_id != 0
            or self.payment_asset_id != bytes32.zeros
            or self.payment_asset_decimals != 2
            or self.external_escrow_contract != bytes32.zeros
        ):
            raise VoucherV3Error("Stripe voucher rail coordinates are invalid")
        if bytes32.zeros in {
            self.stripe_reference_hash,
            self.stripe_evidence_hash,
            self.payment_attestation_hash,
            self.stripe_receipt_hash,
        }:
            raise VoucherV3Error("Stripe voucher receipt commitments cannot be zero")
        expected_fee = technology_fee_minor(
            self.base_price_minor,
            self.technology_fee_bps,
        )
        if self.technology_fee_minor != expected_fee:
            raise VoucherV3Error("technology fee does not match the governed rate")
        if self.gross_price_minor != self.base_price_minor + expected_fee:
            raise VoucherV3Error("gross price must equal base plus technology fee")
        if (
            self.payment_principal
            != self.gross_price_minor + self.processing_charge_minor
        ):
            raise VoucherV3Error(
                "Stripe principal must equal gross price plus processing charge"
            )
        if self.delivery_window_seconds != DELIVERY_WINDOW_SECONDS:
            raise VoucherV3Error("delivery window must be exactly 48 hours")
        expected_vault = puzzle_hash_for_p2_vault(
            self.approved_vault_launcher_id
        )
        if self.approved_vault_p2_puzzle_hash != expected_vault:
            raise VoucherV3Error(
                "approved vault puzzle hash is not canonical p2_vault"
            )

    def to_program(self, *, include_state: bool = True) -> Program:
        fields: list[object] = [
            VOUCHER_V3_DOMAIN,
            self.series_terms_hash,
            self.series_singleton_id,
            self.collection_id,
            self.metadata_root,
            self.allocation_root,
            self.serial,
            int(self.payment_rail),
            self.payment_chain_id,
            self.payment_asset_id,
            self.payment_asset_decimals,
            self.external_escrow_contract,
            self.base_price_minor,
            self.technology_fee_bps,
            self.technology_fee_minor,
            self.gross_price_minor,
            self.processing_charge_minor,
            self.payment_principal,
            self.original_payer,
            self.approved_vault_launcher_id,
            self.approved_vault_p2_puzzle_hash,
            self.refund_deadline,
            self.delivery_window_seconds,
            self.trusted_protocol_treasury,
            self.deed_launcher_id,
            self.smart_deed_inner_hash,
            self.purchase_artifact_hash,
            self.stripe_reference_hash,
            self.stripe_evidence_hash,
            self.payment_attestation_hash,
            self.stripe_receipt_hash,
            self.global_payment_id,
        ]
        if include_state:
            fields.append(int(self.state))
        return Program.to(fields)

    @property
    def commitment_hash(self) -> bytes32:
        return bytes32(self.to_program(include_state=False).get_tree_hash())

    @property
    def voucher_id(self) -> bytes32:
        return bytes32(
            Program.to(
                [VOUCHER_V3_DOMAIN, b"VOUCHER", self.series_singleton_id, self.serial]
            ).get_tree_hash()
        )

    def begin_refund(self) -> "VoucherCommitmentV3":
        if self.state != VoucherState.ESCROWED:
            raise VoucherV3Error("only ESCROWED vouchers may begin a refund")
        return replace(self, state=VoucherState.REFUNDING)

    def finish_refund(self) -> "VoucherCommitmentV3":
        if self.state != VoucherState.REFUNDING:
            raise VoucherV3Error("refund completion requires REFUNDING state")
        return replace(self, state=VoucherState.REFUNDED)

    def begin_redemption(self) -> "VoucherCommitmentV3":
        if self.state != VoucherState.ESCROWED:
            raise VoucherV3Error("only ESCROWED vouchers may begin redemption")
        return replace(self, state=VoucherState.REDEEMING)

    def finish_redemption(self) -> "VoucherCommitmentV3":
        if self.state != VoucherState.REDEEMING:
            raise VoucherV3Error("redemption completion requires REDEEMING state")
        return replace(self, state=VoucherState.REDEEMED)


def build_stripe_voucher_commitment(
    *,
    series: VoucherSeriesTermsV2,
    allocation_root: bytes32,
    serial: int,
    original_payer: bytes32,
    smart_deed_inner_hash: bytes32,
    artifact: PurchaseArtifactV3,
    receipt: StripeSettlementReceiptV1,
) -> VoucherCommitmentV3:
    """Derive the only accepted Stripe voucher from governed payment evidence."""

    if artifact.purchase_kind != PurchaseKind.PRESALE:
        raise VoucherV3Error("Stripe voucher requires a presale purchase artifact")
    if artifact.presale_terms_hash != series.terms_hash:
        raise VoucherV3Error("purchase artifact targets another presale series")
    if artifact.rail != PaymentRail.STRIPE or receipt.artifact != artifact:
        raise VoucherV3Error("Stripe receipt does not match the presale purchase")
    if receipt.evidence.payment_reference_hash == bytes32.zeros:
        raise VoucherV3Error("Stripe payment reference cannot be zero")
    global_payment_id = bytes32(
        Program.to(
            [
                STRIPE_GLOBAL_PAYMENT_DOMAIN,
                artifact.purchase_id,
                receipt.evidence.payment_reference_hash,
            ]
        ).get_tree_hash()
    )
    return VoucherCommitmentV3(
        series_terms_hash=series.terms_hash,
        series_singleton_id=series.series_singleton_id,
        collection_id=series.collection_id,
        metadata_root=series.metadata_root,
        allocation_root=allocation_root,
        serial=serial,
        payment_rail=VoucherPaymentRailV3.STRIPE_USD,
        payment_chain_id=0,
        payment_asset_id=bytes32.zeros,
        payment_asset_decimals=2,
        external_escrow_contract=bytes32.zeros,
        base_price_minor=artifact.base_amount_minor,
        technology_fee_bps=artifact.technology_fee_bps,
        technology_fee_minor=artifact.technology_fee_minor,
        gross_price_minor=artifact.subtotal_minor,
        processing_charge_minor=receipt.evidence.processing_charge_minor,
        payment_principal=receipt.evidence.amount_minor,
        original_payer=original_payer,
        approved_vault_launcher_id=artifact.vault_launcher_id,
        approved_vault_p2_puzzle_hash=artifact.vault_p2_puzzle_hash,
        refund_deadline=series.refund_deadline,
        delivery_window_seconds=DELIVERY_WINDOW_SECONDS,
        trusted_protocol_treasury=series.trusted_protocol_treasury,
        deed_launcher_id=artifact.deed_launcher_id,
        smart_deed_inner_hash=smart_deed_inner_hash,
        purchase_artifact_hash=artifact.artifact_hash,
        stripe_reference_hash=receipt.evidence.payment_reference_hash,
        stripe_evidence_hash=receipt.evidence.evidence_hash,
        payment_attestation_hash=receipt.attestation.attestation_hash,
        stripe_receipt_hash=receipt.receipt_hash,
        global_payment_id=global_payment_id,
    )


def stripe_original_payer(artifact: PurchaseArtifactV3) -> bytes32:
    """Derive a private, validator-reproducible Stripe payer commitment."""

    if artifact.purchase_kind != PurchaseKind.PRESALE:
        raise VoucherV3Error("Stripe payer commitment requires a presale artifact")
    return bytes32(
        Program.to(
            [
                STRIPE_ORIGINAL_PAYER_DOMAIN,
                artifact.purchase_id,
                artifact.artifact_hash,
                artifact.vault_launcher_id,
                artifact.vault_p2_puzzle_hash,
            ]
        ).get_tree_hash()
    )


def validate_stripe_voucher_purchase(
    *,
    series: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV3,
    artifact: PurchaseArtifactV3,
    receipt: StripeSettlementReceiptV1,
    expected_original_payer: bytes32,
    expected_smart_deed_inner_hash: bytes32,
    now_seconds: int,
) -> None:
    _u64(now_seconds, "now_seconds")
    expected = build_stripe_voucher_commitment(
        series=series,
        allocation_root=series.allocation_root,
        serial=voucher.serial,
        original_payer=expected_original_payer,
        smart_deed_inner_hash=expected_smart_deed_inner_hash,
        artifact=artifact,
        receipt=receipt,
    )
    if expected != voucher:
        raise VoucherV3Error("Stripe voucher differs from canonical commitments")
    if not series.sale_open <= now_seconds < series.sale_close:
        raise VoucherV3Error("presale is not open")
    if voucher.serial >= series.inventory_cap:
        raise VoucherV3Error("voucher serial exceeds inventory")


def voucher_commitment_v3_to_json(value: VoucherCommitmentV3) -> dict[str, Any]:
    return {
        "schema": "solslot.voucher-commitment.v3",
        "seriesTermsHash": _hex(value.series_terms_hash),
        "seriesSingletonId": _hex(value.series_singleton_id),
        "collectionId": _hex(value.collection_id),
        "metadataRoot": _hex(value.metadata_root),
        "allocationRoot": _hex(value.allocation_root),
        "serial": value.serial,
        "paymentRail": int(value.payment_rail),
        "paymentChainId": value.payment_chain_id,
        "paymentAssetId": _hex(value.payment_asset_id),
        "paymentAssetDecimals": value.payment_asset_decimals,
        "externalEscrowContract": _hex(value.external_escrow_contract),
        "basePriceMinor": value.base_price_minor,
        "technologyFeeBps": value.technology_fee_bps,
        "technologyFeeMinor": value.technology_fee_minor,
        "grossPriceMinor": value.gross_price_minor,
        "processingChargeMinor": value.processing_charge_minor,
        "paymentPrincipal": value.payment_principal,
        "originalPayer": _hex(value.original_payer),
        "approvedVaultLauncherId": _hex(value.approved_vault_launcher_id),
        "approvedVaultP2PuzzleHash": _hex(value.approved_vault_p2_puzzle_hash),
        "refundDeadline": value.refund_deadline,
        "deliveryWindowSeconds": value.delivery_window_seconds,
        "trustedProtocolTreasury": _hex(value.trusted_protocol_treasury),
        "deedLauncherId": _hex(value.deed_launcher_id),
        "smartDeedInnerHash": _hex(value.smart_deed_inner_hash),
        "purchaseArtifactHash": _hex(value.purchase_artifact_hash),
        "stripeReferenceHash": _hex(value.stripe_reference_hash),
        "stripeEvidenceHash": _hex(value.stripe_evidence_hash),
        "paymentAttestationHash": _hex(value.payment_attestation_hash),
        "stripeReceiptHash": _hex(value.stripe_receipt_hash),
        "globalPaymentId": _hex(value.global_payment_id),
        "commitmentHash": _hex(value.commitment_hash),
    }


def voucher_commitment_v3_from_json(
    value: Mapping[str, Any],
) -> VoucherCommitmentV3:
    try:
        if value.get("schema") != "solslot.voucher-commitment.v3":
            raise ValueError("voucher schema is unsupported")
        result = VoucherCommitmentV3(
            series_terms_hash=_json_b32(value, "seriesTermsHash"),
            series_singleton_id=_json_b32(value, "seriesSingletonId"),
            collection_id=_json_b32(value, "collectionId"),
            metadata_root=_json_b32(value, "metadataRoot"),
            allocation_root=_json_b32(value, "allocationRoot"),
            serial=_json_int(value, "serial"),
            payment_rail=VoucherPaymentRailV3(_json_int(value, "paymentRail")),
            payment_chain_id=_json_int(value, "paymentChainId"),
            payment_asset_id=_json_b32(value, "paymentAssetId", nonzero=False),
            payment_asset_decimals=_json_int(value, "paymentAssetDecimals"),
            external_escrow_contract=_json_b32(
                value, "externalEscrowContract", nonzero=False
            ),
            base_price_minor=_json_int(value, "basePriceMinor"),
            technology_fee_bps=_json_int(value, "technologyFeeBps"),
            technology_fee_minor=_json_int(value, "technologyFeeMinor"),
            gross_price_minor=_json_int(value, "grossPriceMinor"),
            processing_charge_minor=_json_int(value, "processingChargeMinor"),
            payment_principal=_json_int(value, "paymentPrincipal"),
            original_payer=_json_b32(value, "originalPayer"),
            approved_vault_launcher_id=_json_b32(
                value, "approvedVaultLauncherId"
            ),
            approved_vault_p2_puzzle_hash=_json_b32(
                value, "approvedVaultP2PuzzleHash"
            ),
            refund_deadline=_json_int(value, "refundDeadline"),
            delivery_window_seconds=_json_int(value, "deliveryWindowSeconds"),
            trusted_protocol_treasury=_json_b32(
                value, "trustedProtocolTreasury"
            ),
            deed_launcher_id=_json_b32(value, "deedLauncherId"),
            smart_deed_inner_hash=_json_b32(value, "smartDeedInnerHash"),
            purchase_artifact_hash=_json_b32(value, "purchaseArtifactHash"),
            stripe_reference_hash=_json_b32(value, "stripeReferenceHash"),
            stripe_evidence_hash=_json_b32(value, "stripeEvidenceHash"),
            payment_attestation_hash=_json_b32(
                value, "paymentAttestationHash"
            ),
            stripe_receipt_hash=_json_b32(value, "stripeReceiptHash"),
            global_payment_id=_json_b32(value, "globalPaymentId"),
        )
        commitment = value.get("commitmentHash")
        if commitment is not None and _json_hex(commitment, 32) != bytes(
            result.commitment_hash
        ):
            raise ValueError("voucher commitment hash does not re-derive")
        return result
    except (KeyError, PaymentArtifactError, TypeError, ValueError) as exc:
        raise VoucherV3Error("voucher V3 JSON is malformed") from exc


def _hex(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def _json_hex(value: object, size: int) -> bytes:
    if not isinstance(value, str):
        raise TypeError("hex value must be a string")
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != size:
        raise ValueError(f"hex value must be {size} bytes")
    return raw


def _json_b32(
    value: Mapping[str, Any], field: str, *, nonzero: bool = True
) -> bytes32:
    result = bytes32(_json_hex(value[field], 32))
    if nonzero and result == bytes32.zeros:
        raise ValueError(f"{field} cannot be zero")
    return result


def _json_int(value: Mapping[str, Any], field: str) -> int:
    result = value[field]
    if isinstance(result, bool) or not isinstance(result, int):
        raise TypeError(f"{field} must be an integer")
    return result


def _b32(value: bytes32, name: str, *, nonzero: bool = False) -> None:
    if not isinstance(value, bytes32):
        raise VoucherV3Error(f"{name} must be bytes32")
    if nonzero and value == bytes32.zeros:
        raise VoucherV3Error(f"{name} cannot be zero")


def _u64(value: int, name: str, *, positive: bool = False) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 0xFFFFFFFFFFFFFFFF
    ):
        raise VoucherV3Error(f"{name} must be uint64")
    if positive and value == 0:
        raise VoucherV3Error(f"{name} must be positive")


__all__ = [
    "STRIPE_GLOBAL_PAYMENT_DOMAIN",
    "STRIPE_ORIGINAL_PAYER_DOMAIN",
    "VOUCHER_V3_DOMAIN",
    "VoucherCommitmentV3",
    "VoucherPaymentRailV3",
    "VoucherV3Error",
    "build_stripe_voucher_commitment",
    "stripe_original_payer",
    "validate_stripe_voucher_purchase",
    "voucher_commitment_v3_from_json",
    "voucher_commitment_v3_to_json",
]
