"""Canonical RC24 direct-purchase and Stripe settlement artifacts.

The fixed-order CLVM lists in this module are the authorization contract.
Transport JSON is accepted only when its program, artifact, and receipt hashes
re-derive exactly.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
from typing import Any, Mapping

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    OracleRoundV1,
    PaymentArtifactError,
    PaymentAttestationV1,
    PaymentRail,
    PaymentResolution,
    PaymentTransition,
    ZERO_32,
)


PURCHASE_ARTIFACT_SCHEMA = "solslot.purchase-artifact.v3"
PURCHASE_ARTIFACT_V3_SCHEMA = PURCHASE_ARTIFACT_SCHEMA
STRIPE_SETTLEMENT_EVIDENCE_SCHEMA = "solslot.stripe-settlement-evidence.v1"
STRIPE_SETTLEMENT_RECEIPT_SCHEMA = "solslot.stripe-settlement-receipt.v1"
EXTERNAL_SETTLEMENT_RECEIPT_SCHEMA = "solslot.external-settlement-receipt.v1"

PURCHASE_ARTIFACT_VERSION = 3
PURCHASE_ARTIFACT_V3_VERSION = PURCHASE_ARTIFACT_VERSION
STRIPE_SETTLEMENT_EVIDENCE_VERSION = 1
STRIPE_SETTLEMENT_RECEIPT_VERSION = 1

TECHNOLOGY_FEE_BPS_ALPHA = 100
TECHNOLOGY_FEE_BPS_HARD_CAP = 1_000
MAX_TECHNOLOGY_FEE_BPS = TECHNOLOGY_FEE_BPS_HARD_CAP
STRIPE_RECEIPT_TTL_SECONDS = 48 * 60 * 60
SHARE_PPM_TOTAL = 1_000_000
_U64_MAX = (1 << 64) - 1
_PURCHASE_ID_TAG = b"SOLSLOT_PURCHASE_ID_V3"
_STRIPE_REFERENCE_TAG = b"SOLSLOT_STRIPE_REFERENCE_V1"
_STRIPE_PENDING_EVIDENCE_TAG = b"SOLSLOT_STRIPE_PENDING_EVIDENCE_V1"
_EXTERNAL_PENDING_EVIDENCE_TAG = b"SOLSLOT_EXTERNAL_PENDING_EVIDENCE_V1"
STRIPE_PAYMENT_PROVIDER_ID = bytes32(
    hashlib.sha256(b"SOLSLOT_STRIPE_PAYMENT_PROVIDER_V1").digest()
)


class StripeMethodFamily(IntEnum):
    CARD = 1
    US_BANK_ACCOUNT = 2


class StripeMode(IntEnum):
    TEST = 1
    LIVE = 2


class StripeFundingType(IntEnum):
    CREDIT = 1
    DEBIT = 2
    PREPAID = 3
    UNKNOWN = 4
    BANK_ACCOUNT = 5


class StripePaymentStatus(IntEnum):
    REQUIRES_PAYMENT_METHOD = 1
    PROCESSING = 2
    SUCCEEDED = 3
    CANCELED = 4


class StripeRefundState(IntEnum):
    NONE = 0
    PARTIAL = 1
    FULL = 2


class StripeDisputeState(IntEnum):
    NONE = 0
    OPEN = 1
    WON = 2
    LOST = 3


class PurchaseKind(IntEnum):
    DIRECT = 1
    PRESALE = 2


class PurchaseDeliveryKind(IntEnum):
    SMARTDEED = 1
    SGT = 2


def technology_fee_minor(base_minor: int, fee_bps: int) -> int:
    """Return ceil(base * bps / 10_000) using integer arithmetic."""

    _require_u64(base_minor, "base_minor", minimum=1)
    _require_u64(fee_bps, "fee_bps", minimum=0)
    if fee_bps > TECHNOLOGY_FEE_BPS_HARD_CAP:
        raise PaymentArtifactError(
            f"technology fee exceeds {TECHNOLOGY_FEE_BPS_HARD_CAP} bps"
        )
    return (base_minor * fee_bps + 9_999) // 10_000


@dataclass(frozen=True)
class PurchaseArtifactV3:
    network: str
    collection_id: bytes32
    deed_launcher_id: bytes32
    metadata_root: bytes32
    metadata_anchor_id: bytes32
    share_ppm: int
    base_amount_minor: int
    technology_fee_bps: int
    technology_fee_minor: int
    subtotal_minor: int
    protocol_treasury_puzzle_hash: bytes32
    zkpassport_root: bytes32
    rail: PaymentRail
    rail_chain_id: int
    rail_asset_id: bytes32
    rail_asset_decimals: int
    rail_amount: int
    vault_launcher_id: bytes32
    vault_p2_puzzle_hash: bytes32
    authorization_nonce: bytes32
    authorization_expires_at: int
    quote_expires_at: int
    oracle_round_hash: bytes32 = ZERO_32
    oracle_price_usd_minor_per_asset: int = 0
    source_evidence_root: bytes32 = ZERO_32
    purchase_kind: PurchaseKind = PurchaseKind.DIRECT
    presale_terms_hash: bytes32 = ZERO_32
    delivery_kind: PurchaseDeliveryKind = PurchaseDeliveryKind.SMARTDEED
    delivery_asset_id: bytes32 = ZERO_32
    delivery_amount: int = 1
    delivery_context_hash: bytes32 = ZERO_32

    def __post_init__(self) -> None:
        _require_ascii(self.network, "network", maximum=32)
        for name in (
            "collection_id",
            "deed_launcher_id",
            "metadata_root",
            "metadata_anchor_id",
            "protocol_treasury_puzzle_hash",
            "zkpassport_root",
            "rail_asset_id",
            "vault_launcher_id",
            "vault_p2_puzzle_hash",
            "authorization_nonce",
            "oracle_round_hash",
            "source_evidence_root",
            "presale_terms_hash",
            "delivery_asset_id",
            "delivery_context_hash",
        ):
            _require_bytes32(getattr(self, name), name)
        if ZERO_32 in {
            self.protocol_treasury_puzzle_hash,
            self.zkpassport_root,
            self.vault_launcher_id,
            self.vault_p2_puzzle_hash,
            self.authorization_nonce,
        }:
            raise PaymentArtifactError(
                "treasury, zkPassport, vault, and nonce commitments must be non-zero"
            )
        try:
            delivery_kind = PurchaseDeliveryKind(self.delivery_kind)
        except ValueError as exc:
            raise PaymentArtifactError(
                "delivery_kind is unsupported"
            ) from exc
        object.__setattr__(self, "delivery_kind", delivery_kind)
        if delivery_kind == PurchaseDeliveryKind.SMARTDEED:
            if ZERO_32 in {
                self.collection_id,
                self.deed_launcher_id,
                self.metadata_root,
            }:
                raise PaymentArtifactError(
                    "SmartDeed identity and metadata commitments must be non-zero"
                )
            if self.delivery_asset_id == ZERO_32:
                object.__setattr__(
                    self, "delivery_asset_id", self.deed_launcher_id
                )
            if self.delivery_context_hash == ZERO_32:
                object.__setattr__(
                    self, "delivery_context_hash", self.collection_id
                )
            _require_u64(self.share_ppm, "share_ppm", minimum=1)
            if self.share_ppm > SHARE_PPM_TOTAL:
                raise PaymentArtifactError("share_ppm exceeds collection total")
            if (
                self.delivery_asset_id != self.deed_launcher_id
                or self.delivery_amount != 1
                or self.delivery_context_hash != self.collection_id
            ):
                raise PaymentArtifactError(
                    "SmartDeed delivery must match its exact deed and collection"
                )
        else:
            if any(
                value != ZERO_32
                for value in (
                    self.collection_id,
                    self.deed_launcher_id,
                    self.metadata_root,
                    self.metadata_anchor_id,
                )
            ) or self.share_ppm != 0:
                raise PaymentArtifactError(
                    "SGT delivery cannot carry SmartDeed metadata or share fields"
                )
            if ZERO_32 in {
                self.delivery_asset_id,
                self.delivery_context_hash,
            }:
                raise PaymentArtifactError(
                    "SGT delivery requires exact asset and sale commitments"
                )
        _require_u64(self.delivery_amount, "delivery_amount", minimum=1)
        _require_u64(self.base_amount_minor, "base_amount_minor", minimum=1)
        expected_fee = technology_fee_minor(
            self.base_amount_minor, self.technology_fee_bps
        )
        if self.technology_fee_minor != expected_fee:
            raise PaymentArtifactError(
                "technology_fee_minor does not match base price and fee bps"
            )
        expected_subtotal = self.base_amount_minor + expected_fee
        _require_u64(expected_subtotal, "subtotal_minor", minimum=1)
        if self.subtotal_minor != expected_subtotal:
            raise PaymentArtifactError(
                "subtotal_minor must equal base plus technology fee"
            )
        _require_u64(self.rail_chain_id, "rail_chain_id", minimum=0)
        _require_u64(
            self.rail_asset_decimals, "rail_asset_decimals", minimum=0
        )
        if self.rail_asset_decimals > 18:
            raise PaymentArtifactError("rail_asset_decimals must be <= 18")
        _require_u64(self.rail_amount, "rail_amount", minimum=1)
        _require_u64(
            self.authorization_expires_at,
            "authorization_expires_at",
            minimum=1,
        )
        _require_u64(self.quote_expires_at, "quote_expires_at", minimum=1)
        if self.authorization_expires_at < self.quote_expires_at:
            raise PaymentArtifactError(
                "vault authorization must remain valid through quote expiry"
            )
        _require_u64(
            self.oracle_price_usd_minor_per_asset,
            "oracle_price_usd_minor_per_asset",
            minimum=0,
        )
        _validate_rail(self)
        if not isinstance(self.purchase_kind, PurchaseKind):
            raise PaymentArtifactError("purchase_kind is unsupported")
        if self.purchase_kind == PurchaseKind.DIRECT:
            if self.presale_terms_hash != ZERO_32:
                raise PaymentArtifactError(
                    "direct purchase cannot carry presale terms"
                )
        elif self.presale_terms_hash == ZERO_32:
            raise PaymentArtifactError(
                "presale purchase requires its governed terms hash"
            )
        if (
            self.purchase_kind == PurchaseKind.PRESALE
            and self.delivery_kind != PurchaseDeliveryKind.SMARTDEED
        ):
            raise PaymentArtifactError("presales can deliver only SmartDeeds")

    @property
    def usd_amount_minor(self) -> int:
        """Compatibility name for code that consumes the charged subtotal."""

        return self.subtotal_minor

    @property
    def base_usd_amount_minor(self) -> int:
        return self.base_amount_minor

    @property
    def gross_usd_amount_minor(self) -> int:
        return self.subtotal_minor

    def to_program(self) -> Program:
        return Program.to(
            [
                PURCHASE_ARTIFACT_VERSION,
                self.network.encode("ascii"),
                bytes(self.collection_id),
                bytes(self.deed_launcher_id),
                bytes(self.metadata_root),
                bytes(self.metadata_anchor_id),
                self.share_ppm,
                self.base_amount_minor,
                self.technology_fee_bps,
                self.technology_fee_minor,
                self.subtotal_minor,
                bytes(self.protocol_treasury_puzzle_hash),
                bytes(self.zkpassport_root),
                int(self.rail),
                self.rail_chain_id,
                bytes(self.rail_asset_id),
                self.rail_asset_decimals,
                self.rail_amount,
                bytes(self.vault_launcher_id),
                bytes(self.vault_p2_puzzle_hash),
                bytes(self.authorization_nonce),
                self.authorization_expires_at,
                self.quote_expires_at,
                bytes(self.oracle_round_hash),
                self.oracle_price_usd_minor_per_asset,
                bytes(self.source_evidence_root),
                int(self.purchase_kind),
                bytes(self.presale_terms_hash),
                int(self.delivery_kind),
                bytes(self.delivery_asset_id),
                self.delivery_amount,
                bytes(self.delivery_context_hash),
            ]
        )

    @property
    def artifact_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())

    @property
    def purchase_id(self) -> bytes32:
        return bytes32(
            Program.to(
                [_PURCHASE_ID_TAG, bytes(self.artifact_hash)]
            ).get_tree_hash()
        )

    def assert_live(self, now: int) -> None:
        _require_u64(now, "now", minimum=1)
        if now >= self.quote_expires_at:
            raise PaymentArtifactError("purchase quote has expired")
        if now >= self.authorization_expires_at:
            raise PaymentArtifactError("vault authorization has expired")


@dataclass(frozen=True)
class StripeSettlementEvidenceV1:
    stripe_account_id: str
    livemode: bool
    payment_intent_id: str
    event_id: str
    amount_minor: int
    currency: str
    method_family: StripeMethodFamily
    funding_type: StripeFundingType
    processing_charge_minor: int
    status: StripePaymentStatus
    refunded_minor: int
    refund_state: StripeRefundState
    dispute_state: StripeDisputeState
    observed_at: int

    def __post_init__(self) -> None:
        _require_ascii(
            self.stripe_account_id,
            "stripe_account_id",
            maximum=128,
        )
        _require_ascii(
            self.payment_intent_id,
            "payment_intent_id",
            maximum=128,
        )
        _require_ascii(self.event_id, "event_id", maximum=128)
        _require_ascii(self.currency, "currency", maximum=3)
        if self.currency.lower() != "usd":
            raise PaymentArtifactError("Stripe settlement currency must be usd")
        _require_u64(self.amount_minor, "amount_minor", minimum=1)
        _require_u64(
            self.processing_charge_minor,
            "processing_charge_minor",
            minimum=0,
        )
        _require_u64(self.refunded_minor, "refunded_minor", minimum=0)
        if self.refunded_minor > self.amount_minor:
            raise PaymentArtifactError(
                "refunded_minor cannot exceed the collected amount"
            )
        _require_u64(self.observed_at, "observed_at", minimum=1)
        if self.method_family == StripeMethodFamily.US_BANK_ACCOUNT:
            if self.funding_type != StripeFundingType.BANK_ACCOUNT:
                raise PaymentArtifactError(
                    "bank-account payment requires BANK_ACCOUNT funding"
                )
            if self.processing_charge_minor != 0:
                raise PaymentArtifactError(
                    "ACH cannot carry a customer processing surcharge"
                )
        elif self.method_family == StripeMethodFamily.CARD:
            if self.funding_type == StripeFundingType.BANK_ACCOUNT:
                raise PaymentArtifactError(
                    "card payment cannot use BANK_ACCOUNT funding"
                )
            if (
                self.funding_type
                in {
                    StripeFundingType.DEBIT,
                    StripeFundingType.PREPAID,
                    StripeFundingType.UNKNOWN,
                }
                and self.processing_charge_minor != 0
            ):
                raise PaymentArtifactError(
                    "debit, prepaid, and unknown cards cannot be surcharged"
                )
        else:
            raise PaymentArtifactError("unsupported Stripe method family")

    @property
    def payment_reference_hash(self) -> bytes32:
        return bytes32(
            Program.to(
                [_STRIPE_REFERENCE_TAG, self.payment_intent_id.encode("ascii")]
            ).get_tree_hash()
        )

    def to_program(self) -> Program:
        return Program.to(
            [
                STRIPE_SETTLEMENT_EVIDENCE_VERSION,
                self.stripe_account_id.encode("ascii"),
                1 if self.livemode else 0,
                self.payment_intent_id.encode("ascii"),
                self.event_id.encode("ascii"),
                self.amount_minor,
                self.currency.lower().encode("ascii"),
                int(self.method_family),
                int(self.funding_type),
                self.processing_charge_minor,
                int(self.status),
                self.refunded_minor,
                int(self.refund_state),
                int(self.dispute_state),
                self.observed_at,
            ]
        )

    @property
    def evidence_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())


@dataclass(frozen=True)
class StripeSettlementReceiptV1:
    artifact: PurchaseArtifactV3
    evidence: StripeSettlementEvidenceV1
    attestation: PaymentAttestationV1
    validator_roster_root: bytes32
    validator_threshold: int
    receipt_nonce: bytes32
    expires_at: int
    result_authorization_puzzle_hash: bytes32 = ZERO_32

    def __post_init__(self) -> None:
        if self.artifact.rail != PaymentRail.STRIPE:
            raise PaymentArtifactError(
                "Stripe settlement receipt requires a Stripe artifact"
            )
        _require_bytes32(self.validator_roster_root, "validator_roster_root")
        _require_bytes32(self.receipt_nonce, "receipt_nonce")
        _require_bytes32(
            self.result_authorization_puzzle_hash,
            "result_authorization_puzzle_hash",
        )
        if self.result_authorization_puzzle_hash != ZERO_32:
            raise PaymentArtifactError(
                "Stripe settlement cannot carry a Base result authorization"
            )
        if ZERO_32 in {self.validator_roster_root, self.receipt_nonce}:
            raise PaymentArtifactError(
                "validator roster and receipt nonce must be non-zero"
            )
        if self.validator_threshold != 2:
            raise PaymentArtifactError(
                "Stripe settlement requires a 2-of-3 validator threshold"
            )
        _require_u64(self.expires_at, "expires_at", minimum=1)
        if self.expires_at <= self.evidence.observed_at:
            raise PaymentArtifactError(
                "Stripe settlement receipt must expire after observation"
            )
        if (
            self.expires_at - self.evidence.observed_at
            > STRIPE_RECEIPT_TTL_SECONDS
        ):
            raise PaymentArtifactError(
                "Stripe settlement receipt exceeds the 48-hour lifetime"
            )
        if self.evidence.status != StripePaymentStatus.SUCCEEDED:
            raise PaymentArtifactError(
                "only a retrieved succeeded PaymentIntent may deliver a deed"
            )
        if self.evidence.refund_state != StripeRefundState.NONE:
            raise PaymentArtifactError(
                "refunded Stripe payments cannot deliver a deed"
            )
        if self.evidence.refunded_minor != 0:
            raise PaymentArtifactError(
                "refunded Stripe amount must be zero before delivery"
            )
        if self.evidence.dispute_state != StripeDisputeState.NONE:
            raise PaymentArtifactError(
                "disputed Stripe payments cannot deliver a deed"
            )
        expected_amount = (
            self.artifact.subtotal_minor
            + self.evidence.processing_charge_minor
        )
        if self.evidence.amount_minor != expected_amount:
            raise PaymentArtifactError(
                "Stripe amount does not match artifact subtotal and processing "
                "charge"
            )
        if (
            self.attestation.purchase_id != self.artifact.purchase_id
            or self.attestation.artifact_hash != self.artifact.artifact_hash
        ):
            raise PaymentArtifactError(
                "payment attestation does not match purchase artifact"
            )
        if (
            self.attestation.transition != PaymentTransition.SUCCEEDED
            or self.attestation.resolution != PaymentResolution.DELIVER
        ):
            raise PaymentArtifactError(
                "Stripe delivery requires a succeeded delivery attestation"
            )
        if (
            self.attestation.external_reference_hash
            != self.evidence.payment_reference_hash
        ):
            raise PaymentArtifactError(
                "payment attestation references a different PaymentIntent"
            )
        if self.attestation.evidence_hash != self.evidence.evidence_hash:
            raise PaymentArtifactError(
                "payment attestation evidence hash does not match Stripe"
            )
        if self.attestation.observed_at != self.evidence.observed_at:
            raise PaymentArtifactError(
                "payment and Stripe observation times must match"
            )

    def to_program(self) -> Program:
        return Program.to(
            [
                STRIPE_SETTLEMENT_RECEIPT_VERSION,
                bytes(self.artifact.artifact_hash),
                bytes(self.artifact.purchase_id),
                bytes(self.evidence.evidence_hash),
                bytes(self.attestation.attestation_hash),
                bytes(self.validator_roster_root),
                self.validator_threshold,
                bytes(self.receipt_nonce),
                self.evidence.observed_at,
                self.expires_at,
                bytes(self.artifact.deed_launcher_id),
                bytes(self.artifact.vault_launcher_id),
                bytes(self.artifact.vault_p2_puzzle_hash),
                bytes(self.artifact.zkpassport_root),
                bytes(self.artifact.protocol_treasury_puzzle_hash),
                self.artifact.technology_fee_minor,
                bytes(self.result_authorization_puzzle_hash),
            ]
        )

    @property
    def receipt_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())

    def assert_live(self, now: int) -> None:
        _require_u64(now, "now", minimum=1)
        if now >= self.expires_at:
            raise PaymentArtifactError("Stripe settlement receipt has expired")


@dataclass(frozen=True)
class ExternalSettlementReceiptV1:
    """Provider-neutral receipt for independently verified EVM settlement."""

    artifact: PurchaseArtifactV3
    attestation: PaymentAttestationV1
    evidence_hash: bytes32
    observed_at: int
    expires_at: int
    result_authorization_puzzle_hash: bytes32

    def __post_init__(self) -> None:
        if self.artifact.rail not in {
            PaymentRail.STRIPE,
            PaymentRail.EVM_TEST_USD,
        }:
            raise PaymentArtifactError(
                "external settlement requires Stripe or EVM USDC"
            )
        _require_bytes32(self.evidence_hash, "evidence_hash")
        _require_bytes32(
            self.result_authorization_puzzle_hash,
            "result_authorization_puzzle_hash",
        )
        if self.evidence_hash == ZERO_32:
            raise PaymentArtifactError("evidence_hash must be non-zero")
        if (
            self.attestation.purchase_id != self.artifact.purchase_id
            or self.attestation.artifact_hash != self.artifact.artifact_hash
            or self.attestation.evidence_hash != self.evidence_hash
        ):
            raise PaymentArtifactError(
                "external attestation does not match its purchase evidence"
            )
        if (
            self.attestation.transition != PaymentTransition.SUCCEEDED
            or self.attestation.resolution != PaymentResolution.DELIVER
        ):
            raise PaymentArtifactError(
                "external delivery requires a succeeded delivery attestation"
            )
        _require_u64(self.observed_at, "observed_at", minimum=1)
        _require_u64(self.expires_at, "expires_at", minimum=1)
        if self.attestation.observed_at != self.observed_at:
            raise PaymentArtifactError(
                "external receipt and attestation observation times differ"
            )
        if self.expires_at <= self.observed_at:
            raise PaymentArtifactError(
                "external receipt must expire after observation"
            )
        if self.expires_at - self.observed_at > STRIPE_RECEIPT_TTL_SECONDS:
            raise PaymentArtifactError(
                "external receipt exceeds the 48-hour lifetime"
            )
        if self.artifact.rail == PaymentRail.EVM_TEST_USD:
            if self.result_authorization_puzzle_hash == ZERO_32:
                raise PaymentArtifactError(
                    "Base settlement requires a result authorization"
                )
        elif self.result_authorization_puzzle_hash != ZERO_32:
            raise PaymentArtifactError(
                "Stripe settlement cannot carry a Base result authorization"
            )

    def to_program(self) -> Program:
        return Program.to(
            [
                STRIPE_SETTLEMENT_RECEIPT_VERSION,
                bytes(self.artifact.artifact_hash),
                bytes(self.artifact.purchase_id),
                bytes(self.attestation.attestation_hash),
                bytes(self.evidence_hash),
                self.observed_at,
                self.expires_at,
                bytes(self.result_authorization_puzzle_hash),
            ]
        )

    @property
    def receipt_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())


def build_external_settlement_receipt_v1(
    *,
    artifact: PurchaseArtifactV3,
    provider_id: bytes32,
    external_reference_hash: bytes32,
    evidence_hash: bytes32,
    observed_at: int,
    result_authorization_puzzle_hash: bytes32,
    expires_at: int | None = None,
) -> ExternalSettlementReceiptV1:
    if artifact.rail not in {
        PaymentRail.STRIPE,
        PaymentRail.EVM_TEST_USD,
    }:
        raise PaymentArtifactError(
            "external settlement receipt requires Stripe or EVM USDC"
        )
    for value, name in (
        (provider_id, "provider_id"),
        (external_reference_hash, "external_reference_hash"),
        (evidence_hash, "evidence_hash"),
    ):
        _require_bytes32(value, name)
        if value == ZERO_32:
            raise PaymentArtifactError(f"{name} must be non-zero")
    _require_bytes32(
        result_authorization_puzzle_hash,
        "result_authorization_puzzle_hash",
    )
    _require_u64(observed_at, "observed_at", minimum=1)
    pending_evidence_hash = bytes32(
        Program.to(
            [
                _EXTERNAL_PENDING_EVIDENCE_TAG,
                bytes(artifact.purchase_id),
                bytes(artifact.artifact_hash),
                bytes(provider_id),
                bytes(external_reference_hash),
            ]
        ).get_tree_hash()
    )
    pending = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=provider_id,
        external_reference_hash=external_reference_hash,
        evidence_hash=pending_evidence_hash,
        previous_attestation_hash=ZERO_32,
        observed_at=max(1, min(observed_at, artifact.quote_expires_at - 1)),
    )
    succeeded = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=provider_id,
        external_reference_hash=external_reference_hash,
        evidence_hash=evidence_hash,
        previous_attestation_hash=pending.attestation_hash,
        observed_at=observed_at,
    )
    return ExternalSettlementReceiptV1(
        artifact=artifact,
        attestation=succeeded,
        evidence_hash=evidence_hash,
        observed_at=observed_at,
        expires_at=(
            expires_at
            if expires_at is not None
            else observed_at + STRIPE_RECEIPT_TTL_SECONDS
        ),
        result_authorization_puzzle_hash=(
            result_authorization_puzzle_hash
        ),
    )


def build_stripe_pending_attestation(
    *,
    artifact: PurchaseArtifactV3,
    evidence: StripeSettlementEvidenceV1,
    observed_at: int,
) -> PaymentAttestationV1:
    """Bind the pre-confirmation Stripe intent to its exact reviewed total."""

    if artifact.rail != PaymentRail.STRIPE:
        raise PaymentArtifactError(
            "pending Stripe attestation requires a Stripe artifact"
        )
    _require_u64(observed_at, "observed_at", minimum=1)
    if observed_at > evidence.observed_at:
        raise PaymentArtifactError(
            "pending Stripe attestation cannot postdate settlement evidence"
        )
    expected_total = artifact.subtotal_minor + evidence.processing_charge_minor
    if evidence.amount_minor != expected_total:
        raise PaymentArtifactError(
            "pending Stripe attestation amount does not match reviewed total"
        )
    evidence_hash = bytes32(
        Program.to(
            [
                _STRIPE_PENDING_EVIDENCE_TAG,
                artifact.purchase_id,
                artifact.artifact_hash,
                evidence.payment_reference_hash,
                int(evidence.method_family),
                int(evidence.funding_type),
                evidence.processing_charge_minor,
                expected_total,
                observed_at,
            ]
        ).get_tree_hash()
    )
    return PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=STRIPE_PAYMENT_PROVIDER_ID,
        external_reference_hash=evidence.payment_reference_hash,
        evidence_hash=evidence_hash,
        previous_attestation_hash=ZERO_32,
        observed_at=observed_at,
    )


def build_stripe_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    base_amount_minor: int,
    technology_fee_bps: int,
    protocol_treasury_puzzle_hash: bytes32,
    zkpassport_root: bytes32,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    presale_terms_hash: bytes32 = ZERO_32,
) -> PurchaseArtifactV3:
    fee = technology_fee_minor(base_amount_minor, technology_fee_bps)
    return PurchaseArtifactV3(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        base_amount_minor=base_amount_minor,
        technology_fee_bps=technology_fee_bps,
        technology_fee_minor=fee,
        subtotal_minor=base_amount_minor + fee,
        protocol_treasury_puzzle_hash=protocol_treasury_puzzle_hash,
        zkpassport_root=zkpassport_root,
        rail=PaymentRail.STRIPE,
        rail_chain_id=0,
        rail_asset_id=ZERO_32,
        rail_asset_decimals=2,
        rail_amount=base_amount_minor + fee,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        purchase_kind=(
            PurchaseKind.PRESALE
            if presale_terms_hash != ZERO_32
            else PurchaseKind.DIRECT
        ),
        presale_terms_hash=presale_terms_hash,
    )


def build_evm_test_usd_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    base_amount_minor: int,
    technology_fee_bps: int,
    protocol_treasury_puzzle_hash: bytes32,
    zkpassport_root: bytes32,
    chain_id: int,
    token_asset_id: bytes32,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    presale_terms_hash: bytes32 = ZERO_32,
) -> PurchaseArtifactV3:
    fee = technology_fee_minor(base_amount_minor, technology_fee_bps)
    subtotal = base_amount_minor + fee
    return PurchaseArtifactV3(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        base_amount_minor=base_amount_minor,
        technology_fee_bps=technology_fee_bps,
        technology_fee_minor=fee,
        subtotal_minor=subtotal,
        protocol_treasury_puzzle_hash=protocol_treasury_puzzle_hash,
        zkpassport_root=zkpassport_root,
        rail=PaymentRail.EVM_TEST_USD,
        rail_chain_id=chain_id,
        rail_asset_id=token_asset_id,
        rail_asset_decimals=6,
        rail_amount=subtotal * 10_000,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        purchase_kind=(
            PurchaseKind.PRESALE
            if presale_terms_hash != ZERO_32
            else PurchaseKind.DIRECT
        ),
        presale_terms_hash=presale_terms_hash,
    )


def build_xch_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    base_amount_minor: int,
    technology_fee_bps: int,
    protocol_treasury_puzzle_hash: bytes32,
    zkpassport_root: bytes32,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    oracle_round: OracleRoundV1,
    presale_terms_hash: bytes32 = ZERO_32,
) -> PurchaseArtifactV3:
    return _build_chia_purchase_artifact(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        base_amount_minor=base_amount_minor,
        technology_fee_bps=technology_fee_bps,
        protocol_treasury_puzzle_hash=protocol_treasury_puzzle_hash,
        zkpassport_root=zkpassport_root,
        rail=PaymentRail.CHIA_XCH,
        rail_asset_id=ZERO_32,
        rail_asset_decimals=12,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        oracle_round=oracle_round,
        presale_terms_hash=presale_terms_hash,
    )


def build_cat_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    base_amount_minor: int,
    technology_fee_bps: int,
    protocol_treasury_puzzle_hash: bytes32,
    zkpassport_root: bytes32,
    cat_asset_id: bytes32,
    cat_asset_decimals: int,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    oracle_round: OracleRoundV1,
    presale_terms_hash: bytes32 = ZERO_32,
) -> PurchaseArtifactV3:
    return _build_chia_purchase_artifact(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        base_amount_minor=base_amount_minor,
        technology_fee_bps=technology_fee_bps,
        protocol_treasury_puzzle_hash=protocol_treasury_puzzle_hash,
        zkpassport_root=zkpassport_root,
        rail=PaymentRail.CHIA_CAT,
        rail_asset_id=cat_asset_id,
        rail_asset_decimals=cat_asset_decimals,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        oracle_round=oracle_round,
        presale_terms_hash=presale_terms_hash,
    )


def _build_chia_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    base_amount_minor: int,
    technology_fee_bps: int,
    protocol_treasury_puzzle_hash: bytes32,
    zkpassport_root: bytes32,
    rail: PaymentRail,
    rail_asset_id: bytes32,
    rail_asset_decimals: int,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    oracle_round: OracleRoundV1,
    presale_terms_hash: bytes32 = ZERO_32,
) -> PurchaseArtifactV3:
    if rail not in {PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT}:
        raise PaymentArtifactError("unsupported Chia direct-purchase rail")
    if (
        oracle_round.network != network
        or oracle_round.asset_id != rail_asset_id
        or oracle_round.asset_decimals != rail_asset_decimals
    ):
        raise PaymentArtifactError(
            "oracle round does not match the requested Chia asset"
        )
    if quote_expires_at > oracle_round.valid_until:
        raise PaymentArtifactError(
            "purchase quote cannot outlive its oracle round"
        )
    fee = technology_fee_minor(base_amount_minor, technology_fee_bps)
    subtotal = base_amount_minor + fee
    rail_amount = (
        subtotal * (10**rail_asset_decimals)
        + oracle_round.price_usd_minor_per_asset
        - 1
    ) // oracle_round.price_usd_minor_per_asset
    return PurchaseArtifactV3(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        base_amount_minor=base_amount_minor,
        technology_fee_bps=technology_fee_bps,
        technology_fee_minor=fee,
        subtotal_minor=subtotal,
        protocol_treasury_puzzle_hash=protocol_treasury_puzzle_hash,
        zkpassport_root=zkpassport_root,
        rail=rail,
        rail_chain_id=0,
        rail_asset_id=rail_asset_id,
        rail_asset_decimals=rail_asset_decimals,
        rail_amount=rail_amount,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        oracle_round_hash=oracle_round.round_hash,
        oracle_price_usd_minor_per_asset=(
            oracle_round.price_usd_minor_per_asset
        ),
        source_evidence_root=oracle_round.source_evidence_root,
        purchase_kind=(
            PurchaseKind.PRESALE
            if presale_terms_hash != ZERO_32
            else PurchaseKind.DIRECT
        ),
        presale_terms_hash=presale_terms_hash,
    )


def build_stripe_purchase_artifact_v3(
    *, base_usd_amount_minor: int, **kwargs: Any
) -> PurchaseArtifactV3:
    return build_stripe_purchase_artifact(
        base_amount_minor=base_usd_amount_minor,
        **kwargs,
    )


def build_evm_test_usd_purchase_artifact_v3(
    *, base_usd_amount_minor: int, **kwargs: Any
) -> PurchaseArtifactV3:
    return build_evm_test_usd_purchase_artifact(
        base_amount_minor=base_usd_amount_minor,
        **kwargs,
    )


def build_xch_purchase_artifact_v3(
    *, base_usd_amount_minor: int, **kwargs: Any
) -> PurchaseArtifactV3:
    return build_xch_purchase_artifact(
        base_amount_minor=base_usd_amount_minor,
        **kwargs,
    )


def build_cat_purchase_artifact_v3(
    *,
    base_usd_amount_minor: int,
    cat_decimals: int,
    **kwargs: Any,
) -> PurchaseArtifactV3:
    return build_cat_purchase_artifact(
        base_amount_minor=base_usd_amount_minor,
        cat_asset_decimals=cat_decimals,
        **kwargs,
    )


def build_sgt_purchase_artifact_v3(
    *,
    network: str,
    sgt_asset_id: bytes32,
    sale_id: bytes32,
    sgt_amount: int,
    base_usd_amount_minor: int,
    technology_fee_bps: int,
    protocol_treasury_puzzle_hash: bytes32,
    zkpassport_root: bytes32,
    rail: PaymentRail,
    rail_chain_id: int,
    rail_asset_id: bytes32,
    rail_asset_decimals: int,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
) -> PurchaseArtifactV3:
    if rail not in {PaymentRail.STRIPE, PaymentRail.EVM_TEST_USD}:
        raise PaymentArtifactError(
            "SGT external artifact requires Stripe or Base USDC"
        )
    fee = technology_fee_minor(
        base_usd_amount_minor, technology_fee_bps
    )
    subtotal = base_usd_amount_minor + fee
    rail_amount = subtotal if rail == PaymentRail.STRIPE else subtotal * 10_000
    return PurchaseArtifactV3(
        network=network,
        collection_id=ZERO_32,
        deed_launcher_id=ZERO_32,
        metadata_root=ZERO_32,
        metadata_anchor_id=ZERO_32,
        share_ppm=0,
        base_amount_minor=base_usd_amount_minor,
        technology_fee_bps=technology_fee_bps,
        technology_fee_minor=fee,
        subtotal_minor=subtotal,
        protocol_treasury_puzzle_hash=protocol_treasury_puzzle_hash,
        zkpassport_root=zkpassport_root,
        rail=rail,
        rail_chain_id=rail_chain_id,
        rail_asset_id=rail_asset_id,
        rail_asset_decimals=rail_asset_decimals,
        rail_amount=rail_amount,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        delivery_kind=PurchaseDeliveryKind.SGT,
        delivery_asset_id=sgt_asset_id,
        delivery_amount=sgt_amount,
        delivery_context_hash=sale_id,
    )


def purchase_artifact_to_json(
    artifact: PurchaseArtifactV3,
) -> dict[str, Any]:
    value = {
        "schema": PURCHASE_ARTIFACT_SCHEMA,
        "network": artifact.network,
        "collectionId": _hex32(artifact.collection_id),
        "deedLauncherId": _hex32(artifact.deed_launcher_id),
        "metadataRoot": _hex32(artifact.metadata_root),
        "metadataAnchorId": _hex32(artifact.metadata_anchor_id),
        "sharePpm": str(artifact.share_ppm),
        "baseAmountMinor": str(artifact.base_amount_minor),
        "technologyFeeBps": str(artifact.technology_fee_bps),
        "technologyFeeMinor": str(artifact.technology_fee_minor),
        "subtotalMinor": str(artifact.subtotal_minor),
        "protocolTreasuryPuzzleHash": _hex32(
            artifact.protocol_treasury_puzzle_hash
        ),
        "zkPassportRoot": _hex32(artifact.zkpassport_root),
        "rail": int(artifact.rail),
        "railChainId": str(artifact.rail_chain_id),
        "railAssetId": _hex32(artifact.rail_asset_id),
        "railAssetDecimals": str(artifact.rail_asset_decimals),
        "railAmount": str(artifact.rail_amount),
        "vaultLauncherId": _hex32(artifact.vault_launcher_id),
        "vaultP2PuzzleHash": _hex32(artifact.vault_p2_puzzle_hash),
        "authorizationNonce": _hex32(artifact.authorization_nonce),
        "authorizationExpiresAt": str(artifact.authorization_expires_at),
        "quoteExpiresAt": str(artifact.quote_expires_at),
        "oracleRoundHash": _hex32(artifact.oracle_round_hash),
        "oraclePriceUsdMinorPerAsset": str(
            artifact.oracle_price_usd_minor_per_asset
        ),
        "sourceEvidenceRoot": _hex32(artifact.source_evidence_root),
        "purchaseKind": int(artifact.purchase_kind),
        "presaleTermsHash": _hex32(artifact.presale_terms_hash),
        "deliveryKind": int(artifact.delivery_kind),
        "deliveryAssetId": _hex32(artifact.delivery_asset_id),
        "deliveryAmount": str(artifact.delivery_amount),
        "deliveryContextHash": _hex32(artifact.delivery_context_hash),
    }
    value.update(
        {
            "programHex": "0x" + bytes(artifact.to_program()).hex(),
            "artifactHash": _hex32(artifact.artifact_hash),
            "purchaseId": _hex32(artifact.purchase_id),
        }
    )
    return value


def purchase_artifact_from_json(
    value: Mapping[str, Any],
) -> PurchaseArtifactV3:
    expected = set(purchase_artifact_to_json(_json_fixture_artifact()))
    _require_exact_keys(value, expected, "purchase artifact")
    if value["schema"] != PURCHASE_ARTIFACT_SCHEMA:
        raise PaymentArtifactError("purchase artifact schema is unsupported")
    try:
        rail = PaymentRail(_json_int(value, "rail"))
    except ValueError as exc:
        raise PaymentArtifactError("purchase artifact rail is unsupported") from exc
    try:
        purchase_kind = PurchaseKind(_json_int(value, "purchaseKind"))
    except ValueError as exc:
        raise PaymentArtifactError(
            "purchase artifact kind is unsupported"
        ) from exc
    try:
        delivery_kind = PurchaseDeliveryKind(
            _json_int(value, "deliveryKind")
        )
    except ValueError as exc:
        raise PaymentArtifactError(
            "purchase artifact delivery kind is unsupported"
        ) from exc
    artifact = PurchaseArtifactV3(
        network=_json_string(value, "network"),
        collection_id=_json_bytes32(value, "collectionId"),
        deed_launcher_id=_json_bytes32(value, "deedLauncherId"),
        metadata_root=_json_bytes32(value, "metadataRoot"),
        metadata_anchor_id=_json_bytes32(value, "metadataAnchorId"),
        share_ppm=_json_decimal(value, "sharePpm"),
        base_amount_minor=_json_decimal(value, "baseAmountMinor"),
        technology_fee_bps=_json_decimal(value, "technologyFeeBps"),
        technology_fee_minor=_json_decimal(value, "technologyFeeMinor"),
        subtotal_minor=_json_decimal(value, "subtotalMinor"),
        protocol_treasury_puzzle_hash=_json_bytes32(
            value, "protocolTreasuryPuzzleHash"
        ),
        zkpassport_root=_json_bytes32(value, "zkPassportRoot"),
        rail=rail,
        rail_chain_id=_json_decimal(value, "railChainId"),
        rail_asset_id=_json_bytes32(value, "railAssetId"),
        rail_asset_decimals=_json_decimal(value, "railAssetDecimals"),
        rail_amount=_json_decimal(value, "railAmount"),
        vault_launcher_id=_json_bytes32(value, "vaultLauncherId"),
        vault_p2_puzzle_hash=_json_bytes32(value, "vaultP2PuzzleHash"),
        authorization_nonce=_json_bytes32(value, "authorizationNonce"),
        authorization_expires_at=_json_decimal(
            value, "authorizationExpiresAt"
        ),
        quote_expires_at=_json_decimal(value, "quoteExpiresAt"),
        oracle_round_hash=_json_bytes32(value, "oracleRoundHash"),
        oracle_price_usd_minor_per_asset=_json_decimal(
            value, "oraclePriceUsdMinorPerAsset"
        ),
        source_evidence_root=_json_bytes32(value, "sourceEvidenceRoot"),
        purchase_kind=purchase_kind,
        presale_terms_hash=_json_bytes32(value, "presaleTermsHash"),
        delivery_kind=delivery_kind,
        delivery_asset_id=_json_bytes32(value, "deliveryAssetId"),
        delivery_amount=_json_decimal(value, "deliveryAmount"),
        delivery_context_hash=_json_bytes32(
            value, "deliveryContextHash"
        ),
    )
    canonical = purchase_artifact_to_json(artifact)
    for field in ("programHex", "artifactHash", "purchaseId"):
        if value[field] != canonical[field]:
            raise PaymentArtifactError(
                f"purchase artifact {field} does not match canonical CLVM"
            )
    return artifact


def stripe_evidence_to_json(
    evidence: StripeSettlementEvidenceV1,
) -> dict[str, Any]:
    return {
        "schema": STRIPE_SETTLEMENT_EVIDENCE_SCHEMA,
        "stripeAccountId": evidence.stripe_account_id,
        "livemode": evidence.livemode,
        "paymentIntentId": evidence.payment_intent_id,
        "eventId": evidence.event_id,
        "amountMinor": str(evidence.amount_minor),
        "currency": evidence.currency.lower(),
        "methodFamily": int(evidence.method_family),
        "fundingType": int(evidence.funding_type),
        "processingChargeMinor": str(evidence.processing_charge_minor),
        "status": int(evidence.status),
        "refundedMinor": str(evidence.refunded_minor),
        "refundState": int(evidence.refund_state),
        "disputeState": int(evidence.dispute_state),
        "observedAt": str(evidence.observed_at),
        "programHex": "0x" + bytes(evidence.to_program()).hex(),
        "evidenceHash": _hex32(evidence.evidence_hash),
        "paymentReferenceHash": _hex32(evidence.payment_reference_hash),
    }


def stripe_evidence_from_json(
    value: Mapping[str, Any],
) -> StripeSettlementEvidenceV1:
    expected = set(
        stripe_evidence_to_json(
            StripeSettlementEvidenceV1(
                stripe_account_id="acct_test",
                livemode=False,
                payment_intent_id="pi_test",
                event_id="evt_test",
                amount_minor=1,
                currency="usd",
                method_family=StripeMethodFamily.CARD,
                funding_type=StripeFundingType.CREDIT,
                processing_charge_minor=0,
                status=StripePaymentStatus.SUCCEEDED,
                refunded_minor=0,
                refund_state=StripeRefundState.NONE,
                dispute_state=StripeDisputeState.NONE,
                observed_at=1,
            )
        )
    )
    _require_exact_keys(value, expected, "Stripe settlement evidence")
    if value["schema"] != STRIPE_SETTLEMENT_EVIDENCE_SCHEMA:
        raise PaymentArtifactError("Stripe settlement evidence schema is unsupported")
    try:
        evidence = StripeSettlementEvidenceV1(
            stripe_account_id=_json_string(value, "stripeAccountId"),
            livemode=_json_bool(value, "livemode"),
            payment_intent_id=_json_string(value, "paymentIntentId"),
            event_id=_json_string(value, "eventId"),
            amount_minor=_json_decimal(value, "amountMinor"),
            currency=_json_string(value, "currency"),
            method_family=StripeMethodFamily(_json_int(value, "methodFamily")),
            funding_type=StripeFundingType(_json_int(value, "fundingType")),
            processing_charge_minor=_json_decimal(
                value, "processingChargeMinor"
            ),
            status=StripePaymentStatus(_json_int(value, "status")),
            refunded_minor=_json_decimal(value, "refundedMinor"),
            refund_state=StripeRefundState(_json_int(value, "refundState")),
            dispute_state=StripeDisputeState(
                _json_int(value, "disputeState")
            ),
            observed_at=_json_decimal(value, "observedAt"),
        )
    except ValueError as exc:
        raise PaymentArtifactError(
            "Stripe settlement evidence contains an unsupported enum"
        ) from exc
    canonical = stripe_evidence_to_json(evidence)
    for field in ("programHex", "evidenceHash", "paymentReferenceHash"):
        if value[field] != canonical[field]:
            raise PaymentArtifactError(
                f"Stripe settlement evidence {field} does not match canonical CLVM"
            )
    return evidence


def payment_attestation_to_json(
    attestation: PaymentAttestationV1,
) -> dict[str, Any]:
    return {
        "purchaseId": _hex32(attestation.purchase_id),
        "artifactHash": _hex32(attestation.artifact_hash),
        "transition": int(attestation.transition),
        "resolution": int(attestation.resolution),
        "providerId": _hex32(attestation.provider_id),
        "externalReferenceHash": _hex32(
            attestation.external_reference_hash
        ),
        "evidenceHash": _hex32(attestation.evidence_hash),
        "previousAttestationHash": _hex32(
            attestation.previous_attestation_hash
        ),
        "observedAt": str(attestation.observed_at),
        "reasonHash": _hex32(attestation.reason_hash),
        "programHex": "0x" + bytes(attestation.to_program()).hex(),
        "attestationHash": _hex32(attestation.attestation_hash),
    }


def payment_attestation_from_json(
    value: Mapping[str, Any],
) -> PaymentAttestationV1:
    one = bytes32(b"\x01" * 32)
    fixture = PaymentAttestationV1(
        purchase_id=one,
        artifact_hash=one,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=one,
        external_reference_hash=one,
        evidence_hash=one,
        previous_attestation_hash=ZERO_32,
        observed_at=1,
    )
    _require_exact_keys(
        value,
        set(payment_attestation_to_json(fixture)),
        "payment attestation",
    )
    try:
        attestation = PaymentAttestationV1(
            purchase_id=_json_bytes32(value, "purchaseId"),
            artifact_hash=_json_bytes32(value, "artifactHash"),
            transition=PaymentTransition(_json_int(value, "transition")),
            resolution=PaymentResolution(_json_int(value, "resolution")),
            provider_id=_json_bytes32(value, "providerId"),
            external_reference_hash=_json_bytes32(
                value, "externalReferenceHash"
            ),
            evidence_hash=_json_bytes32(value, "evidenceHash"),
            previous_attestation_hash=_json_bytes32(
                value, "previousAttestationHash"
            ),
            observed_at=_json_decimal(value, "observedAt"),
            reason_hash=_json_bytes32(value, "reasonHash"),
        )
    except ValueError as exc:
        raise PaymentArtifactError(
            "payment attestation contains an unsupported enum"
        ) from exc
    canonical = payment_attestation_to_json(attestation)
    for field in ("programHex", "attestationHash"):
        if value[field] != canonical[field]:
            raise PaymentArtifactError(
                f"payment attestation {field} does not match canonical CLVM"
            )
    return attestation


def stripe_receipt_to_json(
    receipt: StripeSettlementReceiptV1,
) -> dict[str, Any]:
    return {
        "schema": STRIPE_SETTLEMENT_RECEIPT_SCHEMA,
        "artifact": purchase_artifact_to_json(receipt.artifact),
        "evidence": stripe_evidence_to_json(receipt.evidence),
        "attestation": payment_attestation_to_json(receipt.attestation),
        "validatorRosterRoot": _hex32(receipt.validator_roster_root),
        "validatorThreshold": receipt.validator_threshold,
        "receiptNonce": _hex32(receipt.receipt_nonce),
        "expiresAt": str(receipt.expires_at),
        "resultAuthorizationPuzzleHash": _hex32(
            receipt.result_authorization_puzzle_hash
        ),
        "programHex": "0x" + bytes(receipt.to_program()).hex(),
        "receiptHash": _hex32(receipt.receipt_hash),
    }


def stripe_receipt_from_json(
    value: Mapping[str, Any],
) -> StripeSettlementReceiptV1:
    expected = {
        "schema",
        "artifact",
        "evidence",
        "attestation",
        "validatorRosterRoot",
        "validatorThreshold",
        "receiptNonce",
        "expiresAt",
        "resultAuthorizationPuzzleHash",
        "programHex",
        "receiptHash",
    }
    _require_exact_keys(value, expected, "Stripe settlement receipt")
    if value["schema"] != STRIPE_SETTLEMENT_RECEIPT_SCHEMA:
        raise PaymentArtifactError("Stripe settlement receipt schema is unsupported")
    artifact_value = _json_mapping(value, "artifact")
    evidence_value = _json_mapping(value, "evidence")
    attestation_value = _json_mapping(value, "attestation")
    receipt = StripeSettlementReceiptV1(
        artifact=purchase_artifact_from_json(artifact_value),
        evidence=stripe_evidence_from_json(evidence_value),
        attestation=payment_attestation_from_json(attestation_value),
        validator_roster_root=_json_bytes32(value, "validatorRosterRoot"),
        validator_threshold=_json_int(value, "validatorThreshold"),
        receipt_nonce=_json_bytes32(value, "receiptNonce"),
        expires_at=_json_decimal(value, "expiresAt"),
        result_authorization_puzzle_hash=_json_bytes32(
            value, "resultAuthorizationPuzzleHash"
        ),
    )
    canonical = stripe_receipt_to_json(receipt)
    for field in ("programHex", "receiptHash"):
        if value[field] != canonical[field]:
            raise PaymentArtifactError(
                f"Stripe settlement receipt {field} does not match canonical CLVM"
            )
    return receipt


def _validate_rail(artifact: PurchaseArtifactV3) -> None:
    if artifact.rail == PaymentRail.STRIPE:
        if artifact.rail_chain_id != 0 or artifact.rail_asset_id != ZERO_32:
            raise PaymentArtifactError(
                "Stripe artifacts cannot declare a chain or asset"
            )
        if artifact.rail_asset_decimals != 2:
            raise PaymentArtifactError(
                "Stripe artifacts use two-decimal USD minor units"
            )
        if artifact.rail_amount != artifact.subtotal_minor:
            raise PaymentArtifactError(
                "Stripe rail amount must equal the artifact subtotal"
            )
        _require_no_oracle(artifact)
        return
    if artifact.rail == PaymentRail.EVM_TEST_USD:
        if (
            artifact.rail_chain_id == 0
            or artifact.rail_asset_id == ZERO_32
            or artifact.rail_asset_decimals != 6
        ):
            raise PaymentArtifactError(
                "EVM USD requires a chain, token, and six decimals"
            )
        if artifact.rail_amount != artifact.subtotal_minor * 10_000:
            raise PaymentArtifactError(
                "EVM USD amount must equal six-decimal subtotal"
            )
        _require_no_oracle(artifact)
        return
    if artifact.rail not in {PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT}:
        raise PaymentArtifactError(f"unsupported payment rail: {artifact.rail}")
    if artifact.rail == PaymentRail.CHIA_XCH:
        if (
            artifact.rail_chain_id != 0
            or artifact.rail_asset_id != ZERO_32
            or artifact.rail_asset_decimals != 12
        ):
            raise PaymentArtifactError("native XCH rail fields are invalid")
    elif artifact.rail_chain_id != 0 or artifact.rail_asset_id == ZERO_32:
        raise PaymentArtifactError("Chia CAT rail fields are invalid")
    if (
        artifact.oracle_round_hash == ZERO_32
        or artifact.source_evidence_root == ZERO_32
        or artifact.oracle_price_usd_minor_per_asset <= 0
    ):
        raise PaymentArtifactError("Chia rails require complete oracle evidence")
    expected = (
        artifact.subtotal_minor * (10**artifact.rail_asset_decimals)
        + artifact.oracle_price_usd_minor_per_asset
        - 1
    ) // artifact.oracle_price_usd_minor_per_asset
    if artifact.rail_amount != expected:
        raise PaymentArtifactError(
            "Chia rail amount does not match the governed quote"
        )


def _require_no_oracle(artifact: PurchaseArtifactV3) -> None:
    if (
        artifact.oracle_round_hash != ZERO_32
        or artifact.oracle_price_usd_minor_per_asset != 0
        or artifact.source_evidence_root != ZERO_32
    ):
        raise PaymentArtifactError(
            f"{artifact.rail.name} artifacts cannot carry oracle data"
        )


def _json_fixture_artifact() -> PurchaseArtifactV3:
    one = bytes32(b"\x01" * 32)
    return build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=one,
        deed_launcher_id=one,
        metadata_root=one,
        metadata_anchor_id=ZERO_32,
        share_ppm=1,
        base_amount_minor=1,
        technology_fee_bps=0,
        protocol_treasury_puzzle_hash=one,
        zkpassport_root=one,
        vault_launcher_id=one,
        vault_p2_puzzle_hash=one,
        authorization_nonce=one,
        authorization_expires_at=2,
        quote_expires_at=1,
    )


def _require_ascii(value: str, name: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value:
        raise PaymentArtifactError(f"{name} must be a non-empty string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PaymentArtifactError(f"{name} must contain ASCII only") from exc
    if len(encoded) > maximum:
        raise PaymentArtifactError(f"{name} exceeds {maximum} bytes")


def _require_bytes32(value: bytes32, name: str) -> None:
    if not isinstance(value, bytes32) or len(value) != 32:
        raise PaymentArtifactError(f"{name} must be bytes32")


def _require_u64(
    value: int,
    name: str,
    *,
    minimum: int,
    maximum: int = _U64_MAX,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PaymentArtifactError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise PaymentArtifactError(
            f"{name} must be in {minimum}..{maximum}, got {value}"
        )


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    if not isinstance(value, Mapping):
        raise PaymentArtifactError(f"{label} must be an object")
    if set(value) != expected:
        raise PaymentArtifactError(f"{label} fields are invalid")


def _json_string(value: Mapping[str, Any], field: str) -> str:
    result = value[field]
    if not isinstance(result, str):
        raise PaymentArtifactError(f"{field} must be a string")
    return result


def _json_bool(value: Mapping[str, Any], field: str) -> bool:
    result = value.get(field)
    if not isinstance(result, bool):
        raise PaymentArtifactError(f"{field} must be a boolean")
    return result


def _json_int(value: Mapping[str, Any], field: str) -> int:
    result = value[field]
    if isinstance(result, bool) or not isinstance(result, int):
        raise PaymentArtifactError(f"{field} must be an integer")
    return result


def _json_mapping(
    value: Mapping[str, Any],
    field: str,
) -> Mapping[str, Any]:
    result = value.get(field)
    if not isinstance(result, Mapping):
        raise PaymentArtifactError(f"{field} must be an object")
    return result


def _json_decimal(value: Mapping[str, Any], field: str) -> int:
    result = _json_string(value, field)
    if not result or (len(result) > 1 and result[0] == "0"):
        raise PaymentArtifactError(f"{field} must be a canonical decimal string")
    if not result.isascii() or not result.isdecimal():
        raise PaymentArtifactError(f"{field} must be a decimal string")
    parsed = int(result)
    _require_u64(parsed, field, minimum=0)
    return parsed


def _json_bytes32(value: Mapping[str, Any], field: str) -> bytes32:
    raw = _json_string(value, field)
    if not raw.startswith("0x") or len(raw) != 66:
        raise PaymentArtifactError(f"{field} must be 0x-prefixed bytes32")
    try:
        return bytes32.from_hexstr(raw)
    except ValueError as exc:
        raise PaymentArtifactError(f"{field} must be valid bytes32") from exc


def build_stripe_settlement_receipt_v1(
    *,
    artifact: PurchaseArtifactV3,
    evidence: StripeSettlementEvidenceV1,
    validator_pubkeys: tuple[bytes, bytes, bytes],
    receipt_nonce: bytes32 | None = None,
    expires_at: int | None = None,
) -> StripeSettlementReceiptV1:
    if len(validator_pubkeys) != 3 or len(set(validator_pubkeys)) != 3:
        raise PaymentArtifactError(
            "Stripe settlement requires three distinct validator public keys"
        )
    if any(len(value) != 48 for value in validator_pubkeys):
        raise PaymentArtifactError(
            "Stripe validator public keys must be 48 bytes"
        )
    pending = build_stripe_pending_attestation(
        artifact=artifact,
        evidence=evidence,
        observed_at=max(1, min(evidence.observed_at, artifact.quote_expires_at - 1)),
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
    roster_root = bytes32(
        Program.to(list(validator_pubkeys)).get_tree_hash()
    )
    resolved_nonce = receipt_nonce or bytes32(
        Program.to(
            [
                b"SOLSLOT_STRIPE_RECEIPT_NONCE_V1",
                bytes(artifact.purchase_id),
                bytes(evidence.evidence_hash),
                bytes(roster_root),
            ]
        ).get_tree_hash()
    )
    resolved_expiry = expires_at or (
        evidence.observed_at + STRIPE_RECEIPT_TTL_SECONDS
    )
    return StripeSettlementReceiptV1(
        artifact=artifact,
        evidence=evidence,
        attestation=succeeded,
        validator_roster_root=roster_root,
        validator_threshold=2,
        receipt_nonce=resolved_nonce,
        expires_at=resolved_expiry,
    )


purchase_artifact_v3_to_json = purchase_artifact_to_json
purchase_artifact_v3_from_json = purchase_artifact_from_json
stripe_settlement_evidence_to_json = stripe_evidence_to_json
stripe_settlement_evidence_from_json = stripe_evidence_from_json


__all__ = [
    "EXTERNAL_SETTLEMENT_RECEIPT_SCHEMA",
    "MAX_TECHNOLOGY_FEE_BPS",
    "PURCHASE_ARTIFACT_SCHEMA",
    "PURCHASE_ARTIFACT_V3_SCHEMA",
    "STRIPE_RECEIPT_TTL_SECONDS",
    "STRIPE_PAYMENT_PROVIDER_ID",
    "STRIPE_SETTLEMENT_EVIDENCE_SCHEMA",
    "STRIPE_SETTLEMENT_RECEIPT_SCHEMA",
    "TECHNOLOGY_FEE_BPS_ALPHA",
    "TECHNOLOGY_FEE_BPS_HARD_CAP",
    "PurchaseArtifactV3",
    "PurchaseDeliveryKind",
    "PurchaseKind",
    "StripeDisputeState",
    "StripeFundingType",
    "StripeMethodFamily",
    "StripeMode",
    "StripePaymentStatus",
    "StripeRefundState",
    "StripeSettlementEvidenceV1",
    "StripeSettlementReceiptV1",
    "ExternalSettlementReceiptV1",
    "build_cat_purchase_artifact",
    "build_cat_purchase_artifact_v3",
    "build_evm_test_usd_purchase_artifact",
    "build_evm_test_usd_purchase_artifact_v3",
    "build_external_settlement_receipt_v1",
    "build_sgt_purchase_artifact_v3",
    "build_stripe_purchase_artifact",
    "build_stripe_purchase_artifact_v3",
    "build_stripe_pending_attestation",
    "build_stripe_settlement_receipt_v1",
    "build_xch_purchase_artifact",
    "build_xch_purchase_artifact_v3",
    "payment_attestation_from_json",
    "payment_attestation_to_json",
    "purchase_artifact_from_json",
    "purchase_artifact_v3_from_json",
    "purchase_artifact_to_json",
    "purchase_artifact_v3_to_json",
    "stripe_evidence_from_json",
    "stripe_evidence_to_json",
    "stripe_settlement_evidence_from_json",
    "stripe_settlement_evidence_to_json",
    "stripe_receipt_from_json",
    "stripe_receipt_to_json",
    "technology_fee_minor",
]
