from __future__ import annotations

from dataclasses import replace

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentAttestationV1,
    PaymentRail,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.payment_artifacts_v3 import (
    STRIPE_RECEIPT_TTL_SECONDS,
    PurchaseArtifactV3,
    PurchaseKind,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    StripeSettlementReceiptV1,
    build_stripe_purchase_artifact,
    payment_attestation_from_json,
    payment_attestation_to_json,
    purchase_artifact_from_json,
    purchase_artifact_to_json,
    stripe_evidence_from_json,
    stripe_evidence_to_json,
    stripe_receipt_from_json,
    stripe_receipt_to_json,
    technology_fee_minor,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def artifact(*, fee_bps: int = 100) -> PurchaseArtifactV3:
    return build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=b32(1),
        deed_launcher_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        share_ppm=40_000,
        base_amount_minor=22_900,
        technology_fee_bps=fee_bps,
        protocol_treasury_puzzle_hash=b32(5),
        zkpassport_root=b32(6),
        vault_launcher_id=b32(7),
        vault_p2_puzzle_hash=b32(8),
        authorization_nonce=b32(9),
        authorization_expires_at=1_800_000_000,
        quote_expires_at=1_700_000_600,
    )


def evidence(
    *,
    method: StripeMethodFamily = StripeMethodFamily.CARD,
    funding: StripeFundingType = StripeFundingType.DEBIT,
    processing_charge: int = 0,
    status: StripePaymentStatus = StripePaymentStatus.SUCCEEDED,
) -> StripeSettlementEvidenceV1:
    item = artifact()
    return StripeSettlementEvidenceV1(
        stripe_account_id="acct_rc24",
        livemode=False,
        payment_intent_id="pi_rc24",
        event_id="evt_rc24",
        amount_minor=item.subtotal_minor + processing_charge,
        currency="usd",
        method_family=method,
        funding_type=funding,
        processing_charge_minor=processing_charge,
        status=status,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=1_700_000_100,
    )


def receipt(
    *,
    artifact_: PurchaseArtifactV3 | None = None,
    evidence_: StripeSettlementEvidenceV1 | None = None,
) -> StripeSettlementReceiptV1:
    item = artifact_ or artifact()
    stripe = evidence_ or evidence()
    pending = PaymentAttestationV1(
        purchase_id=item.purchase_id,
        artifact_hash=item.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=b32(10),
        external_reference_hash=stripe.payment_reference_hash,
        evidence_hash=b32(11),
        previous_attestation_hash=bytes32.zeros,
        observed_at=stripe.observed_at - 1,
    )
    succeeded = PaymentAttestationV1(
        purchase_id=item.purchase_id,
        artifact_hash=item.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=b32(10),
        external_reference_hash=stripe.payment_reference_hash,
        evidence_hash=stripe.evidence_hash,
        previous_attestation_hash=pending.attestation_hash,
        observed_at=stripe.observed_at,
    )
    return StripeSettlementReceiptV1(
        artifact=item,
        evidence=stripe,
        attestation=succeeded,
        validator_roster_root=b32(12),
        validator_threshold=2,
        receipt_nonce=b32(13),
        expires_at=stripe.observed_at + STRIPE_RECEIPT_TTL_SECONDS,
    )


def test_one_percent_fee_uses_ceiling_and_hard_cap() -> None:
    assert technology_fee_minor(22_900, 100) == 229
    assert technology_fee_minor(1, 1) == 1
    with pytest.raises(PaymentArtifactError, match="exceeds"):
        technology_fee_minor(100, 1_001)


def test_artifact_commits_fee_treasury_eligibility_and_vault() -> None:
    item = artifact()
    assert item.artifact_hash.hex() == (
        "2889da8d662bd0dcc27e7197e3a3816d"
        "bcab7643f642595a5ba27c6054a2c072"
    )
    assert item.purchase_id.hex() == (
        "4075085748452a03a60cd0f37e8eff2a"
        "aee9496e15a3a505b4b59acfb234a6af"
    )
    assert item.technology_fee_minor == 229
    assert item.subtotal_minor == 23_129
    fields = item.to_program().as_python()
    assert int.from_bytes(fields[8], signed=True) == 100
    assert int.from_bytes(fields[9], signed=True) == 229
    assert int.from_bytes(fields[10], signed=True) == 23_129
    assert bytes(item.protocol_treasury_puzzle_hash) in fields
    assert bytes(item.zkpassport_root) in fields


def test_artifact_json_round_trip_rederives_program_and_hashes() -> None:
    item = artifact()
    payload = purchase_artifact_to_json(item)
    assert purchase_artifact_from_json(payload) == item
    payload["baseAmountMinor"] = "22901"
    with pytest.raises(PaymentArtifactError):
        purchase_artifact_from_json(payload)


def test_presale_artifact_commits_governed_terms_and_cannot_be_relabelled() -> None:
    direct = artifact()
    presale = build_stripe_purchase_artifact(
        network=direct.network,
        collection_id=direct.collection_id,
        deed_launcher_id=direct.deed_launcher_id,
        metadata_root=direct.metadata_root,
        metadata_anchor_id=direct.metadata_anchor_id,
        share_ppm=direct.share_ppm,
        base_amount_minor=direct.base_amount_minor,
        technology_fee_bps=direct.technology_fee_bps,
        protocol_treasury_puzzle_hash=direct.protocol_treasury_puzzle_hash,
        zkpassport_root=direct.zkpassport_root,
        vault_launcher_id=direct.vault_launcher_id,
        vault_p2_puzzle_hash=direct.vault_p2_puzzle_hash,
        authorization_nonce=direct.authorization_nonce,
        authorization_expires_at=direct.authorization_expires_at,
        quote_expires_at=direct.quote_expires_at,
        presale_terms_hash=b32(15),
    )

    assert direct.purchase_kind == PurchaseKind.DIRECT
    assert presale.purchase_kind == PurchaseKind.PRESALE
    assert presale.presale_terms_hash == b32(15)
    assert presale.artifact_hash != direct.artifact_hash
    assert presale.purchase_id != direct.purchase_id
    assert purchase_artifact_from_json(purchase_artifact_to_json(presale)) == presale

    with pytest.raises(PaymentArtifactError, match="direct purchase"):
        replace(presale, purchase_kind=PurchaseKind.DIRECT)
    with pytest.raises(PaymentArtifactError, match="requires its governed terms"):
        replace(presale, presale_terms_hash=bytes32.zeros)


def test_stripe_receipt_json_round_trip_rederives_every_commitment() -> None:
    item = receipt()
    assert stripe_evidence_from_json(
        stripe_evidence_to_json(item.evidence)
    ) == item.evidence
    assert payment_attestation_from_json(
        payment_attestation_to_json(item.attestation)
    ) == item.attestation
    payload = stripe_receipt_to_json(item)
    assert stripe_receipt_from_json(payload) == item

    payload["attestation"]["observedAt"] = str(
        item.attestation.observed_at + 1
    )
    with pytest.raises(PaymentArtifactError):
        stripe_receipt_from_json(payload)


def test_ach_and_non_credit_cards_cannot_be_surcharged() -> None:
    with pytest.raises(PaymentArtifactError, match="ACH"):
        evidence(
            method=StripeMethodFamily.US_BANK_ACCOUNT,
            funding=StripeFundingType.BANK_ACCOUNT,
            processing_charge=50,
        )
    for funding in (
        StripeFundingType.DEBIT,
        StripeFundingType.PREPAID,
        StripeFundingType.UNKNOWN,
    ):
        with pytest.raises(PaymentArtifactError, match="cannot be surcharged"):
            evidence(funding=funding, processing_charge=50)


def test_credit_surcharge_is_bound_to_exact_collected_amount() -> None:
    stripe = evidence(
        funding=StripeFundingType.CREDIT,
        processing_charge=300,
    )
    assert receipt(evidence_=stripe).evidence.amount_minor == 23_429
    with pytest.raises(PaymentArtifactError, match="amount does not match"):
        receipt(evidence_=replace(stripe, amount_minor=23_428))


def test_processing_ach_cannot_deliver_a_smartdeed() -> None:
    pending = evidence(
        method=StripeMethodFamily.US_BANK_ACCOUNT,
        funding=StripeFundingType.BANK_ACCOUNT,
        status=StripePaymentStatus.PROCESSING,
    )
    with pytest.raises(PaymentArtifactError, match="succeeded"):
        receipt(evidence_=pending)


def test_receipt_rejects_refunds_disputes_and_expired_lifetime() -> None:
    stripe = evidence()
    with pytest.raises(PaymentArtifactError, match="refunded"):
        receipt(
            evidence_=replace(
                stripe,
                refunded_minor=100,
                refund_state=StripeRefundState.PARTIAL,
            )
        )
    with pytest.raises(PaymentArtifactError, match="disputed"):
        receipt(evidence_=replace(stripe, dispute_state=StripeDisputeState.OPEN))
    valid = receipt()
    with pytest.raises(PaymentArtifactError, match="48-hour"):
        replace(valid, expires_at=valid.expires_at + 1)
    with pytest.raises(PaymentArtifactError, match="expired"):
        valid.assert_live(valid.expires_at)


def test_receipt_hash_binds_exact_deed_vault_treasury_and_fee() -> None:
    valid = receipt()
    fields = Program.from_bytes(bytes(valid.to_program())).as_python()
    assert bytes(valid.artifact.deed_launcher_id) in fields
    assert bytes(valid.artifact.vault_p2_puzzle_hash) in fields
    assert bytes(valid.artifact.zkpassport_root) in fields
    assert bytes(valid.artifact.protocol_treasury_puzzle_hash) in fields
    changed = artifact()
    changed = replace(changed, authorization_nonce=b32(14))
    assert receipt(artifact_=changed).receipt_hash != valid.receipt_hash


def test_stripe_artifact_rejects_client_side_fee_or_treasury_tampering() -> None:
    item = artifact()
    with pytest.raises(PaymentArtifactError, match="technology_fee_minor"):
        replace(item, technology_fee_minor=item.technology_fee_minor + 1)
    with pytest.raises(PaymentArtifactError, match="must be non-zero"):
        replace(item, protocol_treasury_puzzle_hash=bytes32.zeros)
    with pytest.raises(PaymentArtifactError, match="must be non-zero"):
        replace(item, zkpassport_root=bytes32.zeros)
    assert item.rail == PaymentRail.STRIPE
