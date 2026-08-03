from __future__ import annotations

from dataclasses import replace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentAttestationV1,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.mint_publish_driver import deed_singleton_struct
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
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    deed_launcher_puzzle_hash_from_struct,
    make_mint_offer_v5_inner,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault, puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import VoucherSeriesState, VoucherSeriesTermsV2
from solslot_puzzles.voucher_presale_v2_driver import (
    SeriesTransition,
    VoucherAction,
    VoucherSeriesStateV2,
    build_voucher_series_phase_spend,
    curry_purchase_launcher,
    curry_series,
)
from solslot_puzzles.voucher_presale_v3 import (
    VoucherV3Error,
    build_stripe_voucher_commitment,
)
from solslot_puzzles.voucher_presale_v3_driver import (
    build_stripe_voucher_issuance_spends,
    build_stripe_voucher_primary_offer_v5,
    build_stripe_voucher_terminal_spends,
    curry_stripe_voucher_receipt,
    prepare_stripe_voucher_redemption_offer,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def smart_deed_struct(deed_launcher_id: bytes32) -> Program:
    protocol_did_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (b32(99), SINGLETON_LAUNCHER_HASH),
        )
    )
    return deed_singleton_struct(
        deed_launcher_id=deed_launcher_id,
        protocol_did_singleton_struct=protocol_did_struct,
    )


def validator_keys() -> tuple[bytes, bytes, bytes]:
    return tuple(
        bytes(AugSchemeMPL.key_gen(bytes([value]) * 32).get_g1())
        for value in (31, 32, 33)
    )  # type: ignore[return-value]


def series_terms() -> VoucherSeriesTermsV2:
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
        validator_pubkeys=validator_keys(),
    )


def settlement() -> StripeSettlementReceiptV1:
    terms = series_terms()
    vault_launcher = b32(8)
    artifact = build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=terms.collection_id,
        deed_launcher_id=b32(9),
        metadata_root=terms.metadata_root,
        metadata_anchor_id=terms.metadata_anchor_id,
        share_ppm=40_000,
        base_amount_minor=22_900,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=terms.trusted_protocol_treasury,
        zkpassport_root=b32(10),
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=b32(11),
        authorization_expires_at=1_800_000_000,
        quote_expires_at=terms.sale_close,
        presale_terms_hash=terms.terms_hash,
    )
    evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_rc24",
        livemode=False,
        payment_intent_id="pi_presale_driver_rc24",
        event_id="evt_presale_driver_rc24",
        amount_minor=artifact.subtotal_minor + 300,
        currency="usd",
        method_family=StripeMethodFamily.CARD,
        funding_type=StripeFundingType.CREDIT,
        processing_charge_minor=300,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=terms.sale_open + 100,
    )
    pending = build_stripe_pending_attestation(
        artifact=artifact,
        evidence=evidence,
        observed_at=terms.sale_open,
    )
    attestation = PaymentAttestationV1(
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
    from solslot_puzzles.stripe_settlement_v1_driver import validator_roster_root

    return StripeSettlementReceiptV1(
        artifact=artifact,
        evidence=evidence,
        attestation=attestation,
        validator_roster_root=validator_roster_root(terms.validator_pubkeys),
        validator_threshold=2,
        receipt_nonce=b32(12),
        expires_at=evidence.observed_at + 48 * 60 * 60,
    )


def issued_voucher():
    terms = series_terms()
    receipt = settlement()
    smart_deed_inner_hash = bytes32(
        load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
    )
    voucher = build_stripe_voucher_commitment(
        series=terms,
        allocation_root=terms.allocation_root,
        serial=0,
        original_payer=b32(13),
        smart_deed_inner_hash=smart_deed_inner_hash,
        artifact=receipt.artifact,
        receipt=receipt,
    )
    receipt_puzzle = curry_stripe_voucher_receipt(
        terms=terms,
        voucher=voucher,
        artifact=receipt.artifact,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=terms,
        voucher=voucher,  # type: ignore[arg-type]
        payment_puzzle_hash=bytes32(receipt_puzzle.get_tree_hash()),
        payment_amount=1,
    )
    launcher_coin = Coin(b32(14), bytes32(launcher_puzzle.get_tree_hash()), uint64(2))
    state = VoucherSeriesStateV2()
    series_inner = curry_series(terms, state)
    series_coin = Coin(
        terms.series_singleton_id,
        bytes32(
            puzzle_for_singleton(terms.series_singleton_id, series_inner).get_tree_hash()
        ),
        uint64(1),
    )
    issuance = build_stripe_voucher_issuance_spends(
        terms=terms,
        state=state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(b32(15), None, uint64(1)),
        voucher=voucher,
        artifact=receipt.artifact,
        receipt=receipt,
        expected_original_payer=b32(13),
        smart_deed_inner_hash=smart_deed_inner_hash,
        purchase_launcher_coin=launcher_coin,
        signer_indices=(0, 2),
    )
    return terms, voucher, receipt, issuance


def test_stripe_voucher_issuance_reuses_series_and_creates_exact_two_outputs() -> None:
    _terms, voucher, _receipt, issuance = issued_voucher()

    assert len(issuance.coin_spends) == 3
    assert issuance.next_series_state.sold_count == 1
    assert issuance.voucher_launcher_id == Coin(
        issuance.purchase_launcher_spend.coin.name(),
        SINGLETON_LAUNCHER_HASH,
        uint64(1),
    ).name()
    assert issuance.voucher_coin.parent_coin_info == issuance.voucher_launcher_id
    assert issuance.receipt_coin.parent_coin_info == issuance.purchase_launcher_spend.coin.name()
    assert int(issuance.receipt_coin.amount) == 1
    assert voucher.payment_principal > voucher.gross_price_minor

    launcher_additions = compute_additions(issuance.purchase_launcher_spend)
    assert {addition.name() for addition in launcher_additions} == {
        Coin(
            issuance.purchase_launcher_spend.coin.name(),
            SINGLETON_LAUNCHER_HASH,
            uint64(1),
        ).name(),
        issuance.receipt_coin.name(),
    }


def test_stripe_voucher_refund_burns_receipt_without_creating_deed_offer() -> None:
    terms, voucher, receipt, issuance = issued_voucher()
    terminal_evidence = b32(20)
    terminal = build_stripe_voucher_terminal_spends(
        terms=terms,
        state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
        voucher=voucher,
        artifact=receipt.artifact,
        voucher_launcher_id=issuance.voucher_launcher_id,
        voucher_coin=issuance.voucher_coin,
        voucher_lineage_proof=lineage_proof_for_coinsol(
            issuance.voucher_launcher_spend
        ),
        receipt_coin=issuance.receipt_coin,
        vault_coin_id=b32(21),
        vault_inner_puzzle_hash=b32(22),
        action=VoucherAction.REFUND_PRESALE,
        terminal_evidence_hash=terminal_evidence,
        signer_indices=(0, 1),
    )

    assert terminal.terminal_evidence_hash == terminal_evidence
    assert terminal.offer_coin is None
    assert terminal.next_series_state.refunded_count == 1
    receipt_additions = compute_additions(terminal.receipt_spend)
    assert receipt_additions == []

    with pytest.raises(VoucherV3Error, match="ownership"):
        build_stripe_voucher_terminal_spends(
            terms=terms,
            state=issuance.next_series_state,
            series_coin=issuance.next_series_coin,
            series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
            voucher=voucher,
            artifact=receipt.artifact,
            voucher_launcher_id=issuance.voucher_launcher_id,
            voucher_coin=issuance.voucher_coin,
            voucher_lineage_proof=lineage_proof_for_coinsol(
                issuance.voucher_launcher_spend
            ),
            receipt_coin=issuance.receipt_coin,
            vault_coin_id=bytes32.zeros,
            vault_inner_puzzle_hash=bytes32.zeros,
            action=VoucherAction.REFUND_PRESALE,
            terminal_evidence_hash=terminal_evidence,
            signer_indices=(0, 1),
        )


def test_live_stripe_voucher_atomically_delivers_reserved_smartdeed() -> None:
    terms, voucher, receipt, issuance = issued_voucher()
    phase = build_voucher_series_phase_spend(
        terms=terms,
        state=issuance.next_series_state,
        series_coin=issuance.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(issuance.series_spend),
        transition=SeriesTransition.LAUNCH,
        launch_anchor=terms.sale_close,
        signer_indices=(0, 1),
    )
    assert phase.next_series_state.phase == VoucherSeriesState.LIVE

    terminal_evidence = b32(23)
    terminal = build_stripe_voucher_terminal_spends(
        terms=terms,
        state=phase.next_series_state,
        series_coin=phase.next_series_coin,
        series_lineage_proof=lineage_proof_for_coinsol(phase.series_spend),
        voucher=voucher,
        artifact=receipt.artifact,
        voucher_launcher_id=issuance.voucher_launcher_id,
        voucher_coin=issuance.voucher_coin,
        voucher_lineage_proof=lineage_proof_for_coinsol(
            issuance.voucher_launcher_spend
        ),
        receipt_coin=issuance.receipt_coin,
        vault_coin_id=bytes32.zeros,
        vault_inner_puzzle_hash=bytes32.zeros,
        action=VoucherAction.REDEEM,
        terminal_evidence_hash=terminal_evidence,
        signer_indices=(0, 1),
    )
    mint_terms = PrimaryMintTermsV3.for_artifact(
        artifact=receipt.artifact,
        smart_deed_inner_hash=voucher.smart_deed_inner_hash,
        deed_launcher_puzzle_hash=deed_launcher_puzzle_hash_from_struct(
            smart_deed_struct(receipt.artifact.deed_launcher_id),
            receipt.artifact.deed_launcher_id,
        ),
        protocol_puzhash=b32(24),
        validator_pubkeys=terms.validator_pubkeys,
    )
    singleton_struct = smart_deed_struct(receipt.artifact.deed_launcher_id)
    buyer_offer = prepare_stripe_voucher_redemption_offer(
        terminal=terminal,
        receipt_coin=issuance.receipt_coin,
        artifact=receipt.artifact,
        terms=mint_terms,
        deed_singleton_struct=singleton_struct,
    )
    reservation = InventoryReservationV1(
        artifact=receipt.artifact,
        expires_at=phase.next_series_state.launched_at + 48 * 60 * 60 + 60,
    )
    deed_inner = make_mint_offer_v5_inner(mint_terms, reservation)
    deed_coin = Coin(
        b32(25),
        bytes32(SINGLETON_MOD.curry(singleton_struct, deed_inner).get_tree_hash()),
        uint64(1),
    )
    purchase = build_stripe_voucher_primary_offer_v5(
        voucher_offer=buyer_offer,
        terminal=terminal,
        receipt_coin=issuance.receipt_coin,
        receipt=receipt,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(b32(26), bytes32(deed_inner.get_tree_hash()), uint64(1)),
        signer_indices=(0, 1),
        terms=mint_terms,
        reservation=reservation,
    )

    assert purchase.aggregate_offer.is_valid()
    assert purchase.aggregate_offer.arbitrage() == {
        receipt.artifact.deed_launcher_id: 0,
        None: 0,
    }
    spend_bundle = purchase.aggregate_offer.to_valid_spend()
    additions = [
        addition
        for spend in spend_bundle.coin_spends
        for addition in compute_additions(spend)
    ]
    delivered_puzzle_hash = bytes32(
        SINGLETON_MOD.curry(
            singleton_struct,
            puzzle_for_p2_vault(receipt.artifact.vault_launcher_id),
        ).get_tree_hash()
    )
    assert sum(
        addition.puzzle_hash == delivered_puzzle_hash
        and int(addition.amount) == 1
        for addition in additions
    ) == 1
    assert terminal.offer_coin is not None
    assert terminal.offer_coin.parent_coin_info == issuance.receipt_coin.name()


def test_direct_stripe_artifact_cannot_enter_voucher_delivery_mode() -> None:
    terms, voucher, receipt, issuance = issued_voucher()
    direct = build_stripe_purchase_artifact(
        network=receipt.artifact.network,
        collection_id=receipt.artifact.collection_id,
        deed_launcher_id=receipt.artifact.deed_launcher_id,
        metadata_root=receipt.artifact.metadata_root,
        metadata_anchor_id=receipt.artifact.metadata_anchor_id,
        share_ppm=receipt.artifact.share_ppm,
        base_amount_minor=receipt.artifact.base_amount_minor,
        technology_fee_bps=receipt.artifact.technology_fee_bps,
        protocol_treasury_puzzle_hash=(
            receipt.artifact.protocol_treasury_puzzle_hash
        ),
        zkpassport_root=receipt.artifact.zkpassport_root,
        vault_launcher_id=receipt.artifact.vault_launcher_id,
        vault_p2_puzzle_hash=receipt.artifact.vault_p2_puzzle_hash,
        authorization_nonce=receipt.artifact.authorization_nonce,
        authorization_expires_at=receipt.artifact.authorization_expires_at,
        quote_expires_at=receipt.artifact.quote_expires_at,
    )
    pending = build_stripe_pending_attestation(
        artifact=direct,
        evidence=receipt.evidence,
        observed_at=series_terms().sale_open,
    )
    direct_attestation = replace(
        receipt.attestation,
        purchase_id=direct.purchase_id,
        artifact_hash=direct.artifact_hash,
        previous_attestation_hash=pending.attestation_hash,
    )
    direct_receipt = replace(
        receipt,
        artifact=direct,
        attestation=direct_attestation,
    )
    with pytest.raises(Exception, match="presale"):
        from solslot_puzzles.voucher_presale_v3_driver import (
            stripe_voucher_offer_v5_solution,
        )

        stripe_voucher_offer_v5_solution(
            deed_coin=Coin(b32(27), b32(28), uint64(1)),
            receipt_coin=issuance.receipt_coin,
            voucher_coin_id=issuance.voucher_coin.name(),
            voucher_transition_message=b32(29),
            terminal_evidence_hash=b32(30),
            receipt=direct_receipt,
            buyer_offer_nonce=b32(31),
            signer_indices=(0, 1),
            terms=PrimaryMintTermsV3.for_artifact(
                artifact=direct,
                smart_deed_inner_hash=voucher.smart_deed_inner_hash,
                deed_launcher_puzzle_hash=deed_launcher_puzzle_hash_from_struct(
                    smart_deed_struct(direct.deed_launcher_id),
                    direct.deed_launcher_id,
                ),
                protocol_puzhash=b32(24),
                validator_pubkeys=terms.validator_pubkeys,
            ),
            reservation=InventoryReservationV1(
                artifact=direct,
                expires_at=direct.quote_expires_at,
            ),
        )
