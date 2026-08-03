"""RC24 Stripe voucher issuance, refund, and SmartDeed delivery drivers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    PurchaseArtifactV3,
    PurchaseKind,
    StripeSettlementReceiptV1,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    ChiaPrimaryOffer,
    PrimaryPurchaseMode,
    smart_deed_singleton_driver,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    assert_artifact_matches_terms,
    deed_launcher_puzzle_hash_from_struct,
    make_mint_offer_v5_inner,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    VoucherSeriesState,
    VoucherSeriesTermsV2,
    VoucherState,
)
from solslot_puzzles.voucher_presale_v2_driver import (
    SeriesTransition,
    VoucherAction,
    VoucherSeriesStateV2,
    VoucherTransitionContextV2,
    burn_inner_hash,
    curry_purchase_launcher,
    curry_series,
    issuance_coin_ids,
    next_series_state,
    purchase_launcher_solution,
    series_solution,
    transition_message,
)
from solslot_puzzles.voucher_presale_v3 import (
    VoucherCommitmentV3,
    VoucherPaymentRailV3,
    VoucherV3Error,
    validate_stripe_voucher_purchase,
)


STRIPE_VOUCHER_EVIDENCE_DOMAIN = b"SOLSLOT_STRIPE_VOUCHER_EVIDENCE_V1"
STRIPE_VOUCHER_SETTLEMENT_DOMAIN = b"SOLSLOT_STRIPE_VOUCHER_SETTLEMENT_V1"


@dataclass(frozen=True)
class StripeVoucherIssuanceSpendsV3:
    purchase_launcher_spend: CoinSpend
    voucher_launcher_spend: CoinSpend
    series_spend: CoinSpend
    voucher_launcher_id: bytes32
    voucher_coin: Coin
    receipt_coin: Coin
    next_series_coin: Coin
    next_series_state: VoucherSeriesStateV2
    transition_context: VoucherTransitionContextV2
    validator_message: bytes32

    @property
    def coin_spends(self) -> tuple[CoinSpend, CoinSpend, CoinSpend]:
        return (
            self.purchase_launcher_spend,
            self.voucher_launcher_spend,
            self.series_spend,
        )


@dataclass(frozen=True)
class StripeVoucherTerminalSpendsV3:
    series_spend: CoinSpend
    voucher_spend: CoinSpend
    receipt_spend: CoinSpend
    next_series_coin: Coin
    terminal_voucher_coin: Coin
    offer_coin: Coin | None
    next_series_state: VoucherSeriesStateV2
    transition_context: VoucherTransitionContextV2
    validator_message: bytes32
    terminal_evidence_hash: bytes32
    receipt_validator_message: bytes32
    receipt_settlement_message: bytes32

    @property
    def coin_spends(self) -> tuple[CoinSpend, CoinSpend, CoinSpend]:
        return self.series_spend, self.voucher_spend, self.receipt_spend


def voucher_inner_v3_mod() -> Program:
    return load_puzzle("voucher_nft_inner_v3.clsp")


def stripe_voucher_receipt_mod() -> Program:
    return load_puzzle("voucher_stripe_receipt_v1.clsp")


def curry_voucher_inner_v3(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV3,
    voucher_launcher_id: bytes32,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    if voucher.payment_rail != VoucherPaymentRailV3.STRIPE_USD:
        raise VoucherV3Error("voucher V3 inner requires Stripe USD")
    p2 = puzzle_for_p2_vault(voucher.approved_vault_launcher_id)
    return voucher_inner_v3_mod().curry(
        bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
        p2,
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
        burn_inner_hash(),
        terms.terms_hash,
        voucher.commitment_hash,
        voucher_launcher_id,
        voucher.approved_vault_launcher_id,
        voucher.approved_vault_p2_puzzle_hash,
        voucher.global_payment_id,
        voucher.payment_principal,
        voucher.refund_deadline,
        list(terms.validator_pubkeys),
    )


def curry_stripe_voucher_receipt(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV3,
    artifact: PurchaseArtifactV3,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    if artifact.artifact_hash != voucher.purchase_artifact_hash:
        raise VoucherV3Error("Stripe artifact differs from voucher commitment")
    return stripe_voucher_receipt_mod().curry(
        terms.terms_hash,
        voucher.commitment_hash,
        voucher.global_payment_id,
        voucher.original_payer,
        voucher.payment_principal,
        voucher.refund_deadline,
        artifact.artifact_hash,
        artifact.purchase_id,
        voucher.deed_launcher_id,
        voucher.approved_vault_p2_puzzle_hash,
        voucher.trusted_protocol_treasury,
        voucher.stripe_reference_hash,
        voucher.stripe_evidence_hash,
        voucher.payment_attestation_hash,
        voucher.stripe_receipt_hash,
        list(terms.validator_pubkeys),
        bytes32(OFFER_MOD_HASH),
    )


def voucher_v3_solution(
    *,
    action: VoucherAction,
    delivery_deadline: int,
    series_coin_id: bytes32,
    receipt_coin_id: bytes32,
    vault_inner_puzzle_hash: bytes32,
    vault_coin_id: bytes32,
    voucher_inner_puzzle_hash: bytes32,
    signer_indices: Sequence[int],
) -> Program:
    return Program.to(
        [
            int(action),
            delivery_deadline,
            series_coin_id,
            receipt_coin_id,
            vault_inner_puzzle_hash,
            vault_coin_id,
            voucher_inner_puzzle_hash,
            list(_signer_indices(signer_indices)),
        ]
    )


def stripe_voucher_receipt_solution(
    *,
    receipt_coin: Coin,
    action: VoucherAction,
    delivery_deadline: int,
    series_coin_id: bytes32,
    voucher_coin_id: bytes32,
    terminal_evidence_hash: bytes32,
    signer_indices: Sequence[int],
) -> Program:
    if terminal_evidence_hash == bytes32.zeros:
        raise VoucherV3Error("terminal Stripe evidence cannot be zero")
    return Program.to(
        [
            int(action),
            delivery_deadline,
            series_coin_id,
            voucher_coin_id,
            receipt_coin.name(),
            receipt_coin.parent_coin_info,
            receipt_coin.puzzle_hash,
            int(receipt_coin.amount),
            terminal_evidence_hash,
            list(_signer_indices(signer_indices)),
        ]
    )


def stripe_voucher_evidence_message(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV3,
    artifact: PurchaseArtifactV3,
    action: VoucherAction,
    terminal_evidence_hash: bytes32,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                STRIPE_VOUCHER_EVIDENCE_DOMAIN,
                terms.terms_hash,
                voucher.commitment_hash,
                voucher.global_payment_id,
                voucher.original_payer,
                voucher.payment_principal,
                artifact.artifact_hash,
                artifact.purchase_id,
                voucher.stripe_reference_hash,
                voucher.stripe_evidence_hash,
                voucher.payment_attestation_hash,
                voucher.stripe_receipt_hash,
                int(action),
                terminal_evidence_hash,
            ]
        ).get_tree_hash()
    )


def stripe_voucher_settlement_message(
    *,
    voucher: VoucherCommitmentV3,
    artifact: PurchaseArtifactV3,
    terminal_evidence_hash: bytes32,
    voucher_transition_message: bytes32,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                STRIPE_VOUCHER_SETTLEMENT_DOMAIN,
                voucher.stripe_receipt_hash,
                artifact.artifact_hash,
                artifact.purchase_id,
                terminal_evidence_hash,
                voucher.payment_attestation_hash,
                voucher.deed_launcher_id,
                voucher.approved_vault_p2_puzzle_hash,
                voucher_transition_message,
            ]
        ).get_tree_hash()
    )


def build_stripe_voucher_issuance_spends(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    series_lineage_proof: LineageProof,
    voucher: VoucherCommitmentV3,
    artifact: PurchaseArtifactV3,
    receipt: StripeSettlementReceiptV1,
    expected_original_payer: bytes32,
    smart_deed_inner_hash: bytes32,
    purchase_launcher_coin: Coin,
    signer_indices: Sequence[int],
) -> StripeVoucherIssuanceSpendsV3:
    validate_stripe_voucher_purchase(
        series=terms,
        voucher=voucher,
        artifact=artifact,
        receipt=receipt,
        expected_original_payer=expected_original_payer,
        expected_smart_deed_inner_hash=smart_deed_inner_hash,
        now_seconds=receipt.evidence.observed_at,
    )
    receipt_puzzle = curry_stripe_voucher_receipt(
        terms=terms,
        voucher=voucher,
        artifact=artifact,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=terms,
        voucher=voucher,  # type: ignore[arg-type]
        payment_puzzle_hash=bytes32(receipt_puzzle.get_tree_hash()),
        payment_amount=1,
    )
    if (
        purchase_launcher_coin.puzzle_hash != launcher_puzzle.get_tree_hash()
        or int(purchase_launcher_coin.amount) != 2
    ):
        raise VoucherV3Error("Stripe voucher launcher coin is not exact")
    voucher_launcher_id, receipt_coin_id = issuance_coin_ids(
        purchase_launcher_coin,
        payment_puzzle_hash=bytes32(receipt_puzzle.get_tree_hash()),
        payment_amount=1,
    )
    voucher_inner = curry_voucher_inner_v3(
        terms=terms,
        voucher=voucher,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_full = puzzle_for_singleton(voucher_launcher_id, voucher_inner)
    voucher_full_hash = bytes32(voucher_full.get_tree_hash())
    voucher_launcher_coin = Coin(
        purchase_launcher_coin.name(), SINGLETON_LAUNCHER_HASH, uint64(1)
    )
    receipt_coin = Coin(
        purchase_launcher_coin.name(),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    if receipt_coin.name() != receipt_coin_id:
        raise VoucherV3Error("Stripe voucher receipt coin ID changed")

    series_inner = curry_series(terms, state)
    series_full = puzzle_for_singleton(terms.series_singleton_id, series_inner)
    if (
        series_coin.puzzle_hash != series_full.get_tree_hash()
        or int(series_coin.amount) != 1
    ):
        raise VoucherV3Error("current series coin does not match its state")
    context = VoucherTransitionContextV2(
        transition=SeriesTransition.SALE,
        action=VoucherAction.NONE,
        voucher_commitment_hash=voucher.commitment_hash,
        global_payment_id=voucher.global_payment_id,
        escrow_coin_id=receipt_coin_id,
        voucher_launcher_id=voucher_launcher_id,
        voucher_full_puzzle_hash=voucher_full_hash,
        purchase_launcher_coin_id=purchase_launcher_coin.name(),
    )
    next_state = next_series_state(terms, state, context)
    next_inner = curry_series(terms, next_state)
    next_full = puzzle_for_singleton(terms.series_singleton_id, next_inner)
    indices = _signer_indices(signer_indices)
    return StripeVoucherIssuanceSpendsV3(
        purchase_launcher_spend=make_spend(
            purchase_launcher_coin,
            launcher_puzzle,
            purchase_launcher_solution(
                purchase_launcher_coin=purchase_launcher_coin,
                series_coin_id=series_coin.name(),
                voucher_full_puzzle_hash=voucher_full_hash,
            ),
        ),
        voucher_launcher_spend=make_spend(
            voucher_launcher_coin,
            SINGLETON_LAUNCHER,
            Program.to(
                [
                    voucher_full_hash,
                    1,
                    [voucher.commitment_hash, voucher.global_payment_id],
                ]
            ),
        ),
        series_spend=make_spend(
            series_coin,
            series_full,
            solution_for_singleton(
                series_lineage_proof,
                uint64(1),
                series_solution(
                    coin=series_coin,
                    inner_puzzle_hash=bytes32(series_inner.get_tree_hash()),
                    context=context,
                    signer_indices=indices,
                ),
            ),
        ),
        voucher_launcher_id=voucher_launcher_id,
        voucher_coin=Coin(voucher_launcher_id, voucher_full_hash, uint64(1)),
        receipt_coin=receipt_coin,
        next_series_coin=Coin(
            series_coin.name(), bytes32(next_full.get_tree_hash()), uint64(1)
        ),
        next_series_state=next_state,
        transition_context=context,
        validator_message=transition_message(
            terms=terms,
            state=state,
            series_coin_id=series_coin.name(),
            context=context,
        ),
    )


def build_stripe_voucher_terminal_spends(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    series_lineage_proof: LineageProof,
    voucher: VoucherCommitmentV3,
    artifact: PurchaseArtifactV3,
    voucher_launcher_id: bytes32,
    voucher_coin: Coin,
    voucher_lineage_proof: LineageProof,
    receipt_coin: Coin,
    vault_coin_id: bytes32,
    vault_inner_puzzle_hash: bytes32,
    action: VoucherAction,
    terminal_evidence_hash: bytes32,
    signer_indices: Sequence[int],
) -> StripeVoucherTerminalSpendsV3:
    _assert_voucher_matches_terms(terms, voucher)
    if voucher.state != VoucherState.ESCROWED:
        raise VoucherV3Error("only an ESCROWED voucher can settle")
    if artifact.artifact_hash != voucher.purchase_artifact_hash:
        raise VoucherV3Error("Stripe artifact differs from voucher")
    if action not in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REFUND_CANCELED,
        VoucherAction.REDEEM,
    }:
        raise VoucherV3Error("unsupported Stripe voucher action")
    owner_authorized = action in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_CANCELED,
    }
    if owner_authorized and bytes32.zeros in {
        vault_coin_id,
        vault_inner_puzzle_hash,
    }:
        raise VoucherV3Error("voluntary refund requires current vault ownership")
    if not owner_authorized and (
        vault_coin_id != bytes32.zeros
        or vault_inner_puzzle_hash != bytes32.zeros
    ):
        raise VoucherV3Error("automatic settlement cannot carry a vault spend")
    transition = (
        SeriesTransition.REDEEM
        if action == VoucherAction.REDEEM
        else SeriesTransition.REFUND
    )
    context = VoucherTransitionContextV2(
        transition=transition,
        action=action,
        voucher_commitment_hash=voucher.commitment_hash,
        global_payment_id=voucher.global_payment_id,
        escrow_coin_id=receipt_coin.name(),
    )
    next_state = next_series_state(terms, state, context)
    delivery_deadline = (
        state.launched_at + DELIVERY_WINDOW_SECONDS
        if state.phase == VoucherSeriesState.LIVE
        else 0
    )
    series_inner = curry_series(terms, state)
    series_full = puzzle_for_singleton(terms.series_singleton_id, series_inner)
    if series_coin.puzzle_hash != series_full.get_tree_hash():
        raise VoucherV3Error("current series coin does not match its state")
    next_series_inner = curry_series(terms, next_state)
    next_series_full = puzzle_for_singleton(
        terms.series_singleton_id, next_series_inner
    )
    voucher_inner = curry_voucher_inner_v3(
        terms=terms,
        voucher=voucher,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_full = puzzle_for_singleton(voucher_launcher_id, voucher_inner)
    if voucher_coin.puzzle_hash != voucher_full.get_tree_hash():
        raise VoucherV3Error("current voucher coin does not match commitments")
    receipt_puzzle = curry_stripe_voucher_receipt(
        terms=terms,
        voucher=voucher,
        artifact=artifact,
    )
    if (
        receipt_coin.puzzle_hash != receipt_puzzle.get_tree_hash()
        or int(receipt_coin.amount) != 1
    ):
        raise VoucherV3Error("current Stripe receipt coin is not exact")
    indices = _signer_indices(signer_indices)
    validator_message = transition_message(
        terms=terms,
        state=state,
        series_coin_id=series_coin.name(),
        context=context,
    )
    evidence_message = stripe_voucher_evidence_message(
        terms=terms,
        voucher=voucher,
        artifact=artifact,
        action=action,
        terminal_evidence_hash=terminal_evidence_hash,
    )
    settlement_message = stripe_voucher_settlement_message(
        voucher=voucher,
        artifact=artifact,
        terminal_evidence_hash=terminal_evidence_hash,
        voucher_transition_message=validator_message,
    )
    series_spend = make_spend(
        series_coin,
        series_full,
        solution_for_singleton(
            series_lineage_proof,
            uint64(1),
            series_solution(
                coin=series_coin,
                inner_puzzle_hash=bytes32(series_inner.get_tree_hash()),
                context=context,
                signer_indices=indices,
            ),
        ),
    )
    voucher_spend = make_spend(
        voucher_coin,
        voucher_full,
        solution_for_singleton(
            voucher_lineage_proof,
            uint64(1),
            voucher_v3_solution(
                action=action,
                delivery_deadline=delivery_deadline,
                series_coin_id=series_coin.name(),
                receipt_coin_id=receipt_coin.name(),
                vault_inner_puzzle_hash=vault_inner_puzzle_hash,
                vault_coin_id=vault_coin_id,
                voucher_inner_puzzle_hash=bytes32(voucher_inner.get_tree_hash()),
                signer_indices=indices,
            ),
        ),
    )
    receipt_spend = make_spend(
        receipt_coin,
        receipt_puzzle,
        stripe_voucher_receipt_solution(
            receipt_coin=receipt_coin,
            action=action,
            delivery_deadline=delivery_deadline,
            series_coin_id=series_coin.name(),
            voucher_coin_id=voucher_coin.name(),
            terminal_evidence_hash=terminal_evidence_hash,
            signer_indices=indices,
        ),
    )
    terminal_full = puzzle_for_singleton(
        voucher_launcher_id,
        load_puzzle("voucher_burn_v2.clsp"),
    )
    return StripeVoucherTerminalSpendsV3(
        series_spend=series_spend,
        voucher_spend=voucher_spend,
        receipt_spend=receipt_spend,
        next_series_coin=Coin(
            series_coin.name(),
            bytes32(next_series_full.get_tree_hash()),
            uint64(1),
        ),
        terminal_voucher_coin=Coin(
            voucher_coin.name(), bytes32(terminal_full.get_tree_hash()), uint64(1)
        ),
        offer_coin=(
            Coin(receipt_coin.name(), bytes32(OFFER_MOD_HASH), uint64(1))
            if action == VoucherAction.REDEEM
            else None
        ),
        next_series_state=next_state,
        transition_context=context,
        validator_message=validator_message,
        terminal_evidence_hash=terminal_evidence_hash,
        receipt_validator_message=evidence_message,
        receipt_settlement_message=settlement_message,
    )


def prepare_stripe_voucher_redemption_offer(
    *,
    terminal: StripeVoucherTerminalSpendsV3,
    receipt_coin: Coin,
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
    deed_singleton_struct: Program,
) -> Offer:
    assert_artifact_matches_terms(artifact, terms)
    if (
        artifact.rail != PaymentRail.STRIPE
        or artifact.purchase_kind != PurchaseKind.PRESALE
    ):
        raise PaymentArtifactError("voucher redemption requires a Stripe presale")
    spends = terminal.coin_spends
    if len(spends) != 3 or sum(spend.coin == receipt_coin for spend in spends) != 1:
        raise PaymentArtifactError("Stripe voucher offer requires exact terminal spends")
    deed_launcher_puzzle_hash = deed_launcher_puzzle_hash_from_struct(
        deed_singleton_struct,
        artifact.deed_launcher_id,
    )
    if deed_launcher_puzzle_hash != terms.deed_launcher_puzzle_hash:
        raise PaymentArtifactError(
            "deed singleton struct does not match governed mint terms"
        )
    requested = {
        artifact.deed_launcher_id: [
            CreateCoin(
                artifact.vault_p2_puzzle_hash,
                uint64(1),
                [
                    artifact.deed_launcher_id,
                    terms.smart_deed_inner_hash,
                    artifact.metadata_root,
                    artifact.purchase_id,
                    artifact.artifact_hash,
                ],
            )
        ]
    }
    offer = Offer(
        Offer.notarize_payments(requested, [receipt_coin]),
        WalletSpendBundle(list(spends), G2Element()),
        {
            artifact.deed_launcher_id: smart_deed_singleton_driver(
                artifact.deed_launcher_id,
                deed_launcher_puzzle_hash,
            )
        },
    )
    if offer.get_offered_amounts() != {None: 1} or offer.fees() != 0:
        raise PaymentArtifactError("Stripe voucher must offer one zero-fee mojo")
    return offer


def stripe_voucher_offer_v5_solution(
    *,
    deed_coin: Coin,
    receipt_coin: Coin,
    voucher_coin_id: bytes32,
    voucher_transition_message: bytes32,
    terminal_evidence_hash: bytes32,
    receipt: StripeSettlementReceiptV1,
    buyer_offer_nonce: bytes32,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> Program:
    artifact = receipt.artifact
    assert_artifact_matches_terms(artifact, terms)
    if reservation.artifact != artifact:
        raise PaymentArtifactError("voucher differs from active deed reservation")
    if artifact.purchase_kind != PurchaseKind.PRESALE:
        raise PaymentArtifactError("voucher delivery requires a presale artifact")
    return Program.to(
        [
            deed_coin.name(),
            deed_coin.parent_coin_info,
            deed_coin.puzzle_hash,
            deed_coin.amount,
            artifact.vault_launcher_id,
            artifact.vault_p2_puzzle_hash,
            artifact.zkpassport_root,
            artifact.authorization_nonce,
            artifact.authorization_expires_at,
            artifact.quote_expires_at,
            int(artifact.rail),
            artifact.rail_chain_id,
            artifact.rail_asset_id,
            artifact.rail_asset_decimals,
            artifact.rail_amount,
            artifact.oracle_round_hash,
            artifact.oracle_price_usd_minor_per_asset,
            artifact.source_evidence_root,
            int(artifact.purchase_kind),
            artifact.presale_terms_hash,
            buyer_offer_nonce,
            int(PrimaryPurchaseMode.VOUCHER),
            voucher_coin_id,
            voucher_transition_message,
            receipt_coin.name(),
            terminal_evidence_hash,
            receipt.attestation.attestation_hash,
            receipt.receipt_hash,
            0,
            bytes32.zeros,
            0,
            list(_signer_indices(signer_indices)),
        ]
    )


def build_stripe_voucher_primary_offer_v5(
    *,
    voucher_offer: Offer,
    terminal: StripeVoucherTerminalSpendsV3,
    receipt_coin: Coin,
    receipt: StripeSettlementReceiptV1,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> ChiaPrimaryOffer:
    artifact = receipt.artifact
    deed_launcher_puzzle_hash = deed_launcher_puzzle_hash_from_struct(
        deed_singleton_struct,
        artifact.deed_launcher_id,
    )
    if deed_launcher_puzzle_hash != terms.deed_launcher_puzzle_hash:
        raise PaymentArtifactError(
            "deed singleton struct does not match governed mint terms"
        )
    payments = voucher_offer.requested_payments.get(artifact.deed_launcher_id, [])
    if len(payments) != 1:
        raise PaymentArtifactError("Stripe voucher must request one SmartDeed")
    buyer_offer_nonce = bytes32(payments[0].nonce)
    inner = make_mint_offer_v5_inner(terms, reservation)
    full = SINGLETON_MOD.curry(deed_singleton_struct, inner)
    if deed_coin.puzzle_hash != full.get_tree_hash():
        raise PaymentArtifactError("reserved deed does not match mint offer V5")
    deed_spend = make_spend(
        deed_coin,
        full,
        solution_for_singleton(
            lineage_proof,
            uint64(1),
            stripe_voucher_offer_v5_solution(
                deed_coin=deed_coin,
                receipt_coin=receipt_coin,
                voucher_coin_id=terminal.voucher_spend.coin.name(),
                voucher_transition_message=terminal.validator_message,
                terminal_evidence_hash=terminal.terminal_evidence_hash,
                receipt=receipt,
                buyer_offer_nonce=buyer_offer_nonce,
                signer_indices=signer_indices,
                terms=terms,
                reservation=reservation,
            ),
        ),
    )
    issuer_offer = Offer(
        Offer.notarize_payments(
            {
                None: [
                    CreateCoin(
                        terms.protocol_puzhash,
                        uint64(1),
                        [artifact.purchase_id, artifact.artifact_hash],
                    )
                ]
            },
            [deed_coin],
        ),
        WalletSpendBundle([deed_spend], G2Element()),
        {
            artifact.deed_launcher_id: smart_deed_singleton_driver(
                artifact.deed_launcher_id,
                deed_launcher_puzzle_hash,
            )
        },
    )
    aggregate = Offer.aggregate([voucher_offer, issuer_offer])
    if not aggregate.is_valid():
        raise PaymentArtifactError("Stripe voucher and deed offer do not balance")
    return ChiaPrimaryOffer(
        buyer_offer=voucher_offer,
        issuer_offer=issuer_offer,
        aggregate_offer=aggregate,
        deed_spend=deed_spend,
    )
def _assert_voucher_matches_terms(
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV3,
) -> None:
    if (
        voucher.series_terms_hash != terms.terms_hash
        or voucher.series_singleton_id != terms.series_singleton_id
        or voucher.collection_id != terms.collection_id
        or voucher.metadata_root != terms.metadata_root
        or voucher.allocation_root != terms.allocation_root
        or voucher.refund_deadline != terms.refund_deadline
        or voucher.trusted_protocol_treasury != terms.trusted_protocol_treasury
    ):
        raise VoucherV3Error("voucher differs from governed series terms")


def _signer_indices(values: Sequence[int]) -> tuple[int, int]:
    indices = tuple(values)
    if (
        len(indices) != 2
        or tuple(sorted(indices)) != indices
        or len(set(indices)) != 2
        or any(index < 0 or index > 2 for index in indices)
    ):
        raise VoucherV3Error("exactly two sorted validator indices are required")
    return indices  # type: ignore[return-value]


__all__ = [
    "STRIPE_VOUCHER_EVIDENCE_DOMAIN",
    "STRIPE_VOUCHER_SETTLEMENT_DOMAIN",
    "StripeVoucherIssuanceSpendsV3",
    "StripeVoucherTerminalSpendsV3",
    "build_stripe_voucher_issuance_spends",
    "build_stripe_voucher_primary_offer_v5",
    "build_stripe_voucher_terminal_spends",
    "curry_stripe_voucher_receipt",
    "curry_voucher_inner_v3",
    "prepare_stripe_voucher_redemption_offer",
    "stripe_voucher_evidence_message",
    "stripe_voucher_offer_v5_solution",
    "stripe_voucher_receipt_solution",
    "stripe_voucher_settlement_message",
    "voucher_v3_solution",
]
