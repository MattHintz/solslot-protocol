"""Current reserved SmartDeed delivery for Base vouchers using existing V5 CLVM."""
from typing import Sequence
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_MOD, solution_for_singleton
from chia.wallet.trading.offer import Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import PurchaseArtifactV3, PurchaseKind
from solslot_puzzles.primary_purchase_v2_driver import ChiaPrimaryOffer, PrimaryPurchaseMode, smart_deed_singleton_driver
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1, PrimaryMintTermsV3, assert_artifact_matches_terms,
    deed_launcher_puzzle_hash_from_struct, make_mint_offer_v5_inner,
)
from solslot_puzzles.voucher_presale_v2_driver import BaseVoucherTerminalSpendsV2, _signer_indices
from solslot_puzzles.voucher_purchase import require_current_base_presale


def prepare_base_voucher_redemption_offer_v5(
    *,
    terminal: BaseVoucherTerminalSpendsV2,
    receipt_coin: Coin,
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
    deed_singleton_struct: Program,
) -> Offer:
    require_current_base_presale(artifact)
    assert_artifact_matches_terms(artifact, terms)
    if (
        artifact.rail != PaymentRail.EVM_TEST_USD
        or artifact.purchase_kind != PurchaseKind.PRESALE
    ):
        raise PaymentArtifactError("voucher redemption requires a Base presale")
    spends = terminal.coin_spends
    if len(spends) != 3 or sum(spend.coin == receipt_coin for spend in spends) != 1:
        raise PaymentArtifactError("Base voucher offer requires exact terminal spends")
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
        raise PaymentArtifactError("Base voucher must offer one zero-fee mojo")
    return offer


def base_voucher_offer_v5_solution(
    *,
    deed_coin: Coin,
    receipt_coin: Coin,
    voucher_coin_id: bytes32,
    voucher_transition_message: bytes32,
    terminal_evidence_hash: bytes32,
    artifact: PurchaseArtifactV3,
    buyer_offer_nonce: bytes32,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> Program:
    require_current_base_presale(artifact)
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
            bytes32.zeros,
            bytes32.zeros,
            0,
            bytes32.zeros,
            0,
            list(_signer_indices(signer_indices)),
        ]
    )


def build_base_voucher_primary_offer_v5(
    *,
    voucher_offer: Offer,
    terminal: BaseVoucherTerminalSpendsV2,
    receipt_coin: Coin,
    artifact: PurchaseArtifactV3,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> ChiaPrimaryOffer:
    require_current_base_presale(artifact)
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
        raise PaymentArtifactError("Base voucher must request one SmartDeed")
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
            base_voucher_offer_v5_solution(
                deed_coin=deed_coin,
                receipt_coin=receipt_coin,
                voucher_coin_id=terminal.voucher_spend.coin.name(),
                voucher_transition_message=terminal.validator_message,
                terminal_evidence_hash=terminal.external_settlement_evidence_hash,
                artifact=artifact,
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
        raise PaymentArtifactError("Base voucher and deed offer do not balance")
    return ChiaPrimaryOffer(
        buyer_offer=voucher_offer,
        issuer_offer=issuer_offer,
        aggregate_offer=aggregate,
        deed_spend=deed_spend,
    )
