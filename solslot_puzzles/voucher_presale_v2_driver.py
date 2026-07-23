"""Drivers for the RC20 refundable voucher singleton and payment commitments."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Sequence

from chia.consensus.condition_tools import conditions_dict_for_solution
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import INFINITE_COST, Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk,
    solution_for_conditions,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentRail,
    PurchaseArtifactV2,
)
from solslot_puzzles.vault_driver import (
    P2_VAULT_MOD_HASH,
    puzzle_for_p2_vault,
)
from solslot_puzzles.voucher_presale_v2 import (
    DELIVERY_WINDOW_SECONDS,
    VoucherCommitmentV2,
    VoucherPaymentRail,
    VoucherSeriesState,
    VoucherSeriesTermsV2,
    VoucherState,
    VoucherV2Error,
)

BASE_SEPOLIA_USDC_ASSET_ID = bytes32(
    b"\x00" * 12
    + bytes.fromhex("036cbd53842c5426634e7929541ec2318f3dcf7e")
)


class SeriesTransition(IntEnum):
    SALE = 1
    LAUNCH = 2
    CANCEL = 3
    REFUND = 4
    REDEEM = 5


class VoucherAction(IntEnum):
    NONE = 0
    REFUND_PRESALE = 1
    REFUND_EXPIRED = 2
    REDEEM = 3
    REFUND_CANCELED = 4


@dataclass(frozen=True)
class VoucherSeriesStateV2:
    sold_count: int = 0
    redeemed_count: int = 0
    refunded_count: int = 0
    phase: VoucherSeriesState = VoucherSeriesState.PRESALE
    launched_at: int = 0

    def __post_init__(self) -> None:
        for name in ("sold_count", "redeemed_count", "refunded_count", "launched_at"):
            _uint64(getattr(self, name), name)
        if self.redeemed_count + self.refunded_count > self.sold_count:
            raise VoucherV2Error("settled vouchers exceed sold inventory")
        if self.phase == VoucherSeriesState.LIVE:
            if self.launched_at == 0:
                raise VoucherV2Error("LIVE series requires launched_at")
        elif self.launched_at != 0:
            raise VoucherV2Error("non-LIVE series cannot retain launched_at")


@dataclass(frozen=True)
class VoucherTransitionContextV2:
    transition: SeriesTransition
    action: VoucherAction
    voucher_commitment_hash: bytes32
    global_payment_id: bytes32
    escrow_coin_id: bytes32
    launch_anchor: int = 0
    voucher_launcher_id: bytes32 = bytes32.zeros
    voucher_full_puzzle_hash: bytes32 = bytes32.zeros
    purchase_launcher_coin_id: bytes32 = bytes32.zeros


@dataclass(frozen=True)
class VoucherIssuanceSpendsV2:
    purchase_launcher_spend: CoinSpend
    voucher_launcher_spend: CoinSpend
    series_spend: CoinSpend
    voucher_launcher_id: bytes32
    voucher_coin: Coin
    payment_coin: Coin
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
class VoucherTerminalSpendsV2:
    series_spend: CoinSpend
    voucher_spend: CoinSpend
    payment_spend: CoinSpend
    next_series_coin: Coin
    terminal_voucher_coin: Coin
    settlement_coin: Coin
    next_series_state: VoucherSeriesStateV2
    transition_context: VoucherTransitionContextV2
    validator_message: bytes32

    @property
    def coin_spends(self) -> tuple[CoinSpend, CoinSpend, CoinSpend]:
        return self.series_spend, self.voucher_spend, self.payment_spend


@dataclass(frozen=True)
class BaseVoucherTerminalSpendsV2:
    series_spend: CoinSpend
    voucher_spend: CoinSpend
    receipt_spend: CoinSpend
    next_series_coin: Coin
    terminal_voucher_coin: Coin
    result_authorization_inner_puzzle: Program
    offer_coin: Coin | None
    next_series_state: VoucherSeriesStateV2
    transition_context: VoucherTransitionContextV2
    validator_message: bytes32
    external_settlement_evidence_hash: bytes32
    receipt_settlement_message: bytes32

    @property
    def coin_spends(self) -> tuple[CoinSpend, CoinSpend, CoinSpend]:
        return self.series_spend, self.voucher_spend, self.receipt_spend


@dataclass(frozen=True)
class VoucherSeriesPhaseSpendV2:
    series_spend: CoinSpend
    next_series_coin: Coin
    next_series_state: VoucherSeriesStateV2
    transition_context: VoucherTransitionContextV2
    validator_message: bytes32


@dataclass(frozen=True)
class PreparedXchVoucherOfferV2:
    offer: Offer
    payment_spend: CoinSpend
    purchase_launcher_coin: Coin


def series_mod() -> Program:
    return load_puzzle("voucher_presale_series_v2.clsp")


def voucher_inner_mod() -> Program:
    return load_puzzle("voucher_nft_inner_v2.clsp")


def escrow_mod() -> Program:
    return load_puzzle("voucher_payment_escrow_v2.clsp")


def external_receipt_mod() -> Program:
    return load_puzzle("voucher_external_escrow_receipt_v2.clsp")


def base_result_authorization_mod() -> Program:
    return load_puzzle("voucher_base_result_authorization_v2.clsp")


def purchase_launcher_mod() -> Program:
    return load_puzzle("voucher_purchase_launcher_v2.clsp")


def burn_inner_hash() -> bytes32:
    return bytes32(load_puzzle("voucher_burn_v2.clsp").get_tree_hash())


def singleton_struct(launcher_id: bytes32) -> Program:
    return Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))


def curry_series(
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
) -> Program:
    if state.sold_count > terms.inventory_cap:
        raise VoucherV2Error("sold inventory exceeds series cap")
    mod = series_mod()
    return mod.curry(
        bytes32(mod.get_tree_hash()),
        singleton_struct(terms.series_singleton_id),
        terms.terms_hash,
        terms.inventory_cap,
        terms.sale_open,
        terms.sale_close,
        terms.refund_deadline,
        terms.launch_deadline,
        DELIVERY_WINDOW_SECONDS,
        list(terms.validator_pubkeys),
        state.sold_count,
        state.redeemed_count,
        state.refunded_count,
        int(state.phase),
        state.launched_at,
    )


def transition_message(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin_id: bytes32,
    context: VoucherTransitionContextV2,
) -> bytes32:
    if context.transition == SeriesTransition.SALE:
        return bytes32(
            Program.to(
                [
                    b"SOLSLOT_VOUCHER_ISSUANCE_V2",
                    terms.terms_hash,
                    series_coin_id,
                    context.purchase_launcher_coin_id,
                    context.voucher_launcher_id,
                    context.voucher_full_puzzle_hash,
                    context.escrow_coin_id,
                    context.voucher_commitment_hash,
                    context.global_payment_id,
                ]
            ).get_tree_hash()
        )
    if context.transition in {SeriesTransition.REFUND, SeriesTransition.REDEEM}:
        deadline = (
            state.launched_at + DELIVERY_WINDOW_SECONDS
            if state.phase == VoucherSeriesState.LIVE
            else 0
        )
        return bytes32(
            Program.to(
                [
                    b"SOLSLOT_VOUCHER_TRANSITION_V2",
                    terms.terms_hash,
                    context.voucher_commitment_hash,
                    context.global_payment_id,
                    int(context.action),
                    int(context.transition),
                    deadline,
                    series_coin_id,
                    context.escrow_coin_id,
                ]
            ).get_tree_hash()
        )
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_VOUCHER_SERIES_V2",
                terms.terms_hash,
                state.sold_count,
                state.redeemed_count,
                state.refunded_count,
                int(state.phase),
                state.launched_at,
                int(context.transition),
                int(context.action),
                context.voucher_commitment_hash,
                context.global_payment_id,
                context.escrow_coin_id,
                context.launch_anchor,
            ]
        ).get_tree_hash()
    )


def next_series_state(
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    context: VoucherTransitionContextV2,
) -> VoucherSeriesStateV2:
    zero = bytes32.zeros
    if context.transition == SeriesTransition.SALE:
        if (
            state.phase != VoucherSeriesState.PRESALE
            or state.sold_count >= terms.inventory_cap
            or context.action != VoucherAction.NONE
            or zero in {
                context.voucher_commitment_hash,
                context.global_payment_id,
                context.escrow_coin_id,
            }
            or context.launch_anchor != 0
            or context.voucher_launcher_id == zero
            or context.voucher_full_puzzle_hash == zero
            or context.purchase_launcher_coin_id == zero
        ):
            raise VoucherV2Error("invalid SALE transition")
        return VoucherSeriesStateV2(
            state.sold_count + 1,
            state.redeemed_count,
            state.refunded_count,
            state.phase,
            0,
        )
    if context.transition == SeriesTransition.LAUNCH:
        if (
            state.phase != VoucherSeriesState.PRESALE
            or context.action != VoucherAction.NONE
            or any(
                value != zero
                for value in (
                    context.voucher_commitment_hash,
                    context.global_payment_id,
                    context.escrow_coin_id,
                )
            )
            or not terms.sale_close <= context.launch_anchor <= terms.launch_deadline
            or context.voucher_launcher_id != zero
            or context.voucher_full_puzzle_hash != zero
            or context.purchase_launcher_coin_id != zero
        ):
            raise VoucherV2Error("invalid LAUNCH transition")
        return VoucherSeriesStateV2(
            state.sold_count,
            state.redeemed_count,
            state.refunded_count,
            VoucherSeriesState.LIVE,
            context.launch_anchor,
        )
    if context.transition == SeriesTransition.CANCEL:
        if (
            state.phase != VoucherSeriesState.PRESALE
            or context.action != VoucherAction.NONE
            or any(
                value != zero
                for value in (
                    context.voucher_commitment_hash,
                    context.global_payment_id,
                    context.escrow_coin_id,
                )
            )
            or context.launch_anchor != 0
            or context.voucher_launcher_id != zero
            or context.voucher_full_puzzle_hash != zero
            or context.purchase_launcher_coin_id != zero
        ):
            raise VoucherV2Error("invalid CANCEL transition")
        return VoucherSeriesStateV2(
            state.sold_count,
            state.redeemed_count,
            state.refunded_count,
            VoucherSeriesState.CANCELED,
            0,
        )
    if state.redeemed_count + state.refunded_count >= state.sold_count:
        raise VoucherV2Error("no unsettled voucher remains")
    if (
        context.voucher_launcher_id != zero
        or context.voucher_full_puzzle_hash != zero
        or context.purchase_launcher_coin_id != zero
    ):
        raise VoucherV2Error("terminal transitions cannot change issuance coins")
    expected_action = {
        VoucherSeriesState.PRESALE: VoucherAction.REFUND_PRESALE,
        VoucherSeriesState.LIVE: VoucherAction.REFUND_EXPIRED,
        VoucherSeriesState.CANCELED: VoucherAction.REFUND_CANCELED,
    }
    if context.transition == SeriesTransition.REFUND:
        if context.action != expected_action[state.phase]:
            raise VoucherV2Error("refund action does not match series phase")
        return VoucherSeriesStateV2(
            state.sold_count,
            state.redeemed_count,
            state.refunded_count + 1,
            state.phase,
            state.launched_at,
        )
    if (
        context.transition != SeriesTransition.REDEEM
        or state.phase != VoucherSeriesState.LIVE
        or context.action != VoucherAction.REDEEM
    ):
        raise VoucherV2Error("invalid REDEEM transition")
    return VoucherSeriesStateV2(
        state.sold_count,
        state.redeemed_count + 1,
        state.refunded_count,
        state.phase,
        state.launched_at,
    )


def series_solution(
    *,
    coin: Coin,
    inner_puzzle_hash: bytes32,
    context: VoucherTransitionContextV2,
    signer_indices: Sequence[int],
) -> Program:
    indices = _signer_indices(signer_indices)
    return Program.to(
        [
            coin.name(),
            inner_puzzle_hash,
            int(coin.amount),
            int(context.transition),
            int(context.action),
            context.voucher_commitment_hash,
            context.global_payment_id,
            context.escrow_coin_id,
            context.launch_anchor,
            context.voucher_launcher_id,
            context.voucher_full_puzzle_hash,
            context.purchase_launcher_coin_id,
            list(indices),
        ]
    )


def curry_voucher_inner(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
    voucher_launcher_id: bytes32,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    p2 = puzzle_for_p2_vault(voucher.approved_vault_launcher_id)
    return voucher_inner_mod().curry(
        P2_VAULT_MOD_HASH,
        p2,
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
        burn_inner_hash(),
        bytes32(base_result_authorization_mod().get_tree_hash()),
        terms.base_return_puzzle_hash,
        terms.terms_hash,
        voucher.commitment_hash,
        voucher_launcher_id,
        voucher.approved_vault_launcher_id,
        voucher.approved_vault_p2_puzzle_hash,
        voucher.global_payment_id,
        int(voucher.payment_rail),
        voucher.payment_principal,
        voucher.refund_deadline,
        list(terms.validator_pubkeys),
    )


def base_result_message(
    *,
    voucher: VoucherCommitmentV2,
    succeeded: bool,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_BASE_VOUCHER_RESULT_V2",
                voucher.commitment_hash,
                voucher.global_payment_id,
                voucher.payment_principal,
                1 if succeeded else 0,
            ]
        ).get_tree_hash()
    )


def curry_base_result_authorization(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
    action: VoucherAction,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    if voucher.payment_rail != VoucherPaymentRail.BASE_SEPOLIA_USDC:
        raise VoucherV2Error(
            "Base result authorization requires a Base Sepolia USDC voucher"
        )
    if action not in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REFUND_CANCELED,
        VoucherAction.REDEEM,
    }:
        raise VoucherV2Error("unsupported Base result action")
    return base_result_authorization_mod().curry(
        burn_inner_hash(),
        terms.base_return_puzzle_hash,
        voucher.commitment_hash,
        voucher.global_payment_id,
        voucher.payment_principal,
        1 if action == VoucherAction.REDEEM else 0,
    )


def voucher_solution(
    *,
    action: VoucherAction,
    delivery_deadline: int,
    series_coin_id: bytes32,
    escrow_coin_id: bytes32,
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
            escrow_coin_id,
            vault_inner_puzzle_hash,
            vault_coin_id,
            voucher_inner_puzzle_hash,
            list(_signer_indices(signer_indices)),
        ]
    )


def curry_xch_escrow(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    if (
        purchase.rail != PaymentRail.CHIA_XCH
        or voucher.payment_rail != VoucherPaymentRail.CHIA_XCH
    ):
        raise PaymentArtifactError("voucher XCH escrow requires a native XCH artifact")
    comparisons = (
        (purchase.collection_id, voucher.collection_id),
        (purchase.deed_launcher_id, voucher.deed_launcher_id),
        (purchase.metadata_root, voucher.metadata_root),
        (purchase.vault_launcher_id, voucher.approved_vault_launcher_id),
        (purchase.vault_p2_puzzle_hash, voucher.approved_vault_p2_puzzle_hash),
    )
    if any(left != right for left, right in comparisons):
        raise PaymentArtifactError("purchase artifact differs from voucher commitments")
    if (
        purchase.usd_amount_minor != voucher.gross_price_minor
        or purchase.rail_amount != voucher.payment_principal
        or purchase.artifact_hash != voucher.purchase_artifact_hash
    ):
        raise PaymentArtifactError("purchase price differs from voucher commitments")
    return escrow_mod().curry(
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
        OFFER_MOD_HASH,
        terms.terms_hash,
        voucher.commitment_hash,
        voucher.global_payment_id,
        voucher.original_payer,
        voucher.payment_principal,
        voucher.refund_deadline,
        voucher.deed_launcher_id,
        voucher.smart_deed_inner_hash,
        voucher.metadata_root,
        purchase.purchase_id,
        purchase.artifact_hash,
        voucher.approved_vault_p2_puzzle_hash,
        list(terms.validator_pubkeys),
    )


def escrow_solution(
    *,
    escrow_coin: Coin,
    action: VoucherAction,
    delivery_deadline: int,
    series_coin_id: bytes32,
    voucher_coin_id: bytes32,
    signer_indices: Sequence[int],
) -> Program:
    return Program.to(
        [
            int(action),
            delivery_deadline,
            series_coin_id,
            voucher_coin_id,
            escrow_coin.name(),
            escrow_coin.parent_coin_info,
            escrow_coin.puzzle_hash,
            int(escrow_coin.amount),
            list(_signer_indices(signer_indices)),
        ]
    )


def curry_external_receipt(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    if voucher.payment_rail != VoucherPaymentRail.BASE_SEPOLIA_USDC:
        raise VoucherV2Error("external receipt requires the Base Sepolia USDC rail")
    return external_receipt_mod().curry(
        terms.terms_hash,
        voucher.commitment_hash,
        voucher.global_payment_id,
        voucher.original_payer,
        voucher.payment_principal,
        voucher.refund_deadline,
        voucher.payment_chain_id,
        voucher.external_escrow_contract,
        voucher.payment_asset_id,
        voucher.purchase_artifact_hash,
        voucher.deed_launcher_id,
        voucher.approved_vault_p2_puzzle_hash,
        voucher.trusted_protocol_treasury,
        list(terms.validator_pubkeys),
        bytes32(OFFER_MOD_HASH),
    )


def external_receipt_settlement_message(
    *,
    voucher: VoucherCommitmentV2,
    action: VoucherAction,
    external_settlement_evidence_hash: bytes32,
    voucher_transition_message: bytes32,
) -> bytes32:
    if action not in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REDEEM,
        VoucherAction.REFUND_CANCELED,
    }:
        raise VoucherV2Error("unsupported external receipt action")
    for name, value in (
        ("external_settlement_evidence_hash", external_settlement_evidence_hash),
        ("voucher_transition_message", voucher_transition_message),
    ):
        if value == bytes32.zeros:
            raise VoucherV2Error(f"{name} cannot be zero")
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_BASE_RECEIPT_SETTLEMENT_V2",
                voucher.purchase_artifact_hash,
                voucher.deed_launcher_id,
                voucher.approved_vault_p2_puzzle_hash,
                int(action),
                external_settlement_evidence_hash,
                voucher_transition_message,
            ]
        ).get_tree_hash()
    )


def external_receipt_evidence_message(
    *,
    voucher: VoucherCommitmentV2,
    action: VoucherAction,
    external_settlement_evidence_hash: bytes32,
) -> bytes32:
    """Return the exact Base evidence message signed by receipt validators."""
    if action not in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REDEEM,
        VoucherAction.REFUND_CANCELED,
    }:
        raise VoucherV2Error("unsupported external receipt action")
    if external_settlement_evidence_hash == bytes32.zeros:
        raise VoucherV2Error("external settlement evidence cannot be zero")
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_BASE_ESCROW_SETTLEMENT_V2",
                voucher.payment_chain_id,
                voucher.external_escrow_contract,
                voucher.payment_asset_id,
                voucher.global_payment_id,
                voucher.original_payer,
                voucher.payment_principal,
                voucher.purchase_artifact_hash,
                int(action),
                external_settlement_evidence_hash,
            ]
        ).get_tree_hash()
    )


def external_receipt_solution(
    *,
    receipt_coin: Coin,
    action: VoucherAction,
    delivery_deadline: int,
    series_coin_id: bytes32,
    voucher_coin_id: bytes32,
    external_settlement_evidence_hash: bytes32,
    signer_indices: Sequence[int],
) -> Program:
    if external_settlement_evidence_hash == bytes32.zeros:
        raise VoucherV2Error("external settlement evidence cannot be zero")
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
            external_settlement_evidence_hash,
            list(_signer_indices(signer_indices)),
        ]
    )


def curry_purchase_launcher(
    *,
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
    payment_puzzle_hash: bytes32,
    payment_amount: int,
) -> Program:
    _assert_voucher_matches_terms(terms, voucher)
    _uint64(payment_amount, "payment_amount")
    if payment_amount == 0:
        raise VoucherV2Error("payment_amount must be positive")
    return purchase_launcher_mod().curry(
        SINGLETON_LAUNCHER_HASH,
        terms.terms_hash,
        voucher.commitment_hash,
        voucher.global_payment_id,
        payment_puzzle_hash,
        payment_amount,
    )


def issuance_coin_ids(
    purchase_launcher_coin: Coin,
    *,
    payment_puzzle_hash: bytes32,
    payment_amount: int,
) -> tuple[bytes32, bytes32]:
    parent_id = purchase_launcher_coin.name()
    voucher_launcher_id = Coin(
        parent_id, SINGLETON_LAUNCHER_HASH, 1
    ).name()
    payment_coin_id = Coin(
        parent_id, payment_puzzle_hash, payment_amount
    ).name()
    return voucher_launcher_id, payment_coin_id


def purchase_launcher_solution(
    *,
    purchase_launcher_coin: Coin,
    series_coin_id: bytes32,
    voucher_full_puzzle_hash: bytes32,
) -> Program:
    return Program.to(
        [
            purchase_launcher_coin.name(),
            purchase_launcher_coin.parent_coin_info,
            purchase_launcher_coin.puzzle_hash,
            int(purchase_launcher_coin.amount),
            series_coin_id,
            voucher_full_puzzle_hash,
        ]
    )


def build_voucher_issuance_spends(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    series_lineage_proof: LineageProof,
    voucher: VoucherCommitmentV2,
    purchase_launcher_coin: Coin,
    payment_puzzle: Program,
    payment_amount: int,
    signer_indices: Sequence[int],
) -> VoucherIssuanceSpendsV2:
    """Build the consensus-critical half of one atomic voucher issuance.

    The caller supplies the spend that created ``purchase_launcher_coin`` and
    its signature. This function binds that paid coin to the signed series
    transition, the standard voucher singleton launcher, and the immutable
    XCH escrow or Base receipt output.
    """
    _assert_voucher_matches_terms(terms, voucher)
    _uint64(payment_amount, "payment_amount")
    if payment_amount == 0:
        raise VoucherV2Error("payment_amount must be positive")
    payment_puzzle_hash = bytes32(payment_puzzle.get_tree_hash())
    purchase_launcher = curry_purchase_launcher(
        terms=terms,
        voucher=voucher,
        payment_puzzle_hash=payment_puzzle_hash,
        payment_amount=payment_amount,
    )
    if (
        purchase_launcher_coin.puzzle_hash != purchase_launcher.get_tree_hash()
        or int(purchase_launcher_coin.amount) != payment_amount + 1
    ):
        raise VoucherV2Error(
            "purchase launcher coin does not match the committed payment"
        )

    voucher_launcher_id, payment_coin_id = issuance_coin_ids(
        purchase_launcher_coin,
        payment_puzzle_hash=payment_puzzle_hash,
        payment_amount=payment_amount,
    )
    voucher_inner = curry_voucher_inner(
        terms=terms,
        voucher=voucher,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_full = puzzle_for_singleton(voucher_launcher_id, voucher_inner)
    voucher_full_hash = bytes32(voucher_full.get_tree_hash())
    voucher_launcher_coin = Coin(
        purchase_launcher_coin.name(),
        SINGLETON_LAUNCHER_HASH,
        1,
    )
    payment_coin = Coin(
        purchase_launcher_coin.name(),
        payment_puzzle_hash,
        payment_amount,
    )
    if (
        voucher_launcher_coin.name() != voucher_launcher_id
        or payment_coin.name() != payment_coin_id
    ):
        raise VoucherV2Error("issuance output IDs changed during construction")

    series_inner = curry_series(terms, state)
    series_full = puzzle_for_singleton(terms.series_singleton_id, series_inner)
    if (
        series_coin.puzzle_hash != series_full.get_tree_hash()
        or int(series_coin.amount) != 1
    ):
        raise VoucherV2Error("current series coin does not match its committed state")
    context = VoucherTransitionContextV2(
        transition=SeriesTransition.SALE,
        action=VoucherAction.NONE,
        voucher_commitment_hash=voucher.commitment_hash,
        global_payment_id=voucher.global_payment_id,
        escrow_coin_id=payment_coin_id,
        voucher_launcher_id=voucher_launcher_id,
        voucher_full_puzzle_hash=voucher_full_hash,
        purchase_launcher_coin_id=purchase_launcher_coin.name(),
    )
    next_state = next_series_state(terms, state, context)
    next_inner = curry_series(terms, next_state)
    next_full = puzzle_for_singleton(terms.series_singleton_id, next_inner)

    purchase_spend = make_spend(
        purchase_launcher_coin,
        purchase_launcher,
        purchase_launcher_solution(
            purchase_launcher_coin=purchase_launcher_coin,
            series_coin_id=series_coin.name(),
            voucher_full_puzzle_hash=voucher_full_hash,
        ),
    )
    voucher_launcher_spend = make_spend(
        voucher_launcher_coin,
        SINGLETON_LAUNCHER,
        Program.to(
            [
                voucher_full_hash,
                1,
                [voucher.commitment_hash, voucher.global_payment_id],
            ]
        ),
    )
    series_spend = make_spend(
        series_coin,
        series_full,
        solution_for_singleton(
            series_lineage_proof,
            series_coin.amount,
            series_solution(
                coin=series_coin,
                inner_puzzle_hash=bytes32(series_inner.get_tree_hash()),
                context=context,
                signer_indices=signer_indices,
            ),
        ),
    )
    return VoucherIssuanceSpendsV2(
        purchase_launcher_spend=purchase_spend,
        voucher_launcher_spend=voucher_launcher_spend,
        series_spend=series_spend,
        voucher_launcher_id=voucher_launcher_id,
        voucher_coin=Coin(voucher_launcher_id, voucher_full_hash, 1),
        payment_coin=payment_coin,
        next_series_coin=Coin(
            series_coin.name(),
            bytes32(next_full.get_tree_hash()),
            1,
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


def build_xch_voucher_terminal_spends(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    series_lineage_proof: LineageProof,
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2,
    voucher_launcher_id: bytes32,
    voucher_coin: Coin,
    voucher_lineage_proof: LineageProof,
    payment_coin: Coin,
    vault_coin_id: bytes32,
    vault_inner_puzzle_hash: bytes32,
    action: VoucherAction,
    signer_indices: Sequence[int],
) -> VoucherTerminalSpendsV2:
    """Build the immutable XCH refund or redemption protocol spends.

    Presale and canceled refunds require the approved vault singleton to be
    co-spent by its owner. Expired refunds and redemption are automatic: their
    zero vault placeholders are accepted only by those terminal branches.
    """
    _assert_voucher_matches_terms(terms, voucher)
    if voucher.state != VoucherState.ESCROWED:
        raise VoucherV2Error("only an ESCROWED voucher can settle on chain")
    if voucher.payment_rail != VoucherPaymentRail.CHIA_XCH:
        raise VoucherV2Error("XCH terminal spends require an XCH voucher")
    if action not in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REFUND_CANCELED,
        VoucherAction.REDEEM,
    }:
        raise VoucherV2Error("unsupported voucher terminal action")
    if voucher_launcher_id == bytes32.zeros:
        raise VoucherV2Error("voucher launcher input must be nonzero")
    owner_authorized = action in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_CANCELED,
    }
    if owner_authorized and bytes32.zeros in {
        vault_coin_id,
        vault_inner_puzzle_hash,
    }:
        raise VoucherV2Error("refund vault lineage inputs must be nonzero")
    if not owner_authorized and (
        vault_coin_id != bytes32.zeros
        or vault_inner_puzzle_hash != bytes32.zeros
    ):
        raise VoucherV2Error(
            "automatic voucher settlement cannot carry a second owner spend"
        )

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
        escrow_coin_id=payment_coin.name(),
    )
    next_state = next_series_state(terms, state, context)
    delivery_deadline = (
        state.launched_at + DELIVERY_WINDOW_SECONDS
        if state.phase == VoucherSeriesState.LIVE
        else 0
    )

    series_inner = curry_series(terms, state)
    series_full = puzzle_for_singleton(terms.series_singleton_id, series_inner)
    if series_coin.puzzle_hash != series_full.get_tree_hash() or int(series_coin.amount) != 1:
        raise VoucherV2Error("current series coin does not match its committed state")
    next_series_inner = curry_series(terms, next_state)
    next_series_full = puzzle_for_singleton(
        terms.series_singleton_id,
        next_series_inner,
    )

    voucher_inner = curry_voucher_inner(
        terms=terms,
        voucher=voucher,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_full = puzzle_for_singleton(voucher_launcher_id, voucher_inner)
    if voucher_coin.puzzle_hash != voucher_full.get_tree_hash() or int(voucher_coin.amount) != 1:
        raise VoucherV2Error("current voucher coin does not match its commitments")
    terminal_voucher_full = puzzle_for_singleton(
        voucher_launcher_id,
        load_puzzle("voucher_burn_v2.clsp"),
    )

    payment_puzzle = curry_xch_escrow(
        terms=terms,
        voucher=voucher,
        purchase=purchase,
    )
    if (
        payment_coin.puzzle_hash != payment_puzzle.get_tree_hash()
        or int(payment_coin.amount) != voucher.payment_principal
    ):
        raise VoucherV2Error("current XCH escrow coin does not match the voucher")

    indices = _signer_indices(signer_indices)
    series_spend = make_spend(
        series_coin,
        series_full,
        solution_for_singleton(
            series_lineage_proof,
            series_coin.amount,
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
            voucher_coin.amount,
            voucher_solution(
                action=action,
                delivery_deadline=delivery_deadline,
                series_coin_id=series_coin.name(),
                escrow_coin_id=payment_coin.name(),
                vault_inner_puzzle_hash=vault_inner_puzzle_hash,
                vault_coin_id=vault_coin_id,
                voucher_inner_puzzle_hash=bytes32(voucher_inner.get_tree_hash()),
                signer_indices=indices,
            ),
        ),
    )
    payment_spend = make_spend(
        payment_coin,
        payment_puzzle,
        escrow_solution(
            escrow_coin=payment_coin,
            action=action,
            delivery_deadline=delivery_deadline,
            series_coin_id=series_coin.name(),
            voucher_coin_id=voucher_coin.name(),
            signer_indices=indices,
        ),
    )
    settlement_puzzle_hash = (
        bytes32(OFFER_MOD_HASH)
        if action == VoucherAction.REDEEM
        else voucher.original_payer
    )
    return VoucherTerminalSpendsV2(
        series_spend=series_spend,
        voucher_spend=voucher_spend,
        payment_spend=payment_spend,
        next_series_coin=Coin(
            series_coin.name(),
            bytes32(next_series_full.get_tree_hash()),
            uint64(1),
        ),
        terminal_voucher_coin=Coin(
            voucher_coin.name(),
            bytes32(terminal_voucher_full.get_tree_hash()),
            uint64(1),
        ),
        settlement_coin=Coin(
            payment_coin.name(),
            settlement_puzzle_hash,
            uint64(voucher.payment_principal),
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


def build_base_voucher_terminal_spends(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    series_lineage_proof: LineageProof,
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2,
    voucher_launcher_id: bytes32,
    voucher_coin: Coin,
    voucher_lineage_proof: LineageProof,
    receipt_coin: Coin,
    vault_coin_id: bytes32,
    vault_inner_puzzle_hash: bytes32,
    action: VoucherAction,
    external_settlement_evidence_hash: bytes32,
    signer_indices: Sequence[int],
) -> BaseVoucherTerminalSpendsV2:
    """Build one exact Base USDC voucher refund or deed-delivery transition.

    The Chia receipt is a one-mojo coordination coin, never the USDC payment.
    On redemption it exposes that mojo through OFFER_MOD so the governed deed
    can be delivered atomically. The EVM escrow remains the sole USDC
    custodian and settles only after the resulting Chia evidence is confirmed.
    """
    _assert_voucher_matches_terms(terms, voucher)
    _assert_base_voucher_matches_purchase(voucher, purchase)
    if voucher.state != VoucherState.ESCROWED:
        raise VoucherV2Error("only an ESCROWED voucher can settle on chain")
    if action not in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_EXPIRED,
        VoucherAction.REFUND_CANCELED,
        VoucherAction.REDEEM,
    }:
        raise VoucherV2Error("unsupported voucher terminal action")
    if voucher_launcher_id == bytes32.zeros:
        raise VoucherV2Error("voucher launcher input must be nonzero")
    if external_settlement_evidence_hash == bytes32.zeros:
        raise VoucherV2Error("external settlement evidence cannot be zero")
    owner_authorized = action in {
        VoucherAction.REFUND_PRESALE,
        VoucherAction.REFUND_CANCELED,
    }
    if owner_authorized and bytes32.zeros in {
        vault_coin_id,
        vault_inner_puzzle_hash,
    }:
        raise VoucherV2Error("refund vault lineage inputs must be nonzero")
    if not owner_authorized and (
        vault_coin_id != bytes32.zeros
        or vault_inner_puzzle_hash != bytes32.zeros
    ):
        raise VoucherV2Error(
            "automatic voucher settlement cannot carry a second owner spend"
        )

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
    if (
        series_coin.puzzle_hash != series_full.get_tree_hash()
        or int(series_coin.amount) != 1
    ):
        raise VoucherV2Error("current series coin does not match its committed state")
    next_series_inner = curry_series(terms, next_state)
    next_series_full = puzzle_for_singleton(
        terms.series_singleton_id,
        next_series_inner,
    )

    voucher_inner = curry_voucher_inner(
        terms=terms,
        voucher=voucher,
        voucher_launcher_id=voucher_launcher_id,
    )
    voucher_full = puzzle_for_singleton(voucher_launcher_id, voucher_inner)
    if (
        voucher_coin.puzzle_hash != voucher_full.get_tree_hash()
        or int(voucher_coin.amount) != 1
    ):
        raise VoucherV2Error("current voucher coin does not match its commitments")
    result_authorization_inner = curry_base_result_authorization(
        terms=terms,
        voucher=voucher,
        action=action,
    )
    terminal_voucher_full = puzzle_for_singleton(
        voucher_launcher_id,
        result_authorization_inner,
    )

    receipt_puzzle = curry_external_receipt(terms=terms, voucher=voucher)
    if (
        receipt_coin.puzzle_hash != receipt_puzzle.get_tree_hash()
        or int(receipt_coin.amount) != 1
    ):
        raise VoucherV2Error("current Base receipt coin does not match the voucher")

    indices = _signer_indices(signer_indices)
    validator_message = transition_message(
        terms=terms,
        state=state,
        series_coin_id=series_coin.name(),
        context=context,
    )
    settlement_message = external_receipt_settlement_message(
        voucher=voucher,
        action=action,
        external_settlement_evidence_hash=external_settlement_evidence_hash,
        voucher_transition_message=validator_message,
    )
    series_spend = make_spend(
        series_coin,
        series_full,
        solution_for_singleton(
            series_lineage_proof,
            series_coin.amount,
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
            voucher_coin.amount,
            voucher_solution(
                action=action,
                delivery_deadline=delivery_deadline,
                series_coin_id=series_coin.name(),
                escrow_coin_id=receipt_coin.name(),
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
        external_receipt_solution(
            receipt_coin=receipt_coin,
            action=action,
            delivery_deadline=delivery_deadline,
            series_coin_id=series_coin.name(),
            voucher_coin_id=voucher_coin.name(),
            external_settlement_evidence_hash=external_settlement_evidence_hash,
            signer_indices=indices,
        ),
    )
    return BaseVoucherTerminalSpendsV2(
        series_spend=series_spend,
        voucher_spend=voucher_spend,
        receipt_spend=receipt_spend,
        next_series_coin=Coin(
            series_coin.name(),
            bytes32(next_series_full.get_tree_hash()),
            uint64(1),
        ),
        terminal_voucher_coin=Coin(
            voucher_coin.name(),
            bytes32(terminal_voucher_full.get_tree_hash()),
            uint64(1),
        ),
        result_authorization_inner_puzzle=result_authorization_inner,
        offer_coin=(
            Coin(receipt_coin.name(), bytes32(OFFER_MOD_HASH), uint64(1))
            if action == VoucherAction.REDEEM
            else None
        ),
        next_series_state=next_state,
        transition_context=context,
        validator_message=validator_message,
        external_settlement_evidence_hash=external_settlement_evidence_hash,
        receipt_settlement_message=settlement_message,
    )


def build_voucher_series_phase_spend(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    series_lineage_proof: LineageProof,
    transition: SeriesTransition,
    launch_anchor: int,
    signer_indices: Sequence[int],
) -> VoucherSeriesPhaseSpendV2:
    """Build one validator-governed PRESALE -> LIVE/CANCELED transition."""
    if transition not in {SeriesTransition.LAUNCH, SeriesTransition.CANCEL}:
        raise VoucherV2Error("series phase spend must launch or cancel")
    if transition == SeriesTransition.CANCEL and launch_anchor != 0:
        raise VoucherV2Error("canceled series cannot carry a launch anchor")
    context = VoucherTransitionContextV2(
        transition=transition,
        action=VoucherAction.NONE,
        voucher_commitment_hash=bytes32.zeros,
        global_payment_id=bytes32.zeros,
        escrow_coin_id=bytes32.zeros,
        launch_anchor=launch_anchor,
    )
    next_state = next_series_state(terms, state, context)
    current_inner = curry_series(terms, state)
    current_full = puzzle_for_singleton(terms.series_singleton_id, current_inner)
    if (
        series_coin.puzzle_hash != current_full.get_tree_hash()
        or int(series_coin.amount) != 1
    ):
        raise VoucherV2Error("current series coin does not match its committed state")
    next_inner = curry_series(terms, next_state)
    next_full = puzzle_for_singleton(terms.series_singleton_id, next_inner)
    spend = make_spend(
        series_coin,
        current_full,
        solution_for_singleton(
            series_lineage_proof,
            series_coin.amount,
            series_solution(
                coin=series_coin,
                inner_puzzle_hash=bytes32(current_inner.get_tree_hash()),
                context=context,
                signer_indices=signer_indices,
            ),
        ),
    )
    return VoucherSeriesPhaseSpendV2(
        series_spend=spend,
        next_series_coin=Coin(
            series_coin.name(),
            bytes32(next_full.get_tree_hash()),
            uint64(1),
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


def prepare_xch_voucher_offer(
    *,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2,
    payment_coin: Coin,
    payment_public_key: bytes,
) -> PreparedXchVoucherOfferV2:
    """Build the one-signature XCH offer half for an atomic voucher sale."""
    if len(payment_public_key) != 48:
        raise VoucherV2Error("payment public key must be 48 bytes")
    try:
        payment_puzzle = puzzle_for_pk(G1Element.from_bytes(payment_public_key))
    except ValueError as exc:
        raise VoucherV2Error("payment public key is invalid") from exc
    if payment_coin.puzzle_hash != payment_puzzle.get_tree_hash():
        raise VoucherV2Error("XCH payment coin does not belong to payment public key")
    payment_commitment = curry_xch_escrow(
        terms=terms,
        voucher=voucher,
        purchase=purchase,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=terms,
        voucher=voucher,
        payment_puzzle_hash=bytes32(payment_commitment.get_tree_hash()),
        payment_amount=voucher.payment_principal,
    )
    launcher_amount = voucher.payment_principal + 1
    if int(payment_coin.amount) < launcher_amount:
        raise VoucherV2Error("XCH payment coin cannot cover principal plus voucher mojo")
    launcher_coin = Coin(
        payment_coin.name(),
        bytes32(launcher_puzzle.get_tree_hash()),
        launcher_amount,
    )
    issuance = build_voucher_issuance_spends(
        terms=terms,
        state=state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(bytes32.zeros, None, uint64(1)),
        voucher=voucher,
        purchase_launcher_coin=launcher_coin,
        payment_puzzle=payment_commitment,
        payment_amount=voucher.payment_principal,
        signer_indices=(0, 1),
    )
    conditions = [
        Program.to(
            [
                ConditionOpcode.CREATE_COIN,
                launcher_coin.puzzle_hash,
                launcher_amount,
                [terms.terms_hash, voucher.commitment_hash, voucher.global_payment_id],
            ]
        ),
        Program.to(
            [
                ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT,
                bytes32(
                    hashlib.sha256(
                        bytes(launcher_coin.name()) + bytes(issuance.validator_message)
                    ).digest()
                ),
            ]
        ),
    ]
    change = int(payment_coin.amount) - launcher_amount
    if change:
        conditions.append(
            Program.to(
                [
                    ConditionOpcode.CREATE_COIN,
                    payment_coin.puzzle_hash,
                    change,
                    [payment_coin.puzzle_hash],
                ]
            )
        )
    spend = make_spend(
        payment_coin,
        payment_puzzle,
        solution_for_conditions([item.as_python() for item in conditions]),
    )
    offer = Offer({}, WalletSpendBundle([spend], G2Element()), {})
    validate_xch_voucher_offer(
        buyer_offer=offer,
        terms=terms,
        state=state,
        series_coin=series_coin,
        voucher=voucher,
        purchase=purchase,
    )
    return PreparedXchVoucherOfferV2(offer, spend, launcher_coin)


def validate_xch_voucher_offer(
    *,
    buyer_offer: Offer,
    terms: VoucherSeriesTermsV2,
    state: VoucherSeriesStateV2,
    series_coin: Coin,
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2,
) -> Coin:
    """Validate a signed or unsigned wallet half and return its launcher coin."""
    if buyer_offer.requested_payments or buyer_offer.driver_dict:
        raise VoucherV2Error("voucher offer cannot request another asset")
    spends = buyer_offer.coin_spends()
    if len(spends) != 1 or buyer_offer.fees() != 0:
        raise VoucherV2Error("voucher offer must use one zero-fee XCH input")
    spend = spends[0]
    if spend.puzzle_reveal.get_tree_hash() != spend.coin.puzzle_hash:
        raise VoucherV2Error("voucher offer puzzle reveal does not match payment coin")
    payment_commitment = curry_xch_escrow(
        terms=terms,
        voucher=voucher,
        purchase=purchase,
    )
    launcher_puzzle = curry_purchase_launcher(
        terms=terms,
        voucher=voucher,
        payment_puzzle_hash=bytes32(payment_commitment.get_tree_hash()),
        payment_amount=voucher.payment_principal,
    )
    launcher_amount = voucher.payment_principal + 1
    launcher_coin = Coin(
        spend.coin.name(), bytes32(launcher_puzzle.get_tree_hash()), launcher_amount
    )
    issuance = build_voucher_issuance_spends(
        terms=terms,
        state=state,
        series_coin=series_coin,
        series_lineage_proof=LineageProof(bytes32.zeros, None, uint64(1)),
        voucher=voucher,
        purchase_launcher_coin=launcher_coin,
        payment_puzzle=payment_commitment,
        payment_amount=voucher.payment_principal,
        signer_indices=(0, 1),
    )
    expected_announcement = bytes32(
        hashlib.sha256(
            bytes(launcher_coin.name()) + bytes(issuance.validator_message)
        ).digest()
    )
    try:
        puzzle_reveal = Program.from_bytes(bytes(spend.puzzle_reveal))
        solution = Program.from_bytes(bytes(spend.solution))
        _, condition_program = puzzle_reveal.run_with_cost(
            INFINITE_COST,
            solution,
        )
        raw_conditions = condition_program.as_python()
        conditions = conditions_dict_for_solution(
            puzzle_reveal,
            solution,
            INFINITE_COST,
        )
    except Exception as exc:  # noqa: BLE001
        raise VoucherV2Error("voucher offer conditions are invalid") from exc
    if not isinstance(raw_conditions, list) or any(
        not isinstance(row, list) or not row or not isinstance(row[0], bytes)
        for row in raw_conditions
    ):
        raise VoucherV2Error("voucher offer conditions are malformed")
    expected_outputs = [
        (
            bytes(launcher_coin.puzzle_hash),
            launcher_amount,
            [
                bytes(terms.terms_hash),
                bytes(voucher.commitment_hash),
                bytes(voucher.global_payment_id),
            ],
        )
    ]
    change = int(spend.coin.amount) - launcher_amount
    if change < 0:
        raise VoucherV2Error("voucher offer payment input is too small")
    if change:
        expected_outputs.append(
            (bytes(spend.coin.puzzle_hash), change, [bytes(spend.coin.puzzle_hash)])
        )
    observed_outputs = []
    for row in raw_conditions:
        if row[0] != ConditionOpcode.CREATE_COIN.value:
            continue
        if (
            len(row) != 4
            or not isinstance(row[1], bytes)
            or not isinstance(row[2], bytes)
            or not isinstance(row[3], list)
            or any(not isinstance(memo, bytes) for memo in row[3])
        ):
            raise VoucherV2Error("voucher offer CREATE_COIN is malformed")
        observed_outputs.append(
            (bytes(row[1]), int.from_bytes(row[2], "big"), list(row[3]))
        )
    if observed_outputs != expected_outputs:
        raise VoucherV2Error("voucher offer changes payment, change, or commitments")
    announcements = conditions.get(ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT, [])
    if len(announcements) != 1 or bytes(announcements[0].vars[0]) != bytes(
        expected_announcement
    ):
        raise VoucherV2Error("voucher offer is not atomically bound to issuance")
    allowed = {
        ConditionOpcode.CREATE_COIN.value,
        ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT.value,
        ConditionOpcode.AGG_SIG_ME.value,
    }
    if any(row[0] not in allowed for row in raw_conditions):
        raise VoucherV2Error("voucher offer contains unsupported conditions")
    return launcher_coin


def _assert_voucher_matches_terms(
    terms: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
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
        raise VoucherV2Error("voucher differs from series terms")


def _assert_base_voucher_matches_purchase(
    voucher: VoucherCommitmentV2,
    purchase: PurchaseArtifactV2,
) -> None:
    if (
        voucher.payment_rail != VoucherPaymentRail.BASE_SEPOLIA_USDC
        or purchase.rail != PaymentRail.EVM_TEST_USD
        or voucher.payment_chain_id != 84532
        or purchase.rail_chain_id != 84532
        or voucher.payment_asset_id != BASE_SEPOLIA_USDC_ASSET_ID
        or purchase.rail_asset_id != BASE_SEPOLIA_USDC_ASSET_ID
        or voucher.payment_asset_decimals != 6
        or purchase.rail_asset_decimals != 6
    ):
        raise PaymentArtifactError(
            "Base voucher requires official six-decimal Base Sepolia USDC"
        )
    comparisons = (
        (purchase.collection_id, voucher.collection_id),
        (purchase.deed_launcher_id, voucher.deed_launcher_id),
        (purchase.metadata_root, voucher.metadata_root),
        (purchase.vault_launcher_id, voucher.approved_vault_launcher_id),
        (purchase.vault_p2_puzzle_hash, voucher.approved_vault_p2_puzzle_hash),
    )
    if any(left != right for left, right in comparisons):
        raise PaymentArtifactError("purchase artifact differs from voucher commitments")
    if (
        purchase.usd_amount_minor != voucher.gross_price_minor
        or purchase.rail_amount != voucher.payment_principal
        or purchase.artifact_hash != voucher.purchase_artifact_hash
    ):
        raise PaymentArtifactError("purchase price differs from voucher commitments")


def _signer_indices(values: Sequence[int]) -> tuple[int, ...]:
    result = tuple(values)
    if (
        len(result) < 2
        or tuple(sorted(result)) != result
        or len(set(result)) != len(result)
        or any(value < 0 or value > 2 for value in result)
    ):
        raise VoucherV2Error("signer indices require two unique sorted values in 0..2")
    return result


def _uint64(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise VoucherV2Error(f"{name} must be uint64")


__all__ = [
    "SeriesTransition",
    "VoucherAction",
    "VoucherSeriesStateV2",
    "VoucherTransitionContextV2",
    "VoucherIssuanceSpendsV2",
    "VoucherSeriesPhaseSpendV2",
    "VoucherTerminalSpendsV2",
    "BaseVoucherTerminalSpendsV2",
    "PreparedXchVoucherOfferV2",
    "burn_inner_hash",
    "build_voucher_issuance_spends",
    "build_voucher_series_phase_spend",
    "build_xch_voucher_terminal_spends",
    "base_result_authorization_mod",
    "base_result_message",
    "build_base_voucher_terminal_spends",
    "prepare_xch_voucher_offer",
    "validate_xch_voucher_offer",
    "curry_series",
    "curry_external_receipt",
    "curry_base_result_authorization",
    "external_receipt_evidence_message",
    "external_receipt_settlement_message",
    "curry_purchase_launcher",
    "curry_voucher_inner",
    "curry_xch_escrow",
    "escrow_solution",
    "external_receipt_solution",
    "issuance_coin_ids",
    "next_series_state",
    "series_solution",
    "transition_message",
    "purchase_launcher_solution",
    "voucher_solution",
]
