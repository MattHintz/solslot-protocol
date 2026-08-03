"""RC25 governed-asset receipt and primary SmartDeed delivery drivers."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    solution_for_singleton,
)
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.cat_wallet.cat_utils import (
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk,
    solution_for_conditions,
)
from chia_rs import G1Element, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import PaymentArtifactError, PaymentRail
from solslot_puzzles.payment_artifacts_v3 import (
    ExternalSettlementReceiptV1,
    PurchaseArtifactV3,
    PurchaseBatchSettlementReceiptV1,
    PurchaseBatchV1,
    PurchaseDeliveryKind,
    StripeSettlementReceiptV1,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    ChiaPrimaryOffer,
    PreparedChiaBuyerOffer,
    PrimaryPurchaseMode,
    chia_cat_driver,
    smart_deed_singleton_driver,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


PRIMARY_PURCHASE_PROVIDER_ID = bytes32(
    hashlib.sha256(b"SOLSLOT_H_SYSTEM_PRIMARY_PURCHASE_V3").digest()
)
PROVIDER_COUNT = 3
PROVIDER_THRESHOLD = 2
STRIPE_EXTERNAL_MODE = 3
RESERVATION_RELEASE_TIMEOUT_MODE = 4
RESERVATION_RELEASE_FAILURE_MODE = 5
RESERVATION_EXTEND_MODE = 6
MAX_RESERVATION_EXTENSION_SECONDS = 11 * 24 * 60 * 60
_STRIPE_SETTLEMENT_DOMAIN = b"SOLSLOT_STRIPE_RECEIPT_SETTLEMENT_V1"

# chia_rs ``Program`` values own thread-affine LazyNodes.  API request tests
# and production workers may call this driver from different threads, so keep
# only immutable serialized puzzle bytes at module scope and reconstruct the
# Program in the calling thread.
_MINT_OFFER_V5_MOD_BYTES = bytes(load_puzzle("mint_offer_delegate_v5.clsp"))
_INVENTORY_AVAILABLE_MOD_BYTES = bytes(
    load_puzzle("mint_offer_inventory_available_v1.clsp")
)
_STRIPE_RECEIPT_MOD_BYTES = bytes(
    load_puzzle("stripe_settlement_receipt_v1.clsp")
)
_PURCHASE_BATCH_RECEIPT_MOD_BYTES = bytes(
    load_puzzle("purchase_batch_settlement_receipt_v1.clsp")
)
_P2_VAULT_MOD_HASH = bytes32(load_puzzle("p2_vault.clsp").get_tree_hash())


def deed_launcher_puzzle_hash_from_struct(
    deed_singleton_struct: Program,
    deed_launcher_id: bytes32,
) -> bytes32:
    """Return and validate the launcher hash committed by a deed singleton.

    SmartDeeds use the DID-authorized launcher, not Chia's standard singleton
    launcher.  Offer drivers must carry this exact hash or settlement creates
    a different, unusable singleton puzzle.
    """

    try:
        mod_hash, launcher = deed_singleton_struct.as_python()
        launcher_id, launcher_puzzle_hash = launcher
        mod_hash = bytes32(mod_hash)
        launcher_id = bytes32(launcher_id)
        launcher_puzzle_hash = bytes32(launcher_puzzle_hash)
    except (TypeError, ValueError) as exc:
        raise PaymentArtifactError(
            "deed singleton struct is malformed"
        ) from exc
    if mod_hash != SINGLETON_MOD_HASH or launcher_id != deed_launcher_id:
        raise PaymentArtifactError(
            "deed singleton struct does not match its launcher"
        )
    if launcher_puzzle_hash in {bytes32.zeros, SINGLETON_LAUNCHER_HASH}:
        raise PaymentArtifactError(
            "governed SmartDeed must use its DID-authorized launcher"
        )
    return launcher_puzzle_hash


def _smart_deed_driver(
    terms: "PrimaryMintTermsV3",
    deed_singleton_struct: Program,
):
    launcher_hash = deed_launcher_puzzle_hash_from_struct(
        deed_singleton_struct,
        terms.deed_launcher_id,
    )
    if launcher_hash != terms.deed_launcher_puzzle_hash:
        raise PaymentArtifactError(
            "deed singleton struct does not match governed mint terms"
        )
    return smart_deed_singleton_driver(terms.deed_launcher_id, launcher_hash)


@dataclass(frozen=True)
class PrimaryMintTermsV3:
    network: str
    smart_deed_inner_hash: bytes32
    deed_launcher_id: bytes32
    deed_launcher_puzzle_hash: bytes32
    collection_id: bytes32
    metadata_root: bytes32
    metadata_anchor_id: bytes32
    share_ppm: int
    base_amount_minor: int
    technology_fee_bps: int
    technology_fee_minor: int
    subtotal_minor: int
    protocol_treasury_puzzle_hash: bytes32
    protocol_puzhash: bytes32
    validator_pubkeys: tuple[bytes, bytes, bytes]
    provider_id: bytes32 = PRIMARY_PURCHASE_PROVIDER_ID

    def __post_init__(self) -> None:
        if not self.network or len(self.network.encode("ascii")) > 32:
            raise PaymentArtifactError("network must be 1-32 ASCII bytes")
        for name in (
            "smart_deed_inner_hash",
            "deed_launcher_id",
            "deed_launcher_puzzle_hash",
            "collection_id",
            "metadata_root",
            "metadata_anchor_id",
            "protocol_treasury_puzzle_hash",
            "protocol_puzhash",
            "provider_id",
        ):
            _require_bytes32(getattr(self, name), name)
        if self.deed_launcher_puzzle_hash in {
            bytes32.zeros,
            SINGLETON_LAUNCHER_HASH,
        }:
            raise PaymentArtifactError(
                "governed SmartDeed must use its DID-authorized launcher"
            )
        if len(self.validator_pubkeys) != PROVIDER_COUNT:
            raise PaymentArtifactError("exactly three validators are required")
        if any(len(key) != 48 for key in self.validator_pubkeys):
            raise PaymentArtifactError("validator public keys must be 48 bytes")
        if len(set(self.validator_pubkeys)) != PROVIDER_COUNT:
            raise PaymentArtifactError("validator public keys must be unique")

    @classmethod
    def for_artifact(
        cls,
        *,
        artifact: PurchaseArtifactV3,
        smart_deed_inner_hash: bytes32,
        deed_launcher_puzzle_hash: bytes32,
        protocol_puzhash: bytes32,
        validator_pubkeys: tuple[bytes, bytes, bytes],
        provider_id: bytes32 = PRIMARY_PURCHASE_PROVIDER_ID,
    ) -> "PrimaryMintTermsV3":
        return cls(
            network=artifact.network,
            smart_deed_inner_hash=smart_deed_inner_hash,
            deed_launcher_id=artifact.deed_launcher_id,
            deed_launcher_puzzle_hash=deed_launcher_puzzle_hash,
            collection_id=artifact.collection_id,
            metadata_root=artifact.metadata_root,
            metadata_anchor_id=artifact.metadata_anchor_id,
            share_ppm=artifact.share_ppm,
            base_amount_minor=artifact.base_amount_minor,
            technology_fee_bps=artifact.technology_fee_bps,
            technology_fee_minor=artifact.technology_fee_minor,
            subtotal_minor=artifact.subtotal_minor,
            protocol_treasury_puzzle_hash=(
                artifact.protocol_treasury_puzzle_hash
            ),
            protocol_puzhash=protocol_puzhash,
            validator_pubkeys=validator_pubkeys,
            provider_id=provider_id,
        )


@dataclass(frozen=True)
class InventoryReservationV1:
    artifact: PurchaseArtifactV3
    expires_at: int

    def __post_init__(self) -> None:
        if self.expires_at <= 0 or self.expires_at > 0xFFFFFFFFFFFFFFFF:
            raise PaymentArtifactError(
                "reservation expiry must be a positive uint64"
            )


@dataclass(frozen=True)
class InventoryReservationSpendV1:
    spend: CoinSpend
    reserved_coin: Coin
    reservation: InventoryReservationV1
    validator_message: bytes32


@dataclass(frozen=True)
class InventoryTransitionSpendV1:
    spend: CoinSpend
    next_coin: Coin
    validator_message: bytes32 | None


@dataclass(frozen=True)
class ChiaPrimaryBatchOffer:
    """One atomic native checkout for multiple unique SmartDeeds."""

    buyer_offer: Offer
    issuer_offers: tuple[Offer, ...]
    aggregate_offer: Offer
    deed_spends: tuple[CoinSpend, ...]


ExternalReceiptV1 = StripeSettlementReceiptV1 | ExternalSettlementReceiptV1


@dataclass(frozen=True)
class StripeSettlementTermsV1:
    """Exact validator receipt terms for Stripe or Base Sepolia USDC."""

    receipt: ExternalReceiptV1
    validator_pubkeys: tuple[bytes, bytes, bytes]

    def __post_init__(self) -> None:
        validator_roster_root(self.validator_pubkeys)
        artifact = self.receipt.artifact
        result_hash = self.receipt.result_authorization_puzzle_hash
        if artifact.rail == PaymentRail.EVM_TEST_USD:
            if result_hash == bytes32.zeros:
                raise PaymentArtifactError(
                    "Base settlement requires a result authorization puzzle"
                )
        elif artifact.rail == PaymentRail.STRIPE:
            if result_hash != bytes32.zeros:
                raise PaymentArtifactError(
                    "Stripe settlement cannot carry a Base result puzzle"
                )
        else:
            raise PaymentArtifactError(
                "external receipt requires Stripe or Base Sepolia USDC"
            )


@dataclass(frozen=True)
class PurchaseBatchSettlementTermsV1:
    receipt: PurchaseBatchSettlementReceiptV1
    validator_pubkeys: tuple[bytes, bytes, bytes]

    def __post_init__(self) -> None:
        if self.receipt.validator_roster_root != validator_roster_root(
            self.validator_pubkeys
        ):
            raise PaymentArtifactError(
                "batch receipt validator roster does not match configured validators"
            )


def mint_offer_delegate_v5_mod() -> Program:
    return Program.from_bytes(_MINT_OFFER_V5_MOD_BYTES)


def mint_offer_delegate_v5_mod_hash() -> bytes32:
    return bytes32(mint_offer_delegate_v5_mod().get_tree_hash())


def mint_offer_inventory_available_v1_mod() -> Program:
    return Program.from_bytes(_INVENTORY_AVAILABLE_MOD_BYTES)


def mint_offer_inventory_available_v1_mod_hash() -> bytes32:
    return bytes32(mint_offer_inventory_available_v1_mod().get_tree_hash())


def stripe_settlement_receipt_v1_mod() -> Program:
    return Program.from_bytes(_STRIPE_RECEIPT_MOD_BYTES)


def stripe_settlement_receipt_v1_mod_hash() -> bytes32:
    return bytes32(stripe_settlement_receipt_v1_mod().get_tree_hash())


def purchase_batch_settlement_receipt_v1_mod() -> Program:
    return Program.from_bytes(_PURCHASE_BATCH_RECEIPT_MOD_BYTES)


def purchase_batch_settlement_receipt_v1_mod_hash() -> bytes32:
    return bytes32(purchase_batch_settlement_receipt_v1_mod().get_tree_hash())


def validator_roster_root(pubkeys: Sequence[bytes]) -> bytes32:
    values = tuple(bytes(value) for value in pubkeys)
    if len(values) != PROVIDER_COUNT:
        raise PaymentArtifactError("exactly three validators are required")
    if any(len(value) != 48 for value in values):
        raise PaymentArtifactError("validator public keys must be 48 bytes")
    if len(set(values)) != PROVIDER_COUNT:
        raise PaymentArtifactError("validator public keys must be unique")
    return bytes32(Program.to(list(values)).get_tree_hash())


def _receipt_evidence_hash(receipt: ExternalReceiptV1) -> bytes32:
    if isinstance(receipt, StripeSettlementReceiptV1):
        return receipt.evidence.evidence_hash
    return receipt.evidence_hash


def _receipt_observed_at(receipt: ExternalReceiptV1) -> int:
    if isinstance(receipt, StripeSettlementReceiptV1):
        return receipt.evidence.observed_at
    return receipt.observed_at


def curry_stripe_settlement_receipt(
    terms: StripeSettlementTermsV1,
) -> Program:
    receipt = terms.receipt
    artifact = receipt.artifact
    if isinstance(receipt, StripeSettlementReceiptV1):
        if receipt.validator_roster_root != validator_roster_root(
            terms.validator_pubkeys
        ):
            raise PaymentArtifactError(
                "receipt validator roster does not match configured validators"
            )
    return stripe_settlement_receipt_v1_mod().curry(
        artifact.artifact_hash,
        artifact.purchase_id,
        receipt.receipt_hash,
        _receipt_evidence_hash(receipt),
        receipt.attestation.attestation_hash,
        int(artifact.rail),
        int(artifact.delivery_kind),
        artifact.delivery_asset_id,
        artifact.delivery_amount,
        artifact.delivery_context_hash,
        artifact.vault_launcher_id,
        artifact.vault_p2_puzzle_hash,
        artifact.zkpassport_root,
        artifact.technology_fee_minor,
        artifact.rail_amount,
        artifact.protocol_treasury_puzzle_hash,
        _receipt_observed_at(receipt),
        receipt.expires_at,
        receipt.result_authorization_puzzle_hash,
        list(terms.validator_pubkeys),
        OFFER_MOD_HASH,
    )


def make_stripe_receipt_puzzle(
    *,
    receipt: StripeSettlementReceiptV1,
    validator_pubkeys: tuple[bytes, bytes, bytes],
) -> Program:
    return curry_stripe_settlement_receipt(
        StripeSettlementTermsV1(
            receipt=receipt,
            validator_pubkeys=validator_pubkeys,
        )
    )


def build_stripe_receipt_spend(
    *,
    receipt_coin: Coin,
    receipt: StripeSettlementReceiptV1,
    validator_pubkeys: tuple[bytes, bytes, bytes],
    signer_indices: Sequence[int],
) -> CoinSpend:
    receipt.assert_live(receipt.evidence.observed_at)
    return build_external_receipt_spend(
        receipt_coin=receipt_coin,
        terms=StripeSettlementTermsV1(
            receipt=receipt,
            validator_pubkeys=validator_pubkeys,
        ),
        signer_indices=signer_indices,
    )


def build_external_receipt_spend(
    *,
    receipt_coin: Coin,
    terms: StripeSettlementTermsV1,
    signer_indices: Sequence[int],
) -> CoinSpend:
    """Spend one exact Stripe or Base receipt with two validators."""

    indices = _validate_signer_indices(signer_indices)
    puzzle = curry_stripe_settlement_receipt(terms)
    if receipt_coin.amount != 1:
        raise PaymentArtifactError(
            "external settlement receipt coin must be one mojo"
        )
    if receipt_coin.puzzle_hash != puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "receipt coin does not match the authenticated settlement"
        )
    return make_spend(
        receipt_coin,
        puzzle,
        Program.to(
            [
                receipt_coin.name(),
                receipt_coin.parent_coin_info,
                receipt_coin.puzzle_hash,
                receipt_coin.amount,
                list(indices),
            ]
        ),
    )


def stripe_settlement_receipt_solution(
    *,
    receipt_coin: Coin,
    signer_indices: Sequence[int],
) -> Program:
    if receipt_coin.amount != 1:
        raise PaymentArtifactError(
            "external settlement receipt coin must be one mojo"
        )
    return Program.to(
        [
            receipt_coin.name(),
            receipt_coin.parent_coin_info,
            receipt_coin.puzzle_hash,
            receipt_coin.amount,
            list(_validate_signer_indices(signer_indices)),
        ]
    )


def curry_purchase_batch_settlement_receipt(
    terms: PurchaseBatchSettlementTermsV1,
) -> Program:
    receipt = terms.receipt
    batch = receipt.batch
    children = [
        [
            artifact.artifact_hash,
            artifact.purchase_id,
            artifact.deed_launcher_id,
            artifact.collection_id,
        ]
        for artifact in batch.artifacts
    ]
    return purchase_batch_settlement_receipt_v1_mod().curry(
        batch.batch_hash,
        batch.purchase_id,
        receipt.receipt_hash,
        receipt.evidence_hash,
        receipt.attestation.attestation_hash,
        int(batch.rail),
        batch.quantity,
        batch.vault_launcher_id,
        batch.vault_p2_puzzle_hash,
        batch.zkpassport_root,
        batch.total_technology_fee_minor,
        batch.total_rail_amount,
        receipt.collected_amount_minor,
        receipt.processing_charge_minor,
        batch.protocol_treasury_puzzle_hash,
        receipt.observed_at,
        receipt.expires_at,
        receipt.result_authorization_puzzle_hash,
        children,
        list(terms.validator_pubkeys),
        OFFER_MOD_HASH,
    )


def build_purchase_batch_receipt_spend(
    *,
    receipt_coin: Coin,
    terms: PurchaseBatchSettlementTermsV1,
    signer_indices: Sequence[int],
) -> CoinSpend:
    """Spend one exact N-mojo batch receipt with two validators."""

    receipt = terms.receipt
    receipt.assert_live(receipt.observed_at)
    indices = _validate_signer_indices(signer_indices)
    puzzle = curry_purchase_batch_settlement_receipt(terms)
    if int(receipt_coin.amount) != receipt.batch.quantity:
        raise PaymentArtifactError(
            "batch receipt coin amount must equal the exact deed quantity"
        )
    if receipt_coin.puzzle_hash != puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "batch receipt coin does not match the authenticated settlement"
        )
    return make_spend(
        receipt_coin,
        puzzle,
        Program.to(
            [
                receipt_coin.name(),
                receipt_coin.parent_coin_info,
                receipt_coin.puzzle_hash,
                receipt_coin.amount,
                list(indices),
            ]
        ),
    )


def _mint_immutable_args(terms: PrimaryMintTermsV3) -> tuple[object, ...]:
    return (
        terms.smart_deed_inner_hash,
        _P2_VAULT_MOD_HASH,
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
        terms.deed_launcher_puzzle_hash,
        bytes32(CAT_MOD.get_tree_hash()),
        OFFER_MOD_HASH,
        terms.network.encode("ascii"),
        terms.deed_launcher_id,
        terms.collection_id,
        terms.metadata_root,
        terms.metadata_anchor_id,
        terms.share_ppm,
        terms.base_amount_minor,
        terms.technology_fee_bps,
        terms.technology_fee_minor,
        terms.subtotal_minor,
        terms.protocol_treasury_puzzle_hash,
        terms.protocol_puzhash,
        list(terms.validator_pubkeys),
        terms.provider_id,
    )


def make_inventory_available_inner(terms: PrimaryMintTermsV3) -> Program:
    mod = mint_offer_inventory_available_v1_mod()
    return mod.curry(
        bytes32(mod.get_tree_hash()),
        mint_offer_delegate_v5_mod_hash(),
        *_mint_immutable_args(terms),
    )


def make_mint_offer_v5_inner(
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> Program:
    assert_artifact_matches_terms(reservation.artifact, terms)
    mod = mint_offer_delegate_v5_mod()
    artifact = reservation.artifact
    return mod.curry(
        bytes32(mod.get_tree_hash()),
        *_mint_immutable_args(terms),
        bytes32(make_inventory_available_inner(terms).get_tree_hash()),
        artifact.purchase_id,
        artifact.artifact_hash,
        artifact.vault_p2_puzzle_hash,
        artifact.zkpassport_root,
        int(artifact.rail),
        artifact.rail_amount,
        reservation.expires_at,
    )


def assert_artifact_matches_terms(
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
) -> None:
    expected = {
        "network": terms.network,
        "deed_launcher_id": terms.deed_launcher_id,
        "collection_id": terms.collection_id,
        "metadata_root": terms.metadata_root,
        "metadata_anchor_id": terms.metadata_anchor_id,
        "share_ppm": terms.share_ppm,
        "base_amount_minor": terms.base_amount_minor,
        "technology_fee_bps": terms.technology_fee_bps,
        "technology_fee_minor": terms.technology_fee_minor,
        "subtotal_minor": terms.subtotal_minor,
        "protocol_treasury_puzzle_hash": (
            terms.protocol_treasury_puzzle_hash
        ),
    }
    mismatches = [
        name for name, value in expected.items()
        if getattr(artifact, name) != value
    ]
    if mismatches:
        raise PaymentArtifactError(
            "purchase artifact does not match mint terms: "
            + ", ".join(mismatches)
        )
    if artifact.vault_p2_puzzle_hash != puzzle_hash_for_p2_vault(
        artifact.vault_launcher_id
    ):
        raise PaymentArtifactError(
            "purchase artifact vault puzzle hash is not canonical"
        )


def inventory_reservation_message(
    *,
    available_coin: Coin,
    reservation: InventoryReservationV1,
) -> bytes32:
    artifact = reservation.artifact
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_DEED_RESERVATION_V1",
                available_coin.name(),
                artifact.deed_launcher_id,
                artifact.artifact_hash,
                artifact.purchase_id,
                artifact.vault_p2_puzzle_hash,
                artifact.zkpassport_root,
                int(artifact.rail),
                artifact.rail_amount,
                reservation.expires_at,
            ]
        ).get_tree_hash()
    )


def build_inventory_reservation_spend(
    *,
    available_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    reservation: InventoryReservationV1,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
) -> InventoryReservationSpendV1:
    artifact = reservation.artifact
    assert_artifact_matches_terms(artifact, terms)
    if (
        reservation.expires_at > artifact.quote_expires_at
        or reservation.expires_at > artifact.authorization_expires_at
    ):
        raise PaymentArtifactError(
            "initial reservation cannot outlive the quote or authorization"
        )
    indices = _validate_signer_indices(signer_indices)
    available_inner = make_inventory_available_inner(terms)
    available_full = SINGLETON_MOD.curry(
        deed_singleton_struct,
        available_inner,
    )
    if (
        int(available_coin.amount) != 1
        or available_coin.puzzle_hash != available_full.get_tree_hash()
    ):
        raise PaymentArtifactError(
            "available SmartDeed coin does not match governed inventory terms"
        )
    reserved_inner = make_mint_offer_v5_inner(terms, reservation)
    reserved_full = SINGLETON_MOD.curry(
        deed_singleton_struct,
        reserved_inner,
    )
    spend = make_spend(
        available_coin,
        available_full,
        solution_for_singleton(
            lineage_proof,
            uint64(available_coin.amount),
            Program.to(
                [
                    available_coin.name(),
                    available_coin.parent_coin_info,
                    available_coin.puzzle_hash,
                    available_coin.amount,
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
                    reservation.expires_at,
                    list(indices),
                ]
            ),
        ),
    )
    reserved_coin = Coin(
        available_coin.name(),
        bytes32(reserved_full.get_tree_hash()),
        uint64(1),
    )
    return InventoryReservationSpendV1(
        spend=spend,
        reserved_coin=reserved_coin,
        reservation=reservation,
        validator_message=inventory_reservation_message(
            available_coin=available_coin,
            reservation=reservation,
        ),
    )


def inventory_release_message(
    *,
    reserved_coin: Coin,
    reservation: InventoryReservationV1,
) -> bytes32:
    artifact = reservation.artifact
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_DEED_RESERVATION_RELEASE_V1",
                RESERVATION_RELEASE_FAILURE_MODE,
                reserved_coin.name(),
                artifact.deed_launcher_id,
                artifact.purchase_id,
                artifact.artifact_hash,
                artifact.vault_p2_puzzle_hash,
                artifact.zkpassport_root,
                int(artifact.rail),
                artifact.rail_amount,
                reservation.expires_at,
            ]
        ).get_tree_hash()
    )


def inventory_extension_message(
    *,
    reserved_coin: Coin,
    reservation: InventoryReservationV1,
    next_expires_at: int,
) -> bytes32:
    artifact = reservation.artifact
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_DEED_RESERVATION_EXTEND_V1",
                reserved_coin.name(),
                artifact.deed_launcher_id,
                artifact.purchase_id,
                artifact.artifact_hash,
                artifact.vault_p2_puzzle_hash,
                artifact.zkpassport_root,
                int(artifact.rail),
                artifact.rail_amount,
                reservation.expires_at,
                next_expires_at,
            ]
        ).get_tree_hash()
    )


def _inventory_control_solution(
    *,
    reserved_coin: Coin,
    reservation: InventoryReservationV1,
    mode: int,
    next_expires_at: int,
    signer_indices: Sequence[int],
) -> Program:
    artifact = reservation.artifact
    return Program.to(
        [
            reserved_coin.name(),
            reserved_coin.parent_coin_info,
            reserved_coin.puzzle_hash,
            reserved_coin.amount,
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
            bytes32.zeros,
            mode,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            0,
            bytes32.zeros,
            next_expires_at,
            list(signer_indices),
        ]
    )


def build_inventory_release_spend(
    *,
    reserved_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    reservation: InventoryReservationV1,
    terms: PrimaryMintTermsV3,
    timed_out: bool,
    signer_indices: Sequence[int] = (),
) -> InventoryTransitionSpendV1:
    assert_artifact_matches_terms(reservation.artifact, terms)
    if timed_out:
        if signer_indices:
            raise PaymentArtifactError(
                "timeout release cannot carry validator signatures"
            )
        mode = RESERVATION_RELEASE_TIMEOUT_MODE
        indices: tuple[int, ...] = ()
        message = None
    else:
        mode = RESERVATION_RELEASE_FAILURE_MODE
        indices = _validate_signer_indices(signer_indices)
        message = inventory_release_message(
            reserved_coin=reserved_coin,
            reservation=reservation,
        )
    reserved_inner = make_mint_offer_v5_inner(terms, reservation)
    reserved_full = SINGLETON_MOD.curry(
        deed_singleton_struct,
        reserved_inner,
    )
    if (
        int(reserved_coin.amount) != 1
        or reserved_coin.puzzle_hash != reserved_full.get_tree_hash()
    ):
        raise PaymentArtifactError(
            "reserved SmartDeed coin does not match its reservation"
        )
    available_inner = make_inventory_available_inner(terms)
    available_full = SINGLETON_MOD.curry(
        deed_singleton_struct,
        available_inner,
    )
    spend = make_spend(
        reserved_coin,
        reserved_full,
        solution_for_singleton(
            lineage_proof,
            uint64(1),
            _inventory_control_solution(
                reserved_coin=reserved_coin,
                reservation=reservation,
                mode=mode,
                next_expires_at=0,
                signer_indices=indices,
            ),
        ),
    )
    return InventoryTransitionSpendV1(
        spend=spend,
        next_coin=Coin(
            reserved_coin.name(),
            bytes32(available_full.get_tree_hash()),
            uint64(1),
        ),
        validator_message=message,
    )


def build_inventory_extension_spend(
    *,
    reserved_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    reservation: InventoryReservationV1,
    next_expires_at: int,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
) -> InventoryTransitionSpendV1:
    if (
        next_expires_at <= reservation.expires_at
        or next_expires_at
        > reservation.expires_at + MAX_RESERVATION_EXTENSION_SECONDS
    ):
        raise PaymentArtifactError(
            "reservation extension must advance by at most eleven days"
        )
    indices = _validate_signer_indices(signer_indices)
    reserved_inner = make_mint_offer_v5_inner(terms, reservation)
    reserved_full = SINGLETON_MOD.curry(
        deed_singleton_struct,
        reserved_inner,
    )
    if (
        int(reserved_coin.amount) != 1
        or reserved_coin.puzzle_hash != reserved_full.get_tree_hash()
    ):
        raise PaymentArtifactError(
            "reserved SmartDeed coin does not match its reservation"
        )
    next_reservation = InventoryReservationV1(
        artifact=reservation.artifact,
        expires_at=next_expires_at,
    )
    next_inner = make_mint_offer_v5_inner(terms, next_reservation)
    next_full = SINGLETON_MOD.curry(deed_singleton_struct, next_inner)
    spend = make_spend(
        reserved_coin,
        reserved_full,
        solution_for_singleton(
            lineage_proof,
            uint64(1),
            _inventory_control_solution(
                reserved_coin=reserved_coin,
                reservation=reservation,
                mode=RESERVATION_EXTEND_MODE,
                next_expires_at=next_expires_at,
                signer_indices=indices,
            ),
        ),
    )
    return InventoryTransitionSpendV1(
        spend=spend,
        next_coin=Coin(
            reserved_coin.name(),
            bytes32(next_full.get_tree_hash()),
            uint64(1),
        ),
        validator_message=inventory_extension_message(
            reserved_coin=reserved_coin,
            reservation=reservation,
            next_expires_at=next_expires_at,
        ),
    )


def prepare_chia_buyer_offer_v3(
    *,
    payment_coin: Coin,
    payment_public_key: bytes,
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
    deed_singleton_struct: Program,
    cat_lineage_proof: LineageProof | None = None,
) -> PreparedChiaBuyerOffer:
    """Build the existing one-signature XCH/CAT offer for a V3 reservation."""

    assert_artifact_matches_terms(artifact, terms)
    if artifact.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError(
            "buyer offer preparation requires an XCH or CAT artifact"
        )
    if len(payment_public_key) != 48:
        raise PaymentArtifactError("payment_public_key must be 48 bytes")
    try:
        public_key = G1Element.from_bytes(payment_public_key)
    except ValueError as exc:
        raise PaymentArtifactError(
            "payment_public_key is not valid BLS"
        ) from exc
    if int(payment_coin.amount) < artifact.rail_amount:
        raise PaymentArtifactError(
            "payment coin is smaller than the H-system quote"
        )

    payment_puzzle = puzzle_for_pk(public_key)
    drivers = {
        artifact.deed_launcher_id: _smart_deed_driver(
            terms, deed_singleton_struct
        )
    }
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
    notarized = Offer.notarize_payments(requested, [payment_coin])
    announcements = Offer.calculate_announcements(notarized, drivers)
    conditions = [
        CreateCoin(
            OFFER_MOD_HASH,
            uint64(artifact.rail_amount),
            [OFFER_MOD_HASH],
        ).to_program(),
        *(announcement.to_program() for announcement in announcements),
    ]
    change = int(payment_coin.amount) - artifact.rail_amount
    if change:
        conditions.append(
            CreateCoin(
                bytes32(payment_puzzle.get_tree_hash()),
                uint64(change),
                [bytes32(payment_puzzle.get_tree_hash())],
            ).to_program()
        )
    inner_solution = solution_for_conditions(
        [condition.as_python() for condition in conditions]
    )

    if artifact.rail == PaymentRail.CHIA_XCH:
        if payment_coin.puzzle_hash != payment_puzzle.get_tree_hash():
            raise PaymentArtifactError(
                "XCH payment coin does not belong to payment_public_key"
            )
        coin_spend = make_spend(
            payment_coin,
            payment_puzzle,
            inner_solution,
        )
        bundle = WalletSpendBundle([coin_spend], G2Element())
    else:
        expected_cat_puzzle = construct_cat_puzzle(
            CAT_MOD,
            artifact.rail_asset_id,
            payment_puzzle,
        )
        if payment_coin.puzzle_hash != expected_cat_puzzle.get_tree_hash():
            raise PaymentArtifactError(
                "CAT payment coin does not belong to payment_public_key and asset"
            )
        if (
            cat_lineage_proof is None
            or cat_lineage_proof.parent_name is None
            or cat_lineage_proof.inner_puzzle_hash is None
            or cat_lineage_proof.amount is None
        ):
            raise PaymentArtifactError(
                "CAT payment coin requires a complete lineage proof"
            )
        drivers[artifact.rail_asset_id] = chia_cat_driver(
            artifact.rail_asset_id
        )
        bundle = unsigned_spend_bundle_for_spendable_cats(
            CAT_MOD,
            [
                SpendableCAT(
                    payment_coin,
                    artifact.rail_asset_id,
                    payment_puzzle,
                    inner_solution,
                    lineage_proof=cat_lineage_proof,
                )
            ],
        )
        coin_spend = bundle.coin_spends[0]

    offer = Offer(notarized, bundle, drivers)
    validate_chia_buyer_offer_v3(
        buyer_offer=offer,
        artifact=artifact,
        terms=terms,
        deed_singleton_struct=deed_singleton_struct,
    )
    return PreparedChiaBuyerOffer(
        offer=offer,
        coin_spend=coin_spend,
        payment_puzzle=payment_puzzle,
    )


def prepare_chia_buyer_batch_offer_v3(
    *,
    payment_coin: Coin,
    payment_public_key: bytes,
    batch: PurchaseBatchV1,
    terms: Sequence[PrimaryMintTermsV3],
    deed_singleton_structs: Sequence[Program],
    cat_lineage_proof: LineageProof | None = None,
) -> PreparedChiaBuyerOffer:
    """Build one wallet signature requesting every deed in a native batch."""

    artifacts = batch.artifacts
    if batch.delivery_kind != PurchaseDeliveryKind.SMARTDEED:
        raise PaymentArtifactError(
            "native SmartDeed batching cannot be used for fungible SGT"
        )
    if len(artifacts) != len(terms) or len(artifacts) != len(
        deed_singleton_structs
    ):
        raise PaymentArtifactError(
            "native batch terms must match every purchase artifact"
        )
    if artifacts[0].rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError("native batch requires XCH or CAT")
    for artifact, item_terms in zip(artifacts, terms, strict=True):
        assert_artifact_matches_terms(artifact, item_terms)
    if len(payment_public_key) != 48:
        raise PaymentArtifactError("payment_public_key must be 48 bytes")
    try:
        public_key = G1Element.from_bytes(payment_public_key)
    except ValueError as exc:
        raise PaymentArtifactError(
            "payment_public_key is not valid BLS"
        ) from exc
    if int(payment_coin.amount) < batch.total_rail_amount:
        raise PaymentArtifactError(
            "payment coin is smaller than the batched H-system quote"
        )

    first = artifacts[0]
    payment_puzzle = puzzle_for_pk(public_key)
    drivers = {
        artifact.deed_launcher_id: _smart_deed_driver(
            item_terms, deed_singleton_struct
        )
        for artifact, item_terms, deed_singleton_struct in zip(
            artifacts,
            terms,
            deed_singleton_structs,
            strict=True,
        )
    }
    requested = {
        artifact.deed_launcher_id: [
            CreateCoin(
                artifact.vault_p2_puzzle_hash,
                uint64(1),
                [
                    artifact.deed_launcher_id,
                    item_terms.smart_deed_inner_hash,
                    artifact.metadata_root,
                    artifact.purchase_id,
                    artifact.artifact_hash,
                ],
            )
        ]
        for artifact, item_terms in zip(artifacts, terms, strict=True)
    }
    notarized = Offer.notarize_payments(requested, [payment_coin])
    announcements = Offer.calculate_announcements(notarized, drivers)
    conditions = [
        CreateCoin(
            OFFER_MOD_HASH,
            uint64(batch.total_rail_amount),
            [OFFER_MOD_HASH],
        ).to_program(),
        *(announcement.to_program() for announcement in announcements),
    ]
    change = int(payment_coin.amount) - batch.total_rail_amount
    if change:
        conditions.append(
            CreateCoin(
                bytes32(payment_puzzle.get_tree_hash()),
                uint64(change),
                [bytes32(payment_puzzle.get_tree_hash())],
            ).to_program()
        )
    inner_solution = solution_for_conditions(
        [condition.as_python() for condition in conditions]
    )

    if first.rail == PaymentRail.CHIA_XCH:
        if payment_coin.puzzle_hash != payment_puzzle.get_tree_hash():
            raise PaymentArtifactError(
                "XCH payment coin does not belong to payment_public_key"
            )
        coin_spend = make_spend(payment_coin, payment_puzzle, inner_solution)
        bundle = WalletSpendBundle([coin_spend], G2Element())
    else:
        expected_cat_puzzle = construct_cat_puzzle(
            CAT_MOD,
            first.rail_asset_id,
            payment_puzzle,
        )
        if payment_coin.puzzle_hash != expected_cat_puzzle.get_tree_hash():
            raise PaymentArtifactError(
                "CAT payment coin does not belong to payment_public_key and asset"
            )
        if (
            cat_lineage_proof is None
            or cat_lineage_proof.parent_name is None
            or cat_lineage_proof.inner_puzzle_hash is None
            or cat_lineage_proof.amount is None
        ):
            raise PaymentArtifactError(
                "CAT payment coin requires a complete lineage proof"
            )
        drivers[first.rail_asset_id] = chia_cat_driver(first.rail_asset_id)
        bundle = unsigned_spend_bundle_for_spendable_cats(
            CAT_MOD,
            [
                SpendableCAT(
                    payment_coin,
                    first.rail_asset_id,
                    payment_puzzle,
                    inner_solution,
                    lineage_proof=cat_lineage_proof,
                )
            ],
        )
        coin_spend = bundle.coin_spends[0]

    offer = Offer(notarized, bundle, drivers)
    validate_chia_buyer_batch_offer_v3(
        buyer_offer=offer,
        batch=batch,
        terms=terms,
        deed_singleton_structs=deed_singleton_structs,
    )
    return PreparedChiaBuyerOffer(
        offer=offer,
        coin_spend=coin_spend,
        payment_puzzle=payment_puzzle,
    )


def validate_chia_buyer_batch_offer_v3(
    *,
    buyer_offer: Offer,
    batch: PurchaseBatchV1,
    terms: Sequence[PrimaryMintTermsV3],
    deed_singleton_structs: Sequence[Program],
) -> bytes32:
    """Validate all destinations and the exact aggregate native amount."""

    artifacts = batch.artifacts
    if (
        batch.delivery_kind != PurchaseDeliveryKind.SMARTDEED
        or len(artifacts) != len(terms)
        or len(artifacts) != len(deed_singleton_structs)
    ):
        raise PaymentArtifactError("buyer batch shape is invalid")
    requested = buyer_offer.requested_payments
    if set(requested) != {
        artifact.deed_launcher_id for artifact in artifacts
    }:
        raise PaymentArtifactError(
            "buyer batch must request exactly the committed SmartDeeds"
        )
    nonces: set[bytes32] = set()
    for artifact, item_terms, deed_singleton_struct in zip(
        artifacts,
        terms,
        deed_singleton_structs,
        strict=True,
    ):
        assert_artifact_matches_terms(artifact, item_terms)
        payments = requested[artifact.deed_launcher_id]
        if len(payments) != 1:
            raise PaymentArtifactError(
                "buyer batch must contain one destination per SmartDeed"
            )
        payment = payments[0]
        if (
            payment.puzzle_hash != artifact.vault_p2_puzzle_hash
            or int(payment.amount) != 1
            or list(payment.memos)
            != [
                artifact.deed_launcher_id,
                item_terms.smart_deed_inner_hash,
                artifact.metadata_root,
                artifact.purchase_id,
                artifact.artifact_hash,
            ]
        ):
            raise PaymentArtifactError(
                "buyer batch changes a SmartDeed destination or commitment"
            )
        nonces.add(bytes32(payment.nonce))
        expected_driver = _smart_deed_driver(
            item_terms, deed_singleton_struct
        )
        actual_driver = buyer_offer.driver_dict.get(artifact.deed_launcher_id)
        if actual_driver is None or actual_driver.info != expected_driver.info:
            raise PaymentArtifactError(
                "buyer batch uses an unexpected SmartDeed singleton driver"
            )
    if len(nonces) != 1:
        raise PaymentArtifactError(
            "buyer batch SmartDeeds must share one atomic offer nonce"
        )
    first = artifacts[0]
    payment_asset = (
        None if first.rail == PaymentRail.CHIA_XCH else first.rail_asset_id
    )
    offered = buyer_offer.get_offered_amounts()
    if (
        set(offered) != {payment_asset}
        or int(offered[payment_asset]) != batch.total_rail_amount
    ):
        raise PaymentArtifactError(
            "buyer batch must contain only the exact aggregate XCH or CAT payment"
        )
    if first.rail == PaymentRail.CHIA_CAT:
        expected_cat = chia_cat_driver(first.rail_asset_id)
        actual_cat = buyer_offer.driver_dict.get(first.rail_asset_id)
        if actual_cat is None or actual_cat.info != expected_cat.info:
            raise PaymentArtifactError(
                "buyer batch uses an unexpected CAT driver"
            )
    return next(iter(nonces))


def validate_chia_buyer_offer_v3(
    *,
    buyer_offer: Offer,
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
    deed_singleton_struct: Program,
) -> bytes32:
    """Validate the signed native half-offer against its exact reservation."""

    assert_artifact_matches_terms(artifact, terms)
    if artifact.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError(
            "buyer offer requires a native Chia payment artifact"
        )
    requested = buyer_offer.requested_payments
    if set(requested) != {artifact.deed_launcher_id}:
        raise PaymentArtifactError(
            "buyer offer must request only the governed SmartDeed"
        )
    payments = requested[artifact.deed_launcher_id]
    if len(payments) != 1:
        raise PaymentArtifactError(
            "buyer offer must contain one SmartDeed destination"
        )
    payment = payments[0]
    if (
        payment.puzzle_hash != artifact.vault_p2_puzzle_hash
        or int(payment.amount) != 1
        or list(payment.memos)
        != [
            artifact.deed_launcher_id,
            terms.smart_deed_inner_hash,
            artifact.metadata_root,
            artifact.purchase_id,
            artifact.artifact_hash,
        ]
    ):
        raise PaymentArtifactError(
            "buyer offer does not deliver the SmartDeed to the authorized vault"
        )
    payment_asset = (
        None
        if artifact.rail == PaymentRail.CHIA_XCH
        else artifact.rail_asset_id
    )
    offered = buyer_offer.get_offered_amounts()
    if (
        set(offered) != {payment_asset}
        or int(offered[payment_asset]) != artifact.rail_amount
    ):
        raise PaymentArtifactError(
            "buyer offer must contain only the exact quoted XCH or CAT payment"
        )
    expected_driver = _smart_deed_driver(terms, deed_singleton_struct)
    actual_driver = buyer_offer.driver_dict.get(artifact.deed_launcher_id)
    if actual_driver is None or actual_driver.info != expected_driver.info:
        raise PaymentArtifactError(
            "buyer offer uses an unexpected SmartDeed singleton driver"
        )
    if artifact.rail == PaymentRail.CHIA_CAT:
        expected_cat = chia_cat_driver(artifact.rail_asset_id)
        actual_cat = buyer_offer.driver_dict.get(artifact.rail_asset_id)
        if actual_cat is None or actual_cat.info != expected_cat.info:
            raise PaymentArtifactError(
                "buyer offer uses an unexpected CAT driver"
            )
    return bytes32(payment.nonce)


def native_offer_v5_solution(
    *,
    deed_coin: Coin,
    artifact: PurchaseArtifactV3,
    buyer_offer_nonce: bytes32,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> Program:
    assert_artifact_matches_terms(artifact, terms)
    if reservation.artifact != artifact:
        raise PaymentArtifactError(
            "native purchase differs from the active deed reservation"
        )
    if artifact.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError("native primary purchase requires XCH or CAT")
    indices = _validate_signer_indices(signer_indices)
    _require_bytes32(buyer_offer_nonce, "buyer_offer_nonce")
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
            int(PrimaryPurchaseMode.DIRECT),
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            bytes32.zeros,
            0,
            bytes32.zeros,
            0,
            list(indices),
        ]
    )


def build_native_mint_offer_v5_spend(
    *,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    artifact: PurchaseArtifactV3,
    buyer_offer_nonce: bytes32,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> CoinSpend:
    inner = make_mint_offer_v5_inner(terms, reservation)
    full_puzzle = SINGLETON_MOD.curry(deed_singleton_struct, inner)
    if deed_coin.puzzle_hash != full_puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "deed coin puzzle hash does not match its V3 reservation"
        )
    return make_spend(
        deed_coin,
        full_puzzle,
        solution_for_singleton(
            lineage_proof,
            uint64(deed_coin.amount),
            native_offer_v5_solution(
                deed_coin=deed_coin,
                artifact=artifact,
                buyer_offer_nonce=buyer_offer_nonce,
                signer_indices=signer_indices,
                terms=terms,
                reservation=reservation,
            ),
        ),
    )


def build_native_primary_offer_v5(
    *,
    buyer_offer: Offer,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    artifact: PurchaseArtifactV3,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> ChiaPrimaryOffer:
    """Add the exact reserved SmartDeed to a wallet-signed XCH/CAT offer."""

    buyer_offer_nonce = validate_chia_buyer_offer_v3(
        buyer_offer=buyer_offer,
        artifact=artifact,
        terms=terms,
        deed_singleton_struct=deed_singleton_struct,
    )
    deed_spend = build_native_mint_offer_v5_spend(
        deed_coin=deed_coin,
        deed_singleton_struct=deed_singleton_struct,
        lineage_proof=lineage_proof,
        artifact=artifact,
        buyer_offer_nonce=buyer_offer_nonce,
        signer_indices=signer_indices,
        terms=terms,
        reservation=reservation,
    )
    payment_asset = (
        None
        if artifact.rail == PaymentRail.CHIA_XCH
        else artifact.rail_asset_id
    )
    drivers = {
        artifact.deed_launcher_id: _smart_deed_driver(
            terms, deed_singleton_struct
        )
    }
    if artifact.rail == PaymentRail.CHIA_CAT:
        drivers[artifact.rail_asset_id] = chia_cat_driver(
            artifact.rail_asset_id
        )
    issuer_offer = Offer(
        Offer.notarize_payments(
            {
                payment_asset: [
                    CreateCoin(
                        terms.protocol_puzhash,
                        uint64(artifact.rail_amount),
                        [artifact.purchase_id, artifact.artifact_hash],
                    )
                ]
            },
            [deed_coin],
        ),
        WalletSpendBundle([deed_spend], G2Element()),
        drivers,
    )
    aggregate = Offer.aggregate([buyer_offer, issuer_offer])
    if not aggregate.is_valid():
        raise PaymentArtifactError(
            "buyer and issuer offer files do not balance exactly"
        )
    return ChiaPrimaryOffer(
        buyer_offer=buyer_offer,
        issuer_offer=issuer_offer,
        aggregate_offer=aggregate,
        deed_spend=deed_spend,
    )


def build_native_primary_batch_offer_v5(
    *,
    buyer_offer: Offer,
    batch: PurchaseBatchV1,
    deed_coins: Sequence[Coin],
    deed_singleton_structs: Sequence[Program],
    lineage_proofs: Sequence[LineageProof],
    signer_indices_by_artifact: Sequence[Sequence[int]],
    terms: Sequence[PrimaryMintTermsV3],
    reservations: Sequence[InventoryReservationV1],
) -> ChiaPrimaryBatchOffer:
    """Aggregate exact issuer halves with one signed native buyer offer."""

    artifacts = batch.artifacts
    lengths = {
        len(artifacts),
        len(deed_coins),
        len(deed_singleton_structs),
        len(lineage_proofs),
        len(signer_indices_by_artifact),
        len(terms),
        len(reservations),
    }
    if len(lengths) != 1:
        raise PaymentArtifactError(
            "native batch chain contexts must match every artifact"
        )
    buyer_offer_nonce = validate_chia_buyer_batch_offer_v3(
        buyer_offer=buyer_offer,
        batch=batch,
        terms=terms,
        deed_singleton_structs=deed_singleton_structs,
    )
    issuer_offers: list[Offer] = []
    deed_spends: list[CoinSpend] = []
    first = artifacts[0]
    payment_asset = (
        None if first.rail == PaymentRail.CHIA_XCH else first.rail_asset_id
    )
    for (
        artifact,
        deed_coin,
        singleton_struct,
        lineage_proof,
        item_signer_indices,
        item_terms,
        reservation,
    ) in zip(
        artifacts,
        deed_coins,
        deed_singleton_structs,
        lineage_proofs,
        signer_indices_by_artifact,
        terms,
        reservations,
        strict=True,
    ):
        deed_spend = build_native_mint_offer_v5_spend(
            deed_coin=deed_coin,
            deed_singleton_struct=singleton_struct,
            lineage_proof=lineage_proof,
            artifact=artifact,
            buyer_offer_nonce=buyer_offer_nonce,
            signer_indices=item_signer_indices,
            terms=item_terms,
            reservation=reservation,
        )
        drivers = {
            artifact.deed_launcher_id: _smart_deed_driver(
                item_terms, singleton_struct
            )
        }
        if first.rail == PaymentRail.CHIA_CAT:
            drivers[first.rail_asset_id] = chia_cat_driver(
                first.rail_asset_id
            )
        issuer_offers.append(
            Offer(
                Offer.notarize_payments(
                    {
                        payment_asset: [
                            CreateCoin(
                                item_terms.protocol_puzhash,
                                uint64(artifact.rail_amount),
                                [artifact.purchase_id, artifact.artifact_hash],
                            )
                        ]
                    },
                    [deed_coin],
                ),
                WalletSpendBundle([deed_spend], G2Element()),
                drivers,
            )
        )
        deed_spends.append(deed_spend)

    aggregate = Offer.aggregate([buyer_offer, *issuer_offers])
    if not aggregate.is_valid():
        raise PaymentArtifactError(
            "batched buyer and issuer offers do not balance exactly"
        )
    return ChiaPrimaryBatchOffer(
        buyer_offer=buyer_offer,
        issuer_offers=tuple(issuer_offers),
        aggregate_offer=aggregate,
        deed_spends=tuple(deed_spends),
    )


def stripe_offer_v5_solution(
    *,
    deed_coin: Coin,
    receipt_coin: Coin,
    receipt: ExternalReceiptV1,
    buyer_offer_nonce: bytes32,
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> Program:
    artifact = receipt.artifact
    assert_artifact_matches_terms(artifact, terms)
    if reservation.artifact != artifact:
        raise PaymentArtifactError(
            "Stripe receipt differs from the active deed reservation"
        )
    if artifact.rail not in {
        PaymentRail.STRIPE,
        PaymentRail.EVM_TEST_USD,
    }:
        raise PaymentArtifactError(
            "external primary purchase requires Stripe or Base USDC"
        )
    if artifact.delivery_kind != PurchaseDeliveryKind.SMARTDEED:
        raise PaymentArtifactError(
            "SmartDeed inventory cannot settle an SGT artifact"
        )
    _require_bytes32(buyer_offer_nonce, "buyer_offer_nonce")
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
            STRIPE_EXTERNAL_MODE,
            bytes32.zeros,
            bytes32.zeros,
            receipt_coin.name(),
            _receipt_evidence_hash(receipt),
            receipt.attestation.attestation_hash,
            receipt.receipt_hash,
            receipt.expires_at,
            receipt.result_authorization_puzzle_hash,
            0,
            [],
        ]
    )


def build_stripe_mint_offer_v5_spend(
    *,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    receipt_coin: Coin,
    receipt: ExternalReceiptV1,
    buyer_offer_nonce: bytes32,
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> CoinSpend:
    inner = make_mint_offer_v5_inner(terms, reservation)
    full_puzzle = SINGLETON_MOD.curry(deed_singleton_struct, inner)
    if deed_coin.puzzle_hash != full_puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "deed coin puzzle hash does not match mint offer v5"
        )
    return make_spend(
        deed_coin,
        full_puzzle,
        solution_for_singleton(
            lineage_proof,
            uint64(deed_coin.amount),
            stripe_offer_v5_solution(
                deed_coin=deed_coin,
                receipt_coin=receipt_coin,
                receipt=receipt,
                buyer_offer_nonce=buyer_offer_nonce,
                terms=terms,
                reservation=reservation,
            ),
        ),
    )


def prepare_stripe_receipt_offer(
    *,
    receipt_spend: CoinSpend,
    receipt: ExternalReceiptV1,
    terms: PrimaryMintTermsV3,
    deed_singleton_struct: Program,
) -> Offer:
    artifact = receipt.artifact
    assert_artifact_matches_terms(artifact, terms)
    if receipt_spend.coin.puzzle_hash != curry_stripe_settlement_receipt(
        StripeSettlementTermsV1(
            receipt=receipt,
            validator_pubkeys=terms.validator_pubkeys,
        )
    ).get_tree_hash():
        raise PaymentArtifactError("receipt spend uses the wrong puzzle")
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
        Offer.notarize_payments(requested, [receipt_spend.coin]),
        WalletSpendBundle([receipt_spend], G2Element()),
        {
            artifact.deed_launcher_id: _smart_deed_driver(
                terms, deed_singleton_struct
            )
        },
    )
    if offer.get_offered_amounts() != {None: 1}:
        raise PaymentArtifactError(
            "external receipt offer must expose one technical mojo"
        )
    if offer.fees() != 0:
        raise PaymentArtifactError("external receipt offer must be zero fee")
    return offer


def build_stripe_primary_offer_v5(
    *,
    receipt_offer: Offer,
    receipt_coin: Coin,
    receipt: ExternalReceiptV1,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> ChiaPrimaryOffer:
    artifact = receipt.artifact
    buyer_offer_nonce = _validate_stripe_receipt_offer(
        receipt_offer=receipt_offer,
        receipt_coin=receipt_coin,
        artifact=artifact,
        terms=terms,
        deed_singleton_struct=deed_singleton_struct,
    )
    deed_spend = build_stripe_mint_offer_v5_spend(
        deed_coin=deed_coin,
        deed_singleton_struct=deed_singleton_struct,
        lineage_proof=lineage_proof,
        receipt_coin=receipt_coin,
        receipt=receipt,
        buyer_offer_nonce=buyer_offer_nonce,
        terms=terms,
        reservation=reservation,
    )
    issuer_offer = Offer(
        Offer.notarize_payments(
            {
                None: [
                    CreateCoin(
                        (
                            receipt.result_authorization_puzzle_hash
                            if artifact.rail == PaymentRail.EVM_TEST_USD
                            else terms.protocol_puzhash
                        ),
                        uint64(1),
                        [artifact.purchase_id, artifact.artifact_hash],
                    )
                ]
            },
            [deed_coin],
        ),
        WalletSpendBundle([deed_spend], G2Element()),
        {
            artifact.deed_launcher_id: _smart_deed_driver(
                terms, deed_singleton_struct
            )
        },
    )
    aggregate = Offer.aggregate([receipt_offer, issuer_offer])
    if not aggregate.is_valid():
        raise PaymentArtifactError(
            "Stripe receipt and issuer offers do not balance exactly"
        )
    return ChiaPrimaryOffer(
        buyer_offer=receipt_offer,
        issuer_offer=issuer_offer,
        aggregate_offer=aggregate,
        deed_spend=deed_spend,
    )


def prepare_purchase_batch_receipt_offer(
    *,
    receipt_spend: CoinSpend,
    receipt: PurchaseBatchSettlementReceiptV1,
    terms: Sequence[PrimaryMintTermsV3],
    deed_singleton_structs: Sequence[Program],
) -> Offer:
    """Request every exact deed in exchange for one N-mojo receipt coin."""

    item_terms = _validate_purchase_batch_terms(receipt.batch, terms)
    if len(deed_singleton_structs) != receipt.batch.quantity:
        raise PaymentArtifactError(
            "batch singleton structs must match every exact delivery"
        )
    receipt_terms = PurchaseBatchSettlementTermsV1(
        receipt=receipt,
        validator_pubkeys=item_terms[0].validator_pubkeys,
    )
    if receipt_spend.coin.puzzle_hash != curry_purchase_batch_settlement_receipt(
        receipt_terms
    ).get_tree_hash():
        raise PaymentArtifactError("batch receipt spend uses the wrong puzzle")
    requested = {
        artifact.deed_launcher_id: [
            CreateCoin(
                artifact.vault_p2_puzzle_hash,
                uint64(1),
                [
                    artifact.deed_launcher_id,
                    term.smart_deed_inner_hash,
                    artifact.metadata_root,
                    artifact.purchase_id,
                    artifact.artifact_hash,
                ],
            )
        ]
        for artifact, term in zip(
            receipt.batch.artifacts, item_terms, strict=True
        )
    }
    offer = Offer(
        Offer.notarize_payments(requested, [receipt_spend.coin]),
        WalletSpendBundle([receipt_spend], G2Element()),
        {
            artifact.deed_launcher_id: _smart_deed_driver(
                term, deed_singleton_struct
            )
            for artifact, term, deed_singleton_struct in zip(
                receipt.batch.artifacts,
                item_terms,
                deed_singleton_structs,
                strict=True,
            )
        },
    )
    if offer.get_offered_amounts() != {None: receipt.batch.quantity}:
        raise PaymentArtifactError(
            "batch receipt offer must expose one technical mojo per deed"
        )
    if offer.fees() != 0:
        raise PaymentArtifactError("batch receipt offer must be zero fee")
    return offer


def purchase_batch_offer_v5_solution(
    *,
    deed_coin: Coin,
    receipt_coin: Coin,
    receipt: PurchaseBatchSettlementReceiptV1,
    artifact: PurchaseArtifactV3,
    buyer_offer_nonce: bytes32,
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> Program:
    assert_artifact_matches_terms(artifact, terms)
    if reservation.artifact != artifact or artifact not in receipt.batch.artifacts:
        raise PaymentArtifactError(
            "batch receipt child differs from the active deed reservation"
        )
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
            STRIPE_EXTERNAL_MODE,
            bytes32.zeros,
            bytes32.zeros,
            receipt_coin.name(),
            receipt.evidence_hash,
            receipt.attestation.attestation_hash,
            receipt.receipt_hash,
            receipt.expires_at,
            receipt.result_authorization_puzzle_hash,
            0,
            [],
        ]
    )


def build_purchase_batch_mint_offer_v5_spend(
    *,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    receipt_coin: Coin,
    receipt: PurchaseBatchSettlementReceiptV1,
    artifact: PurchaseArtifactV3,
    buyer_offer_nonce: bytes32,
    terms: PrimaryMintTermsV3,
    reservation: InventoryReservationV1,
) -> CoinSpend:
    inner = make_mint_offer_v5_inner(terms, reservation)
    full_puzzle = SINGLETON_MOD.curry(deed_singleton_struct, inner)
    if deed_coin.puzzle_hash != full_puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "deed coin puzzle hash does not match mint offer v5"
        )
    return make_spend(
        deed_coin,
        full_puzzle,
        solution_for_singleton(
            lineage_proof,
            uint64(deed_coin.amount),
            purchase_batch_offer_v5_solution(
                deed_coin=deed_coin,
                receipt_coin=receipt_coin,
                receipt=receipt,
                artifact=artifact,
                buyer_offer_nonce=buyer_offer_nonce,
                terms=terms,
                reservation=reservation,
            ),
        ),
    )


def build_external_primary_batch_offer_v5(
    *,
    receipt_offer: Offer,
    receipt_coin: Coin,
    receipt: PurchaseBatchSettlementReceiptV1,
    deed_coins: Sequence[Coin],
    deed_singleton_structs: Sequence[Program],
    lineage_proofs: Sequence[LineageProof],
    terms: Sequence[PrimaryMintTermsV3],
    reservations: Sequence[InventoryReservationV1],
) -> ChiaPrimaryBatchOffer:
    batch = receipt.batch
    item_terms = _validate_purchase_batch_terms(batch, terms)
    count = len(batch.artifacts)
    if not (
        len(deed_coins)
        == len(deed_singleton_structs)
        == len(lineage_proofs)
        == len(reservations)
        == count
    ):
        raise PaymentArtifactError(
            "external batch inputs must match the exact deed quantity"
        )
    buyer_offer_nonce = _validate_purchase_batch_receipt_offer(
        receipt_offer=receipt_offer,
        receipt_coin=receipt_coin,
        receipt=receipt,
        terms=item_terms,
        deed_singleton_structs=deed_singleton_structs,
    )
    deed_spends: list[CoinSpend] = []
    issuer_offers: list[Offer] = []
    for artifact, deed_coin, singleton_struct, lineage, term, reservation in zip(
        batch.artifacts,
        deed_coins,
        deed_singleton_structs,
        lineage_proofs,
        item_terms,
        reservations,
        strict=True,
    ):
        deed_spend = build_purchase_batch_mint_offer_v5_spend(
            deed_coin=deed_coin,
            deed_singleton_struct=singleton_struct,
            lineage_proof=lineage,
            receipt_coin=receipt_coin,
            receipt=receipt,
            artifact=artifact,
            buyer_offer_nonce=buyer_offer_nonce,
            terms=term,
            reservation=reservation,
        )
        deed_spends.append(deed_spend)
        issuer_offers.append(
            Offer(
                Offer.notarize_payments(
                    {
                        None: [
                            CreateCoin(
                                (
                                    receipt.result_authorization_puzzle_hash
                                    if batch.rail == PaymentRail.EVM_TEST_USD
                                    else term.protocol_puzhash
                                ),
                                uint64(1),
                                [artifact.purchase_id, artifact.artifact_hash],
                            )
                        ]
                    },
                    [deed_coin],
                ),
                WalletSpendBundle([deed_spend], G2Element()),
                {
                    artifact.deed_launcher_id: _smart_deed_driver(
                        term, singleton_struct
                    )
                },
            )
        )
    aggregate = Offer.aggregate([receipt_offer, *issuer_offers])
    if not aggregate.is_valid():
        raise PaymentArtifactError(
            "external batch receipt and issuer offers do not balance exactly"
        )
    return ChiaPrimaryBatchOffer(
        buyer_offer=receipt_offer,
        issuer_offers=tuple(issuer_offers),
        aggregate_offer=aggregate,
        deed_spends=tuple(deed_spends),
    )


def purchase_batch_child_settlement_message(
    receipt: PurchaseBatchSettlementReceiptV1,
    artifact: PurchaseArtifactV3,
) -> bytes32:
    if artifact not in receipt.batch.artifacts:
        raise PaymentArtifactError("artifact is not part of this purchase batch")
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_EXTERNAL_RECEIPT_SETTLEMENT_V1",
                artifact.artifact_hash,
                artifact.purchase_id,
                receipt.receipt_hash,
                int(receipt.batch.rail),
                int(PurchaseDeliveryKind.SMARTDEED),
                artifact.deed_launcher_id,
                1,
                artifact.collection_id,
                receipt.batch.vault_p2_puzzle_hash,
                receipt.result_authorization_puzzle_hash,
                receipt.evidence_hash,
                receipt.attestation.attestation_hash,
            ]
        ).get_tree_hash()
    )


def purchase_batch_settlement_authorization_message(
    terms: PurchaseBatchSettlementTermsV1,
) -> bytes32:
    receipt = terms.receipt
    batch = receipt.batch
    children = [
        [
            artifact.artifact_hash,
            artifact.purchase_id,
            artifact.deed_launcher_id,
            artifact.collection_id,
        ]
        for artifact in batch.artifacts
    ]
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_PURCHASE_BATCH_RECEIPT_AUTH_V1",
                batch.batch_hash,
                batch.purchase_id,
                receipt.receipt_hash,
                receipt.evidence_hash,
                receipt.attestation.attestation_hash,
                int(batch.rail),
                batch.quantity,
                batch.vault_launcher_id,
                batch.vault_p2_puzzle_hash,
                batch.zkpassport_root,
                batch.total_technology_fee_minor,
                batch.total_rail_amount,
                receipt.collected_amount_minor,
                receipt.processing_charge_minor,
                batch.protocol_treasury_puzzle_hash,
                receipt.observed_at,
                receipt.expires_at,
                receipt.result_authorization_puzzle_hash,
                children,
            ]
        ).get_tree_hash()
    )


def stripe_receipt_settlement_message(
    receipt: ExternalReceiptV1,
) -> bytes32:
    artifact = receipt.artifact
    values: list[object] = [
        b"SOLSLOT_EXTERNAL_RECEIPT_SETTLEMENT_V1",
        artifact.artifact_hash,
        artifact.purchase_id,
        receipt.receipt_hash,
        int(artifact.rail),
        int(artifact.delivery_kind),
        artifact.delivery_asset_id,
        artifact.delivery_amount,
        artifact.delivery_context_hash,
        artifact.vault_p2_puzzle_hash,
    ]
    if artifact.delivery_kind == PurchaseDeliveryKind.SMARTDEED:
        values.extend(
            [
                receipt.result_authorization_puzzle_hash,
                _receipt_evidence_hash(receipt),
                receipt.attestation.attestation_hash,
            ]
        )
    return bytes32(
        Program.to(values).get_tree_hash()
    )


def stripe_settlement_authorization_message(
    terms: StripeSettlementTermsV1,
) -> bytes32:
    receipt = terms.receipt
    artifact = receipt.artifact
    return bytes32(
        Program.to(
            [
                b"SOLSLOT_EXTERNAL_RECEIPT_AUTH_V1",
                artifact.artifact_hash,
                artifact.purchase_id,
                receipt.receipt_hash,
                _receipt_evidence_hash(receipt),
                receipt.attestation.attestation_hash,
                int(artifact.rail),
                int(artifact.delivery_kind),
                artifact.delivery_asset_id,
                artifact.delivery_amount,
                artifact.delivery_context_hash,
                artifact.vault_launcher_id,
                artifact.vault_p2_puzzle_hash,
                artifact.zkpassport_root,
                artifact.technology_fee_minor,
                artifact.rail_amount,
                artifact.protocol_treasury_puzzle_hash,
                _receipt_observed_at(receipt),
                receipt.expires_at,
                receipt.result_authorization_puzzle_hash,
            ]
        ).get_tree_hash()
    )


def _validate_stripe_receipt_offer(
    *,
    receipt_offer: Offer,
    receipt_coin: Coin,
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
    deed_singleton_struct: Program,
) -> bytes32:
    assert_artifact_matches_terms(artifact, terms)
    requested = receipt_offer.requested_payments
    if set(requested) != {artifact.deed_launcher_id}:
        raise PaymentArtifactError(
            "Stripe receipt may request only the committed SmartDeed"
        )
    payments = requested[artifact.deed_launcher_id]
    if len(payments) != 1:
        raise PaymentArtifactError(
            "Stripe receipt must request exactly one SmartDeed"
        )
    payment = payments[0]
    expected_memos = [
        artifact.deed_launcher_id,
        terms.smart_deed_inner_hash,
        artifact.metadata_root,
        artifact.purchase_id,
        artifact.artifact_hash,
    ]
    if (
        payment.puzzle_hash != artifact.vault_p2_puzzle_hash
        or int(payment.amount) != 1
        or list(payment.memos) != expected_memos
    ):
        raise PaymentArtifactError(
            "Stripe receipt does not deliver the exact deed to its vault"
        )
    if receipt_offer.get_offered_amounts() != {None: 1}:
        raise PaymentArtifactError(
            "Stripe receipt must offer one technical mojo"
        )
    spends = receipt_offer.coin_spends()
    if len(spends) != 1 or spends[0].coin != receipt_coin:
        raise PaymentArtifactError(
            "Stripe receipt offer must contain the exact receipt spend"
        )
    expected_driver = _smart_deed_driver(terms, deed_singleton_struct)
    actual_driver = receipt_offer.driver_dict.get(artifact.deed_launcher_id)
    if actual_driver is None or actual_driver.info != expected_driver.info:
        raise PaymentArtifactError(
            "Stripe receipt uses the wrong SmartDeed launcher"
        )
    return bytes32(payment.nonce)


def _validate_purchase_batch_terms(
    batch: PurchaseBatchV1,
    terms: Sequence[PrimaryMintTermsV3],
) -> tuple[PrimaryMintTermsV3, ...]:
    values = tuple(terms)
    if len(values) != len(batch.artifacts):
        raise PaymentArtifactError(
            "batch mint terms must match every exact delivery artifact"
        )
    for artifact, term in zip(batch.artifacts, values, strict=True):
        assert_artifact_matches_terms(artifact, term)
    if len({term.validator_pubkeys for term in values}) != 1:
        raise PaymentArtifactError(
            "batch children must use the same validator roster"
        )
    if len({term.protocol_puzhash for term in values}) != 1:
        raise PaymentArtifactError(
            "batch children must use the same protocol settlement puzzle"
        )
    return values


def _validate_purchase_batch_receipt_offer(
    *,
    receipt_offer: Offer,
    receipt_coin: Coin,
    receipt: PurchaseBatchSettlementReceiptV1,
    terms: Sequence[PrimaryMintTermsV3],
    deed_singleton_structs: Sequence[Program],
) -> bytes32:
    batch = receipt.batch
    item_terms = _validate_purchase_batch_terms(batch, terms)
    if len(deed_singleton_structs) != batch.quantity:
        raise PaymentArtifactError(
            "batch singleton structs must match every exact delivery"
        )
    expected_launchers = {
        artifact.deed_launcher_id for artifact in batch.artifacts
    }
    requested = receipt_offer.requested_payments
    if set(requested) != expected_launchers:
        raise PaymentArtifactError(
            "batch receipt must request every committed SmartDeed exactly once"
        )
    nonces: set[bytes32] = set()
    for artifact, term, deed_singleton_struct in zip(
        batch.artifacts,
        item_terms,
        deed_singleton_structs,
        strict=True,
    ):
        payments = requested[artifact.deed_launcher_id]
        if len(payments) != 1:
            raise PaymentArtifactError(
                "batch receipt must request one output per SmartDeed"
            )
        payment = payments[0]
        expected_memos = [
            artifact.deed_launcher_id,
            term.smart_deed_inner_hash,
            artifact.metadata_root,
            artifact.purchase_id,
            artifact.artifact_hash,
        ]
        if (
            payment.puzzle_hash != batch.vault_p2_puzzle_hash
            or int(payment.amount) != 1
            or list(payment.memos) != expected_memos
        ):
            raise PaymentArtifactError(
                "batch receipt does not deliver an exact deed to its vault"
            )
        nonces.add(bytes32(payment.nonce))
        expected_driver = _smart_deed_driver(term, deed_singleton_struct)
        actual_driver = receipt_offer.driver_dict.get(
            artifact.deed_launcher_id
        )
        if actual_driver is None or actual_driver.info != expected_driver.info:
            raise PaymentArtifactError(
                "batch receipt uses the wrong SmartDeed launcher"
            )
    if len(nonces) != 1:
        raise PaymentArtifactError(
            "batch receipt deliveries must share one atomic offer nonce"
        )
    if receipt_offer.get_offered_amounts() != {None: batch.quantity}:
        raise PaymentArtifactError(
            "batch receipt must offer one technical mojo per deed"
        )
    spends = receipt_offer.coin_spends()
    if len(spends) != 1 or spends[0].coin != receipt_coin:
        raise PaymentArtifactError(
            "batch receipt offer must contain the exact receipt spend"
        )
    return next(iter(nonces))


def _validate_signer_indices(indices: Sequence[int]) -> tuple[int, int]:
    values = tuple(indices)
    if len(values) != PROVIDER_THRESHOLD:
        raise PaymentArtifactError("exactly two validator signatures required")
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise PaymentArtifactError(
            "validator indices must be unique and sorted"
        )
    if any(value < 0 or value >= PROVIDER_COUNT for value in values):
        raise PaymentArtifactError("validator index is out of range")
    return values  # type: ignore[return-value]


def _require_bytes32(value: bytes32, name: str) -> None:
    if not isinstance(value, bytes32) or len(value) != 32:
        raise PaymentArtifactError(f"{name} must be bytes32")


__all__ = [
    "ChiaPrimaryBatchOffer",
    "InventoryReservationSpendV1",
    "InventoryReservationV1",
    "InventoryTransitionSpendV1",
    "MAX_RESERVATION_EXTENSION_SECONDS",
    "PRIMARY_PURCHASE_PROVIDER_ID",
    "PrimaryMintTermsV3",
    "PurchaseBatchSettlementTermsV1",
    "build_external_primary_batch_offer_v5",
    "build_inventory_reservation_spend",
    "build_inventory_extension_spend",
    "build_inventory_release_spend",
    "build_external_receipt_spend",
    "build_native_mint_offer_v5_spend",
    "build_native_primary_offer_v5",
    "build_native_primary_batch_offer_v5",
    "build_purchase_batch_mint_offer_v5_spend",
    "build_purchase_batch_receipt_spend",
    "build_stripe_mint_offer_v5_spend",
    "build_stripe_primary_offer_v5",
    "build_stripe_receipt_spend",
    "curry_purchase_batch_settlement_receipt",
    "inventory_extension_message",
    "inventory_release_message",
    "inventory_reservation_message",
    "make_inventory_available_inner",
    "make_mint_offer_v5_inner",
    "make_stripe_receipt_puzzle",
    "mint_offer_delegate_v5_mod_hash",
    "mint_offer_inventory_available_v1_mod_hash",
    "native_offer_v5_solution",
    "prepare_chia_buyer_offer_v3",
    "prepare_chia_buyer_batch_offer_v3",
    "prepare_purchase_batch_receipt_offer",
    "prepare_stripe_receipt_offer",
    "stripe_receipt_settlement_message",
    "stripe_settlement_receipt_v1_mod_hash",
    "purchase_batch_child_settlement_message",
    "purchase_batch_settlement_authorization_message",
    "purchase_batch_settlement_receipt_v1_mod_hash",
    "validate_chia_buyer_offer_v3",
    "validate_chia_buyer_batch_offer_v3",
    "validator_roster_root",
]
