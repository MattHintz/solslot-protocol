"""RC24 Stripe receipt and governed SmartDeed delivery drivers."""
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
_P2_VAULT_MOD_HASH = bytes32(load_puzzle("p2_vault.clsp").get_tree_hash())


@dataclass(frozen=True)
class PrimaryMintTermsV3:
    network: str
    smart_deed_inner_hash: bytes32
    deed_launcher_id: bytes32
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
            "collection_id",
            "metadata_root",
            "metadata_anchor_id",
            "protocol_treasury_puzzle_hash",
            "protocol_puzhash",
            "provider_id",
        ):
            _require_bytes32(getattr(self, name), name)
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
        protocol_puzhash: bytes32,
        validator_pubkeys: tuple[bytes, bytes, bytes],
        provider_id: bytes32 = PRIMARY_PURCHASE_PROVIDER_ID,
    ) -> "PrimaryMintTermsV3":
        return cls(
            network=artifact.network,
            smart_deed_inner_hash=smart_deed_inner_hash,
            deed_launcher_id=artifact.deed_launcher_id,
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


def _mint_immutable_args(terms: PrimaryMintTermsV3) -> tuple[object, ...]:
    return (
        terms.smart_deed_inner_hash,
        _P2_VAULT_MOD_HASH,
        SINGLETON_MOD_HASH,
        SINGLETON_LAUNCHER_HASH,
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
        artifact.deed_launcher_id: smart_deed_singleton_driver(
            artifact.deed_launcher_id
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
    )
    return PreparedChiaBuyerOffer(
        offer=offer,
        coin_spend=coin_spend,
        payment_puzzle=payment_puzzle,
    )


def validate_chia_buyer_offer_v3(
    *,
    buyer_offer: Offer,
    artifact: PurchaseArtifactV3,
    terms: PrimaryMintTermsV3,
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
    expected_driver = smart_deed_singleton_driver(
        artifact.deed_launcher_id
    )
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
        artifact.deed_launcher_id: smart_deed_singleton_driver(
            artifact.deed_launcher_id
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
            artifact.deed_launcher_id: smart_deed_singleton_driver(
                artifact.deed_launcher_id
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
            artifact.deed_launcher_id: smart_deed_singleton_driver(
                artifact.deed_launcher_id
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
    return bytes32(payment.nonce)


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
    "InventoryReservationSpendV1",
    "InventoryReservationV1",
    "InventoryTransitionSpendV1",
    "MAX_RESERVATION_EXTENSION_SECONDS",
    "PRIMARY_PURCHASE_PROVIDER_ID",
    "PrimaryMintTermsV3",
    "build_inventory_reservation_spend",
    "build_inventory_extension_spend",
    "build_inventory_release_spend",
    "build_external_receipt_spend",
    "build_native_mint_offer_v5_spend",
    "build_native_primary_offer_v5",
    "build_stripe_mint_offer_v5_spend",
    "build_stripe_primary_offer_v5",
    "build_stripe_receipt_spend",
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
    "prepare_stripe_receipt_offer",
    "stripe_receipt_settlement_message",
    "stripe_settlement_receipt_v1_mod_hash",
    "validate_chia_buyer_offer_v3",
    "validator_roster_root",
]
