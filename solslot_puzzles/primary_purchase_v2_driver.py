"""Drivers for external escrow and native Chia primary purchase offers."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.outer_puzzles import AssetType
from chia.wallet.puzzle_drivers import PuzzleInfo
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
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentAttestationV1,
    PaymentRail,
    PaymentResolution,
    PaymentTransition,
    PurchaseArtifactV2,
    validate_manual_release,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


PROTOCOL_PREFIX = b"\x53"
DELIVERY_DOMAIN = b"solslot-payment-delivery-v1"
PROVIDER_THRESHOLD = 2
PROVIDER_COUNT = 3
EXTERNAL_RAIL_MARKER_AMOUNT = 1
MINT_MODE_CHIA_OFFER = 1
MINT_MODE_EXTERNAL_ESCROW = 2
PRIMARY_PURCHASE_PROVIDER_ID = bytes32(
    hashlib.sha256(b"SOLSLOT_H_SYSTEM_PRIMARY_PURCHASE_V2").digest()
)

_PAYMENT_ESCROW_MOD: Program | None = None
_MINT_OFFER_V2_MOD: Program | None = None


@dataclass(frozen=True)
class PrimaryMintTermsV2:
    network: str
    smart_deed_inner_hash: bytes32
    deed_launcher_id: bytes32
    collection_id: bytes32
    metadata_root: bytes32
    metadata_anchor_id: bytes32
    share_ppm: int
    usd_amount_minor: int
    protocol_puzhash: bytes32
    validator_pubkeys: tuple[bytes, bytes, bytes]
    provider_id: bytes32

    def __post_init__(self) -> None:
        if not self.network or len(self.network.encode("ascii")) > 32:
            raise ValueError("network must be 1-32 ASCII bytes")
        for name in (
            "smart_deed_inner_hash",
            "deed_launcher_id",
            "collection_id",
            "metadata_root",
            "metadata_anchor_id",
            "protocol_puzhash",
            "provider_id",
        ):
            _require_bytes32(getattr(self, name), name)
        if self.share_ppm <= 0 or self.share_ppm > 1_000_000:
            raise ValueError("share_ppm must be in 1..1_000_000")
        if self.usd_amount_minor <= 0 or self.usd_amount_minor > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("usd_amount_minor must be a positive uint64")
        _require_validator_set(self.validator_pubkeys)


@dataclass(frozen=True)
class PaymentEscrowSpend:
    puzzle: Program
    solution: Program
    coin_spend: CoinSpend
    attestation_hash: bytes32


@dataclass(frozen=True)
class ChiaPrimaryOffer:
    buyer_offer: Offer
    issuer_offer: Offer
    aggregate_offer: Offer
    deed_spend: CoinSpend


@dataclass(frozen=True)
class PreparedChiaBuyerOffer:
    """Unsigned wallet half of one vault-bound primary purchase."""

    offer: Offer
    coin_spend: CoinSpend
    payment_puzzle: Program


def payment_escrow_v1_mod() -> Program:
    global _PAYMENT_ESCROW_MOD
    if _PAYMENT_ESCROW_MOD is None:
        _PAYMENT_ESCROW_MOD = load_puzzle("payment_escrow_v1.clsp")
    return _PAYMENT_ESCROW_MOD


def payment_escrow_v1_mod_hash() -> bytes32:
    return bytes32(payment_escrow_v1_mod().get_tree_hash())


def mint_offer_delegate_v2_mod() -> Program:
    global _MINT_OFFER_V2_MOD
    if _MINT_OFFER_V2_MOD is None:
        _MINT_OFFER_V2_MOD = load_puzzle("mint_offer_delegate_v2.clsp")
    return _MINT_OFFER_V2_MOD


def mint_offer_delegate_v2_mod_hash() -> bytes32:
    return bytes32(mint_offer_delegate_v2_mod().get_tree_hash())


def delivery_message(
    *,
    purchase_id: bytes32,
    artifact_hash: bytes32,
    vault_p2_puzzle_hash: bytes32,
) -> bytes32:
    for value, name in (
        (purchase_id, "purchase_id"),
        (artifact_hash, "artifact_hash"),
        (vault_p2_puzzle_hash, "vault_p2_puzzle_hash"),
    ):
        _require_bytes32(value, name)
    return bytes32(
        Program.to(
            [
                DELIVERY_DOMAIN,
                bytes(purchase_id),
                bytes(artifact_hash),
                bytes(vault_p2_puzzle_hash),
            ]
        ).get_tree_hash()
    )


def escrow_coin_amount(artifact: PurchaseArtifactV2) -> int:
    if artifact.rail in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError(
            "native Chia purchases settle through offer files, not escrow"
        )
    return EXTERNAL_RAIL_MARKER_AMOUNT


def make_payment_escrow_puzzle(
    *,
    artifact: PurchaseArtifactV2,
    pending_attestation: PaymentAttestationV1,
    protocol_puzhash: bytes32,
    refund_puzhash: bytes32,
    validator_pubkeys: Sequence[bytes],
) -> Program:
    if artifact.rail in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError(
            "native Chia purchases cannot create an external payment escrow"
        )
    _assert_pending_matches_artifact(pending_attestation, artifact)
    _require_bytes32(protocol_puzhash, "protocol_puzhash")
    _require_bytes32(refund_puzhash, "refund_puzhash")
    validators = _require_validator_set(validator_pubkeys)
    return payment_escrow_v1_mod().curry(
        list(validators),
        PROVIDER_THRESHOLD,
        artifact.purchase_id,
        artifact.artifact_hash,
        pending_attestation.provider_id,
        pending_attestation.external_reference_hash,
        pending_attestation.attestation_hash,
        pending_attestation.observed_at,
        int(artifact.rail),
        artifact.rail_amount,
        protocol_puzhash,
        refund_puzhash,
        artifact.vault_p2_puzzle_hash,
    )


def make_mint_offer_v2_inner(terms: PrimaryMintTermsV2) -> Program:
    return mint_offer_delegate_v2_mod().curry(
        terms.smart_deed_inner_hash,
        payment_escrow_v1_mod_hash(),
        bytes32(load_puzzle("p2_vault.clsp").get_tree_hash()),
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
        terms.usd_amount_minor,
        terms.protocol_puzhash,
        list(terms.validator_pubkeys),
        PROVIDER_THRESHOLD,
        terms.provider_id,
    )


def assert_artifact_matches_mint(
    artifact: PurchaseArtifactV2,
    terms: PrimaryMintTermsV2,
) -> None:
    expected = {
        "network": terms.network,
        "deed_launcher_id": terms.deed_launcher_id,
        "collection_id": terms.collection_id,
        "metadata_root": terms.metadata_root,
        "metadata_anchor_id": terms.metadata_anchor_id,
        "share_ppm": terms.share_ppm,
        "usd_amount_minor": terms.usd_amount_minor,
    }
    mismatches = [
        name for name, value in expected.items() if getattr(artifact, name) != value
    ]
    if mismatches:
        raise PaymentArtifactError(
            "purchase artifact does not match mint terms: "
            + ", ".join(mismatches)
        )
    expected_p2 = puzzle_hash_for_p2_vault(artifact.vault_launcher_id)
    if artifact.vault_p2_puzzle_hash != expected_p2:
        raise PaymentArtifactError(
            "purchase artifact vault_p2_puzzle_hash is not canonical"
        )


def mint_offer_v2_solution(
    *,
    deed_coin_id: bytes32,
    artifact: PurchaseArtifactV2,
    pending_attestation: PaymentAttestationV1,
    refund_puzhash: bytes32,
    terms: PrimaryMintTermsV2,
) -> Program:
    _require_bytes32(deed_coin_id, "deed_coin_id")
    _require_bytes32(refund_puzhash, "refund_puzhash")
    assert_artifact_matches_mint(artifact, terms)
    if artifact.rail not in (
        PaymentRail.STRIPE,
        PaymentRail.EVM_TEST_USD,
    ):
        raise PaymentArtifactError(
            "external mint solution requires Stripe or EVM rail"
        )
    _assert_pending_matches_artifact(pending_attestation, artifact)
    if pending_attestation.provider_id != terms.provider_id:
        raise PaymentArtifactError(
            "pending attestation provider does not match mint terms"
        )
    return Program.to(
        [
            MINT_MODE_EXTERNAL_ESCROW,
            deed_coin_id,
            bytes32.zeros,
            bytes32.zeros,
            0,
            artifact.vault_launcher_id,
            artifact.vault_p2_puzzle_hash,
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
            pending_attestation.external_reference_hash,
            pending_attestation.attestation_hash,
            pending_attestation.observed_at,
            refund_puzhash,
            bytes32.zeros,
            [],
        ]
    )


def chia_offer_v2_solution(
    *,
    deed_coin: Coin,
    artifact: PurchaseArtifactV2,
    buyer_offer_nonce: bytes32,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV2,
) -> Program:
    assert_artifact_matches_mint(artifact, terms)
    if artifact.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError(
            "Chia offer solution requires XCH or CAT rail"
        )
    indices = _validate_signer_indices(signer_indices)
    _require_bytes32(buyer_offer_nonce, "buyer_offer_nonce")
    return Program.to(
        [
            MINT_MODE_CHIA_OFFER,
            deed_coin.name(),
            deed_coin.parent_coin_info,
            deed_coin.puzzle_hash,
            deed_coin.amount,
            artifact.vault_launcher_id,
            artifact.vault_p2_puzzle_hash,
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
            bytes32.zeros,
            bytes32.zeros,
            0,
            bytes32.zeros,
            buyer_offer_nonce,
            list(indices),
        ]
    )


def payment_escrow_solution(
    *,
    escrow_coin: Coin,
    escrow_puzzle: Program,
    resolution_attestation: PaymentAttestationV1,
    signer_indices: Sequence[int],
) -> Program:
    if escrow_coin.puzzle_hash != escrow_puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "escrow coin puzzle hash does not match payment escrow puzzle"
        )
    indices = _validate_signer_indices(signer_indices)
    if resolution_attestation.transition not in (
        PaymentTransition.SUCCEEDED,
        PaymentTransition.FAILED,
        PaymentTransition.MANUAL_RELEASE,
    ):
        raise PaymentArtifactError("escrow requires a resolution attestation")
    return Program.to(
        [
            escrow_coin.name(),
            escrow_puzzle.get_tree_hash(),
            escrow_coin.amount,
            int(resolution_attestation.transition),
            int(resolution_attestation.resolution),
            resolution_attestation.evidence_hash,
            resolution_attestation.observed_at,
            resolution_attestation.reason_hash,
            list(indices),
        ]
    )


def build_payment_escrow_spend(
    *,
    escrow_coin: Coin,
    artifact: PurchaseArtifactV2,
    pending_attestation: PaymentAttestationV1,
    resolution_attestation: PaymentAttestationV1,
    protocol_puzhash: bytes32,
    refund_puzhash: bytes32,
    validator_pubkeys: Sequence[bytes],
    signer_indices: Sequence[int],
) -> PaymentEscrowSpend:
    _assert_resolution_matches_pending(
        resolution_attestation=resolution_attestation,
        pending_attestation=pending_attestation,
    )
    puzzle = make_payment_escrow_puzzle(
        artifact=artifact,
        pending_attestation=pending_attestation,
        protocol_puzhash=protocol_puzhash,
        refund_puzhash=refund_puzhash,
        validator_pubkeys=validator_pubkeys,
    )
    expected_amount = escrow_coin_amount(artifact)
    if int(escrow_coin.amount) != expected_amount:
        raise PaymentArtifactError(
            f"escrow coin amount must be {expected_amount}"
        )
    solution = payment_escrow_solution(
        escrow_coin=escrow_coin,
        escrow_puzzle=puzzle,
        resolution_attestation=resolution_attestation,
        signer_indices=signer_indices,
    )
    return PaymentEscrowSpend(
        puzzle=puzzle,
        solution=solution,
        coin_spend=make_spend(escrow_coin, puzzle, solution),
        attestation_hash=resolution_attestation.attestation_hash,
    )


def build_mint_offer_v2_spend(
    *,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    artifact: PurchaseArtifactV2,
    pending_attestation: PaymentAttestationV1,
    refund_puzhash: bytes32,
    terms: PrimaryMintTermsV2,
) -> CoinSpend:
    inner = make_mint_offer_v2_inner(terms)
    full_puzzle = SINGLETON_MOD.curry(deed_singleton_struct, inner)
    if deed_coin.puzzle_hash != full_puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "deed coin puzzle hash does not match mint offer v2"
        )
    inner_solution = mint_offer_v2_solution(
        deed_coin_id=bytes32(deed_coin.name()),
        artifact=artifact,
        pending_attestation=pending_attestation,
        refund_puzhash=refund_puzhash,
        terms=terms,
    )
    full_solution = solution_for_singleton(
        lineage_proof,
        uint64(deed_coin.amount),
        inner_solution,
    )
    return make_spend(deed_coin, full_puzzle, full_solution)


def build_chia_mint_offer_v2_spend(
    *,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    artifact: PurchaseArtifactV2,
    buyer_offer_nonce: bytes32,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV2,
) -> CoinSpend:
    inner = make_mint_offer_v2_inner(terms)
    full_puzzle = SINGLETON_MOD.curry(deed_singleton_struct, inner)
    if deed_coin.puzzle_hash != full_puzzle.get_tree_hash():
        raise PaymentArtifactError(
            "deed coin puzzle hash does not match mint offer v2"
        )
    inner_solution = chia_offer_v2_solution(
        deed_coin=deed_coin,
        artifact=artifact,
        buyer_offer_nonce=buyer_offer_nonce,
        signer_indices=signer_indices,
        terms=terms,
    )
    full_solution = solution_for_singleton(
        lineage_proof,
        uint64(deed_coin.amount),
        inner_solution,
    )
    return make_spend(deed_coin, full_puzzle, full_solution)


def smart_deed_singleton_driver(
    deed_launcher_id: bytes32,
) -> PuzzleInfo:
    _require_bytes32(deed_launcher_id, "deed_launcher_id")
    return PuzzleInfo(
        {
            "type": "singleton",
            "launcher_id": f"0x{deed_launcher_id.hex()}",
            "launcher_ph": f"0x{SINGLETON_LAUNCHER_HASH.hex()}",
        }
    )


def chia_cat_driver(cat_asset_id: bytes32) -> PuzzleInfo:
    _require_bytes32(cat_asset_id, "cat_asset_id")
    if cat_asset_id == bytes32.zeros:
        raise PaymentArtifactError("CAT asset ID cannot be zero")
    return PuzzleInfo(
        {
            "type": AssetType.CAT.value,
            "tail": f"0x{cat_asset_id.hex()}",
        }
    )


def prepare_chia_buyer_offer(
    *,
    payment_coin: Coin,
    payment_public_key: bytes,
    artifact: PurchaseArtifactV2,
    terms: PrimaryMintTermsV2,
    cat_lineage_proof: LineageProof | None = None,
) -> PreparedChiaBuyerOffer:
    """Build the exact unsigned XCH/CAT offer half a wallet must sign.

    A single sufficiently large payment coin keeps the review surface small:
    one input, one settlement output, and at most one change output.  The
    caller remains responsible for checking that the coin is confirmed and
    unspent immediately before asking the wallet to sign it.
    """

    assert_artifact_matches_mint(artifact, terms)
    if artifact.rail not in (PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT):
        raise PaymentArtifactError(
            "buyer offer preparation requires an XCH or CAT artifact"
        )
    if len(payment_public_key) != 48:
        raise PaymentArtifactError("payment_public_key must be 48 bytes")
    try:
        public_key = G1Element.from_bytes(payment_public_key)
    except ValueError as exc:
        raise PaymentArtifactError("payment_public_key is not valid BLS") from exc
    if int(payment_coin.amount) < artifact.rail_amount:
        raise PaymentArtifactError(
            "payment coin is smaller than the H-system quote"
        )

    payment_puzzle = puzzle_for_pk(public_key)
    requested_driver = smart_deed_singleton_driver(
        artifact.deed_launcher_id
    )
    drivers = {artifact.deed_launcher_id: requested_driver}
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
    validate_chia_buyer_offer(
        buyer_offer=offer,
        artifact=artifact,
        terms=terms,
    )
    return PreparedChiaBuyerOffer(
        offer=offer,
        coin_spend=coin_spend,
        payment_puzzle=payment_puzzle,
    )


def validate_chia_buyer_offer(
    *,
    buyer_offer: Offer,
    artifact: PurchaseArtifactV2,
    terms: PrimaryMintTermsV2,
) -> bytes32:
    """Validate the wallet-signed half-offer and return its payment nonce."""

    assert_artifact_matches_mint(artifact, terms)
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
            "buyer offer does not deliver the SmartDeed to the authorized vault"
        )

    payment_asset = (
        None
        if artifact.rail == PaymentRail.CHIA_XCH
        else artifact.rail_asset_id
    )
    offered = buyer_offer.get_offered_amounts()
    if set(offered) != {payment_asset}:
        raise PaymentArtifactError(
            "buyer offer must contain only the quoted XCH or CAT payment"
        )
    if int(offered[payment_asset]) != artifact.rail_amount:
        raise PaymentArtifactError(
            "buyer offer amount does not match the H-system quote"
        )
    expected_driver = smart_deed_singleton_driver(
        artifact.deed_launcher_id
    )
    actual_driver = buyer_offer.driver_dict.get(
        artifact.deed_launcher_id
    )
    if actual_driver is None or actual_driver.info != expected_driver.info:
        raise PaymentArtifactError(
            "buyer offer uses an unexpected SmartDeed singleton driver"
        )
    if artifact.rail == PaymentRail.CHIA_CAT:
        expected_cat_driver = chia_cat_driver(artifact.rail_asset_id)
        actual_cat_driver = buyer_offer.driver_dict.get(
            artifact.rail_asset_id
        )
        if (
            actual_cat_driver is None
            or actual_cat_driver.info != expected_cat_driver.info
        ):
            raise PaymentArtifactError(
                "buyer offer uses an unexpected CAT driver"
            )
    return bytes32(payment.nonce)


def build_chia_primary_offer(
    *,
    buyer_offer: Offer,
    deed_coin: Coin,
    deed_singleton_struct: Program,
    lineage_proof: LineageProof,
    artifact: PurchaseArtifactV2,
    signer_indices: Sequence[int],
    terms: PrimaryMintTermsV2,
) -> ChiaPrimaryOffer:
    """Add the governed deed half to a wallet-signed XCH/CAT offer file."""

    buyer_offer_nonce = validate_chia_buyer_offer(
        buyer_offer=buyer_offer,
        artifact=artifact,
        terms=terms,
    )
    deed_spend = build_chia_mint_offer_v2_spend(
        deed_coin=deed_coin,
        deed_singleton_struct=deed_singleton_struct,
        lineage_proof=lineage_proof,
        artifact=artifact,
        buyer_offer_nonce=buyer_offer_nonce,
        signer_indices=signer_indices,
        terms=terms,
    )
    payment_asset = (
        None
        if artifact.rail == PaymentRail.CHIA_XCH
        else artifact.rail_asset_id
    )
    requested_payments = {
        payment_asset: [
            CreateCoin(
                terms.protocol_puzhash,
                uint64(artifact.rail_amount),
                [artifact.purchase_id, artifact.artifact_hash],
            )
        ]
    }
    notarized = Offer.notarize_payments(
        requested_payments,
        [deed_coin],
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
        notarized,
        WalletSpendBundle([deed_spend], G2Element()),
        drivers,
    )
    aggregate_offer = Offer.aggregate([buyer_offer, issuer_offer])
    if not aggregate_offer.is_valid():
        raise PaymentArtifactError(
            "buyer and issuer offer files do not balance exactly"
        )
    return ChiaPrimaryOffer(
        buyer_offer=buyer_offer,
        issuer_offer=issuer_offer,
        aggregate_offer=aggregate_offer,
        deed_spend=deed_spend,
    )


def _assert_pending_matches_artifact(
    pending_attestation: PaymentAttestationV1,
    artifact: PurchaseArtifactV2,
) -> None:
    if (
        pending_attestation.transition != PaymentTransition.PENDING
        or pending_attestation.resolution != PaymentResolution.NONE
    ):
        raise PaymentArtifactError(
            "payment escrow requires a PENDING attestation"
        )
    if (
        pending_attestation.purchase_id != artifact.purchase_id
        or pending_attestation.artifact_hash != artifact.artifact_hash
    ):
        raise PaymentArtifactError(
            "pending attestation does not match purchase artifact"
        )


def _assert_resolution_matches_pending(
    *,
    resolution_attestation: PaymentAttestationV1,
    pending_attestation: PaymentAttestationV1,
) -> None:
    if (
        resolution_attestation.purchase_id != pending_attestation.purchase_id
        or resolution_attestation.artifact_hash
        != pending_attestation.artifact_hash
        or resolution_attestation.provider_id != pending_attestation.provider_id
        or resolution_attestation.external_reference_hash
        != pending_attestation.external_reference_hash
        or resolution_attestation.previous_attestation_hash
        != pending_attestation.attestation_hash
    ):
        raise PaymentArtifactError(
            "resolution attestation does not match pending attestation"
        )
    if resolution_attestation.transition == PaymentTransition.MANUAL_RELEASE:
        validate_manual_release(
            pending_attestation=pending_attestation,
            release_attestation=resolution_attestation,
        )


def _require_validator_set(
    validator_pubkeys: Sequence[bytes],
) -> tuple[bytes, bytes, bytes]:
    values = tuple(bytes(value) for value in validator_pubkeys)
    if len(values) != PROVIDER_COUNT:
        raise ValueError("payment provider set must contain exactly three keys")
    if any(len(value) != 48 for value in values):
        raise ValueError("payment provider keys must be 48-byte BLS public keys")
    if len(set(values)) != PROVIDER_COUNT:
        raise ValueError("payment provider keys must be unique")
    return values  # type: ignore[return-value]


def _validate_signer_indices(
    signer_indices: Sequence[int],
) -> tuple[int, ...]:
    indices = tuple(signer_indices)
    if (
        len(indices) < PROVIDER_THRESHOLD
        or len(set(indices)) != len(indices)
        or tuple(sorted(indices)) != indices
        or any(index < 0 or index >= PROVIDER_COUNT for index in indices)
    ):
        raise PaymentArtifactError(
            "signer_indices must contain at least two unique sorted indices in 0..2"
        )
    return indices


def _require_bytes32(value: bytes32, name: str) -> None:
    if not isinstance(value, bytes32) or len(value) != 32:
        raise ValueError(f"{name} must be bytes32")
