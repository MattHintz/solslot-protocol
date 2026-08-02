from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
)
from solslot_puzzles.payment_artifacts_v3 import (
    build_evm_test_usd_purchase_artifact_v3,
    build_external_settlement_receipt_v1,
    build_stripe_purchase_artifact_v3,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    BASE_SEPOLIA_USDC_ASSET_ID,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    StripeSettlementTermsV1,
    build_external_receipt_spend,
    build_stripe_primary_offer_v5,
    curry_stripe_settlement_receipt,
    make_mint_offer_v5_inner,
    prepare_stripe_receipt_offer,
    stripe_receipt_settlement_message,
    stripe_settlement_authorization_message,
)
from solslot_puzzles.vault_driver import (
    puzzle_for_p2_vault,
    puzzle_hash_for_p2_vault,
)


AGG_SIG_ME = 50
CREATE_COIN_ANNOUNCEMENT = 60


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


VALIDATORS = tuple(
    bytes(AugSchemeMPL.key_gen(bytes([seed]) * 32).get_g1())
    for seed in (41, 42, 43)
)
VAULT_LAUNCHER = b32(7)
VAULT_P2 = puzzle_hash_for_p2_vault(VAULT_LAUNCHER)


def base_artifact():
    return build_evm_test_usd_purchase_artifact_v3(
        chain_id=84532,
        token_asset_id=BASE_SEPOLIA_USDC_ASSET_ID,
        network="testnet11",
        collection_id=b32(1),
        deed_launcher_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        share_ppm=100_000,
        base_usd_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=b32(5),
        zkpassport_root=b32(6),
        vault_launcher_id=VAULT_LAUNCHER,
        vault_p2_puzzle_hash=VAULT_P2,
        authorization_nonce=b32(9),
        authorization_expires_at=1_800_000_600,
        quote_expires_at=1_800_000_300,
    )


def stripe_artifact():
    return build_stripe_purchase_artifact_v3(
        network="testnet11",
        collection_id=b32(1),
        deed_launcher_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        share_ppm=100_000,
        base_usd_amount_minor=10_000,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=b32(5),
        zkpassport_root=b32(6),
        vault_launcher_id=VAULT_LAUNCHER,
        vault_p2_puzzle_hash=VAULT_P2,
        authorization_nonce=b32(9),
        authorization_expires_at=1_800_000_600,
        quote_expires_at=1_800_000_300,
    )


def mint_terms(artifact) -> PrimaryMintTermsV3:
    return PrimaryMintTermsV3.for_artifact(
        artifact=artifact,
        smart_deed_inner_hash=b32(20),
        protocol_puzhash=b32(21),
        validator_pubkeys=VALIDATORS,  # type: ignore[arg-type]
        provider_id=b32(22),
    )


def base_receipt(result_puzzle_hash: bytes32):
    artifact = base_artifact()
    receipt = build_external_settlement_receipt_v1(
        artifact=artifact,
        provider_id=b32(70),
        external_reference_hash=b32(71),
        evidence_hash=b32(72),
        observed_at=1_800_000_100,
        result_authorization_puzzle_hash=result_puzzle_hash,
    )
    terms = mint_terms(artifact)
    receipt_terms = StripeSettlementTermsV1(
        receipt=receipt,
        validator_pubkeys=VALIDATORS,  # type: ignore[arg-type]
    )
    receipt_puzzle = curry_stripe_settlement_receipt(receipt_terms)
    receipt_coin = Coin(
        b32(73),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    receipt_spend = build_external_receipt_spend(
        receipt_coin=receipt_coin,
        terms=receipt_terms,
        signer_indices=(0, 2),
    )
    offer = prepare_stripe_receipt_offer(
        receipt_spend=receipt_spend,
        receipt=receipt,
        terms=terms,
    )
    return artifact, receipt, receipt_terms, receipt_coin, offer, terms


def opcode(row: list[bytes]) -> int:
    return int.from_bytes(row[0], "big")


def test_v5_base_receipt_binds_validator_authorization_and_settlement() -> None:
    result_hash = b32(74)
    _, receipt, receipt_terms, receipt_coin, _, _ = base_receipt(result_hash)
    puzzle = curry_stripe_settlement_receipt(receipt_terms)
    spend = build_external_receipt_spend(
        receipt_coin=receipt_coin,
        terms=receipt_terms,
        signer_indices=(0, 2),
    )
    conditions = puzzle.run(Program.from_bytes(bytes(spend.solution))).as_python()
    signatures = [row for row in conditions if opcode(row) == AGG_SIG_ME]
    assert len(signatures) == 2
    assert {row[2] for row in signatures} == {
        bytes(stripe_settlement_authorization_message(receipt_terms))
    }
    announcements = [
        row for row in conditions if opcode(row) == CREATE_COIN_ANNOUNCEMENT
    ]
    assert announcements == [
        [b"\x3c", bytes(stripe_receipt_settlement_message(receipt))]
    ]


def test_v5_base_offer_delivers_reserved_deed_and_exact_result() -> None:
    result_hash = b32(75)
    artifact, receipt, _, receipt_coin, receipt_offer, terms = base_receipt(
        result_hash
    )
    reservation = InventoryReservationV1(
        artifact=artifact,
        expires_at=artifact.quote_expires_at,
    )
    inner = make_mint_offer_v5_inner(terms, reservation)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    deed_coin = Coin(
        b32(76),
        bytes32(SINGLETON_MOD.curry(singleton_struct, inner).get_tree_hash()),
        uint64(1),
    )
    purchase = build_stripe_primary_offer_v5(
        receipt_offer=receipt_offer,
        receipt_coin=receipt_coin,
        receipt=receipt,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            b32(77),
            bytes32(inner.get_tree_hash()),
            uint64(1),
        ),
        terms=terms,
        reservation=reservation,
    )

    assert purchase.aggregate_offer.is_valid()
    assert purchase.aggregate_offer.arbitrage() == {
        artifact.deed_launcher_id: 0,
        None: 0,
    }
    additions = purchase.aggregate_offer.to_valid_spend().additions()
    delivered_deed = bytes32(
        SINGLETON_MOD.curry(
            singleton_struct,
            puzzle_for_p2_vault(VAULT_LAUNCHER),
        ).get_tree_hash()
    )
    assert sum(
        coin.puzzle_hash == delivered_deed and int(coin.amount) == 1
        for coin in additions
    ) == 1
    assert sum(
        coin.puzzle_hash == result_hash and int(coin.amount) == 1
        for coin in additions
    ) == 1
    assert not any(
        coin.puzzle_hash == terms.protocol_puzhash for coin in additions
    )


def test_v5_external_result_rules_fail_closed() -> None:
    with pytest.raises(
        PaymentArtifactError,
        match="requires a result authorization",
    ):
        build_external_settlement_receipt_v1(
            artifact=base_artifact(),
            provider_id=b32(80),
            external_reference_hash=b32(81),
            evidence_hash=b32(82),
            observed_at=1_800_000_100,
            result_authorization_puzzle_hash=bytes32.zeros,
        )

    with pytest.raises(
        PaymentArtifactError,
        match="cannot carry a Base result authorization",
    ):
        build_external_settlement_receipt_v1(
            artifact=stripe_artifact(),
            provider_id=b32(83),
            external_reference_hash=b32(84),
            evidence_hash=b32(85),
            observed_at=1_800_000_100,
            result_authorization_puzzle_hash=b32(86),
        )


def test_v5_base_result_changes_receipt_but_not_artifact_reservation() -> None:
    first = base_receipt(b32(90))
    second = base_receipt(b32(91))
    first_artifact, first_receipt, _, _, _, terms = first
    second_artifact, second_receipt, _, _, _, _ = second
    assert first_receipt.receipt_hash != second_receipt.receipt_hash
    first_reservation = InventoryReservationV1(
        artifact=first_artifact,
        expires_at=first_artifact.quote_expires_at,
    )
    second_reservation = InventoryReservationV1(
        artifact=second_artifact,
        expires_at=second_artifact.quote_expires_at,
    )
    assert bytes32(
        curry_stripe_settlement_receipt(first[2]).get_tree_hash()
    ) != bytes32(curry_stripe_settlement_receipt(second[2]).get_tree_hash())
    assert (
        make_mint_offer_v5_inner(terms, first_reservation).get_tree_hash()
        == make_mint_offer_v5_inner(terms, second_reservation).get_tree_hash()
    )


def test_v5_settlement_announcement_cannot_drop_base_result() -> None:
    _, receipt, _, receipt_coin, _, _ = base_receipt(b32(94))
    message = stripe_receipt_settlement_message(receipt)
    without_result = bytes32(
        Program.to(
            [
                b"SOLSLOT_EXTERNAL_RECEIPT_SETTLEMENT_V1",
                receipt.artifact.artifact_hash,
                receipt.artifact.purchase_id,
                receipt.receipt_hash,
                int(receipt.artifact.rail),
                int(receipt.artifact.delivery_kind),
                receipt.artifact.delivery_asset_id,
                receipt.artifact.delivery_amount,
                receipt.artifact.delivery_context_hash,
                receipt.artifact.vault_p2_puzzle_hash,
                bytes32.zeros,
                receipt.evidence_hash,
                receipt.attestation.attestation_hash,
            ]
        ).get_tree_hash()
    )
    assert message != without_result
    assert hashlib.sha256(bytes(receipt_coin.name()) + bytes(message)).digest()
