from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import puzzle_for_pk
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v2 import (
    OracleObservationV1,
    PaymentArtifactError,
    XCH_ASSET_DECIMALS,
    build_oracle_round,
)
from solslot_puzzles.payment_artifacts_v3 import (
    build_purchase_batch_settlement_receipt_v1,
    build_purchase_batch_v1,
    build_evm_test_usd_purchase_artifact_v3,
    build_external_settlement_receipt_v1,
    build_stripe_purchase_artifact_v3,
    build_xch_purchase_artifact_v3,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    BASE_SEPOLIA_USDC_ASSET_ID,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    PurchaseBatchSettlementTermsV1,
    StripeSettlementTermsV1,
    build_external_primary_batch_offer_v5,
    build_external_receipt_spend,
    build_native_primary_batch_offer_v5,
    build_purchase_batch_receipt_spend,
    build_stripe_primary_offer_v5,
    curry_purchase_batch_settlement_receipt,
    curry_stripe_settlement_receipt,
    make_mint_offer_v5_inner,
    prepare_chia_buyer_batch_offer_v3,
    prepare_purchase_batch_receipt_offer,
    prepare_stripe_receipt_offer,
    purchase_batch_child_settlement_message,
    purchase_batch_settlement_authorization_message,
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


def test_v5_native_batch_bundles_two_exact_smartdeeds_in_one_offer() -> None:
    observations = tuple(
        OracleObservationV1(
            source_id=b32(seed),
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            price_usd_minor_per_asset=2_100 + (seed - 31) * 25,
            observed_at=1_700_000_000 + seed - 31,
            valid_until=1_700_000_600 + seed - 31,
            evidence_hash=b32(seed + 20),
        )
        for seed in (31, 32, 33)
    )
    oracle = build_oracle_round(
        network="testnet11",
        sequence=1,
        asset_id=bytes32.zeros,
        asset_decimals=XCH_ASSET_DECIMALS,
        operator_set_root=b32(60),
        observations=observations,
    )
    artifacts = tuple(
        build_xch_purchase_artifact_v3(
            network="testnet11",
            collection_id=b32(1),
            deed_launcher_id=b32(seed),
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
            authorization_expires_at=1_700_000_550,
            quote_expires_at=1_700_000_500,
            oracle_round=oracle,
        )
        for seed in (101, 102)
    )
    batch = build_purchase_batch_v1(
        batch_nonce=b32(103),
        artifacts=artifacts,
    )
    item_terms = tuple(mint_terms(item) for item in artifacts)
    payment_key = AugSchemeMPL.key_gen(bytes([104]) * 32)
    payment_puzzle = puzzle_for_pk(payment_key.get_g1())
    payment_coin = Coin(
        b32(105),
        bytes32(payment_puzzle.get_tree_hash()),
        uint64(batch.total_rail_amount + 1_000),
    )
    buyer = prepare_chia_buyer_batch_offer_v3(
        payment_coin=payment_coin,
        payment_public_key=bytes(payment_key.get_g1()),
        batch=batch,
        terms=item_terms,
    )
    reservations = tuple(
        InventoryReservationV1(
            artifact=item,
            expires_at=item.quote_expires_at,
        )
        for item in artifacts
    )
    inners = tuple(
        make_mint_offer_v5_inner(terms, reservation)
        for terms, reservation in zip(item_terms, reservations, strict=True)
    )
    structs = tuple(
        Program.to(
            (
                SINGLETON_MOD_HASH,
                (item.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
            )
        )
        for item in artifacts
    )
    deed_coins = tuple(
        Coin(
            b32(110 + index),
            bytes32(
                SINGLETON_MOD.curry(struct, inner).get_tree_hash()
            ),
            uint64(1),
        )
        for index, (struct, inner) in enumerate(
            zip(structs, inners, strict=True)
        )
    )
    lineages = tuple(
        LineageProof(b32(120 + index), bytes32(inner.get_tree_hash()), uint64(1))
        for index, inner in enumerate(inners)
    )
    purchase = build_native_primary_batch_offer_v5(
        buyer_offer=buyer.offer,
        batch=batch,
        deed_coins=deed_coins,
        deed_singleton_structs=structs,
        lineage_proofs=lineages,
        signer_indices_by_artifact=((0, 2), (1, 2)),
        terms=item_terms,
        reservations=reservations,
    )

    assert len(purchase.deed_spends) == 2
    assert len(purchase.issuer_offers) == 2
    assert purchase.aggregate_offer.is_valid()
    assert set(purchase.aggregate_offer.arbitrage().values()) == {0}
    assert set(purchase.buyer_offer.requested_payments) == {
        item.deed_launcher_id for item in artifacts
    }


def test_v5_stripe_batch_delivers_two_exact_smartdeeds_atomically() -> None:
    artifacts = tuple(
        build_stripe_purchase_artifact_v3(
            network="testnet11",
            collection_id=b32(1),
            deed_launcher_id=b32(seed),
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
        for seed in (101, 102)
    )
    batch = build_purchase_batch_v1(
        batch_nonce=b32(103),
        artifacts=artifacts,
    )
    receipt = build_purchase_batch_settlement_receipt_v1(
        batch=batch,
        provider_id=b32(104),
        external_reference_hash=b32(105),
        evidence_hash=b32(106),
        observed_at=1_800_000_100,
        validator_pubkeys=VALIDATORS,  # type: ignore[arg-type]
        collected_amount_minor=batch.total_rail_amount + 75,
        processing_charge_minor=75,
    )
    item_terms = tuple(mint_terms(item) for item in batch.artifacts)
    receipt_terms = PurchaseBatchSettlementTermsV1(
        receipt=receipt,
        validator_pubkeys=VALIDATORS,  # type: ignore[arg-type]
    )
    receipt_puzzle = curry_purchase_batch_settlement_receipt(receipt_terms)
    receipt_coin = Coin(
        b32(107),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(batch.quantity),
    )
    receipt_spend = build_purchase_batch_receipt_spend(
        receipt_coin=receipt_coin,
        terms=receipt_terms,
        signer_indices=(0, 2),
    )
    conditions = receipt_puzzle.run(
        Program.from_bytes(bytes(receipt_spend.solution))
    ).as_python()
    signatures = [row for row in conditions if opcode(row) == AGG_SIG_ME]
    announcements = [
        row for row in conditions if opcode(row) == CREATE_COIN_ANNOUNCEMENT
    ]
    assert len(signatures) == 2
    assert {row[2] for row in signatures} == {
        bytes(purchase_batch_settlement_authorization_message(receipt_terms))
    }
    assert {row[1] for row in announcements} == {
        bytes(purchase_batch_child_settlement_message(receipt, artifact))
        for artifact in batch.artifacts
    }

    receipt_offer = prepare_purchase_batch_receipt_offer(
        receipt_spend=receipt_spend,
        receipt=receipt,
        terms=item_terms,
    )
    reservations = tuple(
        InventoryReservationV1(
            artifact=item,
            expires_at=item.quote_expires_at,
        )
        for item in batch.artifacts
    )
    inners = tuple(
        make_mint_offer_v5_inner(term, reservation)
        for term, reservation in zip(item_terms, reservations, strict=True)
    )
    structs = tuple(
        Program.to(
            (
                SINGLETON_MOD_HASH,
                (item.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
            )
        )
        for item in batch.artifacts
    )
    deed_coins = tuple(
        Coin(
            b32(110 + index),
            bytes32(SINGLETON_MOD.curry(struct, inner).get_tree_hash()),
            uint64(1),
        )
        for index, (struct, inner) in enumerate(
            zip(structs, inners, strict=True)
        )
    )
    lineages = tuple(
        LineageProof(b32(120 + index), bytes32(inner.get_tree_hash()), uint64(1))
        for index, inner in enumerate(inners)
    )
    purchase = build_external_primary_batch_offer_v5(
        receipt_offer=receipt_offer,
        receipt_coin=receipt_coin,
        receipt=receipt,
        deed_coins=deed_coins,
        deed_singleton_structs=structs,
        lineage_proofs=lineages,
        terms=item_terms,
        reservations=reservations,
    )

    assert len(purchase.deed_spends) == 2
    assert len(purchase.issuer_offers) == 2
    assert purchase.aggregate_offer.is_valid()
    assert set(purchase.aggregate_offer.arbitrage().values()) == {0}
    assert set(purchase.buyer_offer.requested_payments) == {
        item.deed_launcher_id for item in batch.artifacts
    }

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
    build_purchase_batch_receipt_spend,
    curry_purchase_batch_settlement_receipt,
    prepare_purchase_batch_receipt_offer,
    purchase_batch_child_settlement_message,
    purchase_batch_settlement_authorization_message,
