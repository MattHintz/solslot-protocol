from __future__ import annotations

from dataclasses import replace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.payment_artifacts_v2 import (
    PaymentArtifactError,
    PaymentAttestationV1,
    PaymentResolution,
    PaymentTransition,
)
from solslot_puzzles.payment_artifacts_v3 import (
    STRIPE_RECEIPT_TTL_SECONDS,
    StripeDisputeState,
    StripeFundingType,
    StripeMethodFamily,
    StripePaymentStatus,
    StripeRefundState,
    StripeSettlementEvidenceV1,
    StripeSettlementReceiptV1,
    build_stripe_purchase_artifact,
)
from solslot_puzzles.stripe_settlement_v1_driver import (
    InventoryReservationV1,
    PrimaryMintTermsV3,
    StripeSettlementTermsV1,
    build_inventory_reservation_spend,
    build_inventory_extension_spend,
    build_inventory_release_spend,
    build_stripe_primary_offer_v5,
    build_stripe_receipt_spend,
    inventory_reservation_message,
    make_inventory_available_inner,
    make_mint_offer_v5_inner,
    make_stripe_receipt_puzzle,
    prepare_stripe_receipt_offer,
    stripe_receipt_settlement_message,
    stripe_settlement_authorization_message,
    validator_roster_root,
)
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def validators() -> tuple[bytes, bytes, bytes]:
    return tuple(
        bytes(AugSchemeMPL.key_gen(bytes([value]) * 32).get_g1())
        for value in (41, 42, 43)
    )  # type: ignore[return-value]


def settlement() -> tuple[StripeSettlementReceiptV1, PrimaryMintTermsV3]:
    vault_launcher = b32(7)
    artifact = build_stripe_purchase_artifact(
        network="testnet11",
        collection_id=b32(1),
        deed_launcher_id=b32(2),
        metadata_root=b32(3),
        metadata_anchor_id=b32(4),
        share_ppm=40_000,
        base_amount_minor=22_900,
        technology_fee_bps=100,
        protocol_treasury_puzzle_hash=b32(5),
        zkpassport_root=b32(6),
        vault_launcher_id=vault_launcher,
        vault_p2_puzzle_hash=puzzle_hash_for_p2_vault(vault_launcher),
        authorization_nonce=b32(8),
        authorization_expires_at=1_800_000_000,
        quote_expires_at=1_700_000_600,
    )
    evidence = StripeSettlementEvidenceV1(
        stripe_account_id="acct_rc24",
        livemode=False,
        payment_intent_id="pi_rc24",
        event_id="evt_rc24",
        amount_minor=artifact.subtotal_minor,
        currency="usd",
        method_family=StripeMethodFamily.CARD,
        funding_type=StripeFundingType.DEBIT,
        processing_charge_minor=0,
        status=StripePaymentStatus.SUCCEEDED,
        refunded_minor=0,
        refund_state=StripeRefundState.NONE,
        dispute_state=StripeDisputeState.NONE,
        observed_at=1_700_000_100,
    )
    pending = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=b32(9),
        external_reference_hash=evidence.payment_reference_hash,
        evidence_hash=b32(10),
        previous_attestation_hash=bytes32.zeros,
        observed_at=evidence.observed_at - 1,
    )
    succeeded = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=b32(9),
        external_reference_hash=evidence.payment_reference_hash,
        evidence_hash=evidence.evidence_hash,
        previous_attestation_hash=pending.attestation_hash,
        observed_at=evidence.observed_at,
    )
    keys = validators()
    receipt = StripeSettlementReceiptV1(
        artifact=artifact,
        evidence=evidence,
        attestation=succeeded,
        validator_roster_root=validator_roster_root(keys),
        validator_threshold=2,
        receipt_nonce=b32(11),
        expires_at=evidence.observed_at + STRIPE_RECEIPT_TTL_SECONDS,
    )
    terms = PrimaryMintTermsV3.for_artifact(
        artifact=artifact,
        smart_deed_inner_hash=bytes32(
            load_puzzle("smart_deed_inner_v2.clsp").get_tree_hash()
        ),
        protocol_puzhash=b32(12),
        validator_pubkeys=keys,
        provider_id=b32(13),
    )
    return receipt, terms


def test_receipt_puzzle_requires_exact_two_of_three_and_emits_binding() -> None:
    receipt, terms = settlement()
    puzzle = make_stripe_receipt_puzzle(
        receipt=receipt,
        validator_pubkeys=terms.validator_pubkeys,
    )
    coin = Coin(b32(14), bytes32(puzzle.get_tree_hash()), uint64(1))
    spend = build_stripe_receipt_spend(
        receipt_coin=coin,
        receipt=receipt,
        validator_pubkeys=terms.validator_pubkeys,
        signer_indices=(0, 2),
    )
    conditions = puzzle.run(
        Program.from_bytes(bytes(spend.solution))
    ).as_python()
    sigs = [row for row in conditions if int.from_bytes(row[0], "big") == 50]
    announcements = [
        row for row in conditions if int.from_bytes(row[0], "big") == 60
    ]
    assert len(sigs) == 2
    assert {row[2] for row in sigs} == {
        bytes(
            stripe_settlement_authorization_message(
                StripeSettlementTermsV1(
                    receipt=receipt,
                    validator_pubkeys=terms.validator_pubkeys,
                )
            )
        )
    }
    assert announcements == [[b"\x3c", bytes(stripe_receipt_settlement_message(receipt))]]

    with pytest.raises(PaymentArtifactError, match="exactly two"):
        build_stripe_receipt_spend(
            receipt_coin=coin,
            receipt=receipt,
            validator_pubkeys=terms.validator_pubkeys,
            signer_indices=(0,),
        )


def test_receipt_offer_delivers_only_the_committed_deed_to_canonical_vault() -> None:
    receipt, terms = settlement()
    reservation = InventoryReservationV1(
        artifact=receipt.artifact,
        expires_at=receipt.artifact.quote_expires_at,
    )
    receipt_puzzle = make_stripe_receipt_puzzle(
        receipt=receipt,
        validator_pubkeys=terms.validator_pubkeys,
    )
    receipt_coin = Coin(
        b32(15),
        bytes32(receipt_puzzle.get_tree_hash()),
        uint64(1),
    )
    receipt_spend = build_stripe_receipt_spend(
        receipt_coin=receipt_coin,
        receipt=receipt,
        validator_pubkeys=terms.validator_pubkeys,
        signer_indices=(0, 1),
    )
    buyer = prepare_stripe_receipt_offer(
        receipt_spend=receipt_spend,
        receipt=receipt,
        terms=terms,
    )
    inner = make_mint_offer_v5_inner(terms, reservation)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (receipt.artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    deed_coin = Coin(
        b32(16),
        bytes32(
            SINGLETON_MOD.curry(singleton_struct, inner).get_tree_hash()
        ),
        uint64(1),
    )
    combined = build_stripe_primary_offer_v5(
        receipt_offer=buyer,
        receipt_coin=receipt_coin,
        receipt=receipt,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            b32(17),
            bytes32(inner.get_tree_hash()),
            uint64(1),
        ),
        terms=terms,
        reservation=reservation,
    )
    assert combined.aggregate_offer.is_valid()
    assert combined.aggregate_offer.arbitrage() == {
        receipt.artifact.deed_launcher_id: 0,
        None: 0,
    }
    valid_spend = combined.aggregate_offer.to_valid_spend()
    assert len(valid_spend.coin_spends) >= 3


def test_deed_must_move_from_available_to_exact_reserved_state() -> None:
    receipt, terms = settlement()
    reservation = InventoryReservationV1(
        artifact=receipt.artifact,
        expires_at=receipt.artifact.quote_expires_at,
    )
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (receipt.artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    available_inner = make_inventory_available_inner(terms)
    available_coin = Coin(
        b32(21),
        bytes32(
            SINGLETON_MOD.curry(
                singleton_struct,
                available_inner,
            ).get_tree_hash()
        ),
        uint64(1),
    )
    result = build_inventory_reservation_spend(
        available_coin=available_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            b32(22),
            bytes32(available_inner.get_tree_hash()),
            uint64(1),
        ),
        reservation=reservation,
        signer_indices=(0, 2),
        terms=terms,
    )
    reserved_inner = make_mint_offer_v5_inner(terms, reservation)
    assert result.reserved_coin.parent_coin_info == available_coin.name()
    assert result.reserved_coin.puzzle_hash == bytes32(
        SINGLETON_MOD.curry(
            singleton_struct,
            reserved_inner,
        ).get_tree_hash()
    )
    assert result.validator_message == inventory_reservation_message(
        available_coin=available_coin,
        reservation=reservation,
    )

    other = replace(
        receipt.artifact,
        authorization_nonce=b32(23),
    )
    other_inner = make_mint_offer_v5_inner(
        terms,
        InventoryReservationV1(
            artifact=other,
            expires_at=other.quote_expires_at,
        ),
    )
    assert other_inner.get_tree_hash() != reserved_inner.get_tree_hash()


def test_reserved_inventory_extends_and_releases_only_to_canonical_states() -> None:
    receipt, terms = settlement()
    reservation = InventoryReservationV1(
        artifact=receipt.artifact,
        expires_at=receipt.artifact.quote_expires_at,
    )
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (receipt.artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    available_inner = make_inventory_available_inner(terms)
    available_full = SINGLETON_MOD.curry(singleton_struct, available_inner)
    available_coin = Coin(
        b32(24),
        bytes32(available_full.get_tree_hash()),
        uint64(1),
    )
    reserved = build_inventory_reservation_spend(
        available_coin=available_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            b32(25),
            bytes32(available_inner.get_tree_hash()),
            uint64(1),
        ),
        reservation=reservation,
        signer_indices=(0, 1),
        terms=terms,
    )
    reserved_lineage = LineageProof(
        available_coin.parent_coin_info,
        bytes32(available_inner.get_tree_hash()),
        uint64(1),
    )
    next_expiry = reservation.expires_at + 24 * 60 * 60
    extended = build_inventory_extension_spend(
        reserved_coin=reserved.reserved_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=reserved_lineage,
        reservation=reservation,
        next_expires_at=next_expiry,
        signer_indices=(0, 2),
        terms=terms,
    )
    _cost, extension_conditions = Program.from_bytes(
        bytes(extended.spend.puzzle_reveal)
    ).run_with_cost(
        11_000_000_000,
        Program.from_bytes(bytes(extended.spend.solution)),
    )
    extension_outputs = [
        row
        for row in extension_conditions.as_python()
        if row[0] == ConditionOpcode.CREATE_COIN.value
    ]
    assert any(
        row[1] == bytes(extended.next_coin.puzzle_hash)
        and int.from_bytes(row[2], "big") == 1
        for row in extension_outputs
    ), (extension_outputs, extended.next_coin.puzzle_hash.hex())
    extension_signatures = [
        row
        for row in extension_conditions.as_python()
        if row[0] == ConditionOpcode.AGG_SIG_ME.value
    ]
    assert len(extension_signatures) == 2
    assert {
        row[2] for row in extension_signatures
    } == {bytes(extended.validator_message)}

    released = build_inventory_release_spend(
        reserved_coin=reserved.reserved_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=reserved_lineage,
        reservation=reservation,
        terms=terms,
        timed_out=False,
        signer_indices=(1, 2),
    )
    _cost, release_conditions = Program.from_bytes(
        bytes(released.spend.puzzle_reveal)
    ).run_with_cost(
        11_000_000_000,
        Program.from_bytes(bytes(released.spend.solution)),
    )
    release_outputs = [
        row
        for row in release_conditions.as_python()
        if row[0] == ConditionOpcode.CREATE_COIN.value
    ]
    assert any(
        row[1] == bytes(released.next_coin.puzzle_hash)
        and int.from_bytes(row[2], "big") == 1
        for row in release_outputs
    ), (release_outputs, released.next_coin.puzzle_hash.hex())
    release_signatures = [
        row
        for row in release_conditions.as_python()
        if row[0] == ConditionOpcode.AGG_SIG_ME.value
    ]
    assert len(release_signatures) == 2
    assert {
        row[2] for row in release_signatures
    } == {bytes(released.validator_message)}

    timed_out = build_inventory_release_spend(
        reserved_coin=reserved.reserved_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=reserved_lineage,
        reservation=reservation,
        terms=terms,
        timed_out=True,
    )
    _cost, timeout_conditions = Program.from_bytes(
        bytes(timed_out.spend.puzzle_reveal)
    ).run_with_cost(
        11_000_000_000,
        Program.from_bytes(bytes(timed_out.spend.solution)),
    )
    assert timed_out.validator_message is None
    assert not any(
        row[0] == ConditionOpcode.AGG_SIG_ME.value
        for row in timeout_conditions.as_python()
    )
    assert any(
        row[0] == ConditionOpcode.ASSERT_SECONDS_ABSOLUTE.value
        and int.from_bytes(row[1], "big") == reservation.expires_at
        for row in timeout_conditions.as_python()
    )
    assert any(
        row[0] == ConditionOpcode.CREATE_COIN.value
        and row[1] == bytes(timed_out.next_coin.puzzle_hash)
        and int.from_bytes(row[2], "big") == 1
        for row in timeout_conditions.as_python()
    )


def test_receipt_and_mint_fail_closed_on_vault_or_roster_drift() -> None:
    receipt, terms = settlement()
    with pytest.raises(PaymentArtifactError, match="roster"):
        make_stripe_receipt_puzzle(
            receipt=receipt,
            validator_pubkeys=tuple(reversed(terms.validator_pubkeys)),
        )
    altered = replace(
        receipt.artifact,
        vault_p2_puzzle_hash=b32(99),
    )
    with pytest.raises(PaymentArtifactError, match="canonical"):
        from solslot_puzzles.stripe_settlement_v1_driver import (
            assert_artifact_matches_terms,
        )

        assert_artifact_matches_terms(altered, terms)
