from __future__ import annotations

from dataclasses import replace

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.conditions import CreateCoin
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia.wallet.trading.offer import OFFER_MOD_HASH, Offer
from chia.wallet.wallet_spend_bundle import WalletSpendBundle
from chia_rs import AugSchemeMPL, G2Element
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.payment_artifacts_v2 import (
    MANUAL_RELEASE_DELAY_SECONDS,
    PaymentArtifactError,
    PaymentAttestationV1,
    PaymentRail,
    PaymentResolution,
    PaymentTransition,
    PurchaseArtifactV2,
)
from solslot_puzzles.primary_purchase_v2_driver import (
    PrimaryMintTermsV2,
    build_chia_primary_offer,
    build_payment_escrow_spend,
    chia_offer_v2_solution,
    chia_cat_driver,
    delivery_message,
    escrow_coin_amount,
    make_mint_offer_v2_inner,
    make_payment_escrow_puzzle,
    mint_offer_v2_solution,
    prepare_chia_buyer_offer,
    smart_deed_singleton_driver,
)
from solslot_puzzles.vault_driver import puzzle_for_p2_vault


CREATE_COIN = bytes([51])
SEND_MESSAGE = bytes([66])
RECEIVE_MESSAGE = bytes([67])
AGG_SIG_ME = bytes([50])
ASSERT_SECONDS_ABSOLUTE = bytes([81])
ASSERT_BEFORE_SECONDS_ABSOLUTE = bytes([85])
ASSERT_PUZZLE_ANNOUNCEMENT = bytes([63])
PROTOCOL_PREFIX = b"\x53"


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


VALIDATORS = (
    bytes([1]) * 48,
    bytes([2]) * 48,
    bytes([3]) * 48,
)
PROTOCOL_PUZHASH = _b32(4)
REFUND_PUZHASH = _b32(5)
PROVIDER_ID = _b32(6)
VAULT_LAUNCHER_ID = _b32(7)
VAULT_P2 = bytes32(
    puzzle_for_p2_vault(VAULT_LAUNCHER_ID).get_tree_hash()
)


def _artifact(rail: PaymentRail = PaymentRail.STRIPE) -> PurchaseArtifactV2:
    common = {
        "network": "testnet11",
        "collection_id": _b32(20),
        "deed_launcher_id": _b32(21),
        "metadata_root": _b32(22),
        "metadata_anchor_id": _b32(23),
        "share_ppm": 250_000,
        "usd_amount_minor": 125_000,
        "vault_launcher_id": VAULT_LAUNCHER_ID,
        "vault_p2_puzzle_hash": VAULT_P2,
        "authorization_nonce": _b32(26),
        "authorization_expires_at": 1_800_001_200,
        "quote_expires_at": 1_800_000_600,
    }
    if rail == PaymentRail.STRIPE:
        return PurchaseArtifactV2(
            **common,
            rail=rail,
            rail_chain_id=0,
            rail_asset_id=bytes32.zeros,
            rail_asset_decimals=2,
            rail_amount=125_000,
        )
    if rail == PaymentRail.EVM_TEST_USD:
        return PurchaseArtifactV2(
            **common,
            rail=rail,
            rail_chain_id=84532,
            rail_asset_id=_b32(27),
            rail_asset_decimals=6,
            rail_amount=1_250_000_000,
        )
    if rail == PaymentRail.CHIA_CAT:
        return PurchaseArtifactV2(
            **common,
            rail=rail,
            rail_chain_id=0,
            rail_asset_id=_b32(27),
            rail_asset_decimals=3,
            rail_amount=1_250_000,
            oracle_round_hash=_b32(28),
            oracle_price_usd_minor_per_asset=100,
            source_evidence_root=_b32(29),
        )
    return PurchaseArtifactV2(
        **common,
        rail=rail,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=12,
        rail_amount=58_823_529_411_765,
        oracle_round_hash=_b32(28),
        oracle_price_usd_minor_per_asset=2_125,
        source_evidence_root=_b32(29),
    )


def _pending(artifact: PurchaseArtifactV2) -> PaymentAttestationV1:
    return PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=PROVIDER_ID,
        external_reference_hash=_b32(30),
        evidence_hash=_b32(31),
        previous_attestation_hash=bytes32.zeros,
        observed_at=1_800_000_000,
    )


def _resolution(
    artifact: PurchaseArtifactV2,
    *,
    transition: PaymentTransition = PaymentTransition.SUCCEEDED,
    resolution: PaymentResolution = PaymentResolution.DELIVER,
    observed_at: int = 1_800_000_100,
    reason_hash: bytes32 = bytes32.zeros,
) -> PaymentAttestationV1:
    pending = _pending(artifact)
    return PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=transition,
        resolution=resolution,
        provider_id=PROVIDER_ID,
        external_reference_hash=pending.external_reference_hash,
        evidence_hash=_b32(32),
        previous_attestation_hash=pending.attestation_hash,
        observed_at=observed_at,
        reason_hash=reason_hash,
    )


def _mint_terms(artifact: PurchaseArtifactV2) -> PrimaryMintTermsV2:
    return PrimaryMintTermsV2(
        network=artifact.network,
        smart_deed_inner_hash=_b32(40),
        deed_launcher_id=artifact.deed_launcher_id,
        collection_id=artifact.collection_id,
        metadata_root=artifact.metadata_root,
        metadata_anchor_id=artifact.metadata_anchor_id,
        share_ppm=artifact.share_ppm,
        usd_amount_minor=artifact.usd_amount_minor,
        protocol_puzhash=PROTOCOL_PUZHASH,
        validator_pubkeys=VALIDATORS,
        provider_id=PROVIDER_ID,
    )


def _buyer_xch_offer(
    artifact: PurchaseArtifactV2,
    terms: PrimaryMintTermsV2,
) -> Offer:
    puzzle = Program.to(1)
    coin = Coin(
        _b32(70),
        bytes32(puzzle.get_tree_hash()),
        uint64(artifact.rail_amount),
    )
    driver = smart_deed_singleton_driver(artifact.deed_launcher_id)
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
    notarized = Offer.notarize_payments(requested, [coin])
    announcements = Offer.calculate_announcements(
        notarized,
        {artifact.deed_launcher_id: driver},
    )
    conditions = [
        CreateCoin(
            OFFER_MOD_HASH,
            uint64(artifact.rail_amount),
            [OFFER_MOD_HASH],
        ).to_program(),
        *(item.to_program() for item in announcements),
    ]
    spend = make_spend(
        coin,
        puzzle,
        Program.to([item.as_python() for item in conditions]),
    )
    return Offer(
        notarized,
        WalletSpendBundle([spend], G2Element()),
        {artifact.deed_launcher_id: driver},
    )


def _buyer_cat_offer(
    artifact: PurchaseArtifactV2,
    terms: PrimaryMintTermsV2,
    tail: Program,
) -> Offer:
    puzzle = Program.to(1)
    cat_puzzle = construct_cat_puzzle(
        CAT_MOD,
        artifact.rail_asset_id,
        puzzle,
    )
    coin = Coin(
        _b32(73),
        bytes32(cat_puzzle.get_tree_hash()),
        uint64(artifact.rail_amount),
    )
    drivers = {
        artifact.deed_launcher_id: smart_deed_singleton_driver(
            artifact.deed_launcher_id
        ),
        artifact.rail_asset_id: chia_cat_driver(
            artifact.rail_asset_id
        ),
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
    notarized = Offer.notarize_payments(requested, [coin])
    announcements = Offer.calculate_announcements(notarized, drivers)
    inner_solution = Program.to(
        [
            [51, 0, -113, tail, []],
            [51, OFFER_MOD_HASH, artifact.rail_amount],
            *(item.to_program().as_python() for item in announcements),
        ]
    )
    bundle = unsigned_spend_bundle_for_spendable_cats(
        CAT_MOD,
        [
            SpendableCAT(
                coin,
                artifact.rail_asset_id,
                puzzle,
                inner_solution,
            )
        ],
    )
    return Offer(notarized, bundle, drivers)


def test_prepare_xch_buyer_offer_binds_vault_quote_and_change() -> None:
    artifact = _artifact(PaymentRail.CHIA_XCH)
    terms = _mint_terms(artifact)
    key = AugSchemeMPL.key_gen(bytes([91]) * 32)
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
        puzzle_for_pk,
    )

    payment_puzzle = puzzle_for_pk(key.get_g1())
    coin = Coin(
        _b32(90),
        bytes32(payment_puzzle.get_tree_hash()),
        uint64(artifact.rail_amount + 123),
    )
    prepared = prepare_chia_buyer_offer(
        payment_coin=coin,
        payment_public_key=bytes(key.get_g1()),
        artifact=artifact,
        terms=terms,
    )

    assert prepared.offer.get_offered_amounts() == {
        None: artifact.rail_amount
    }
    payment = prepared.offer.requested_payments[
        artifact.deed_launcher_id
    ][0]
    assert payment.puzzle_hash == artifact.vault_p2_puzzle_hash
    assert list(payment.memos)[-2:] == [
        artifact.purchase_id,
        artifact.artifact_hash,
    ]
    additions = prepared.offer.additions()
    assert any(
        addition.puzzle_hash == OFFER_MOD_HASH
        and int(addition.amount) == artifact.rail_amount
        for addition in additions
    )
    assert any(
        addition.puzzle_hash == payment_puzzle.get_tree_hash()
        and int(addition.amount) == 123
        for addition in additions
    )


def test_prepare_cat_buyer_offer_binds_asset_and_requires_lineage() -> None:
    artifact = _artifact(PaymentRail.CHIA_CAT)
    terms = _mint_terms(artifact)
    key = AugSchemeMPL.key_gen(bytes([92]) * 32)
    from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
        puzzle_for_pk,
    )

    inner = puzzle_for_pk(key.get_g1())
    outer = construct_cat_puzzle(CAT_MOD, artifact.rail_asset_id, inner)
    parent_coin = Coin(
        _b32(93),
        bytes32(outer.get_tree_hash()),
        uint64(artifact.rail_amount + 17),
    )
    coin = Coin(
        bytes32(parent_coin.name()),
        bytes32(outer.get_tree_hash()),
        uint64(artifact.rail_amount + 17),
    )
    with pytest.raises(PaymentArtifactError, match="lineage proof"):
        prepare_chia_buyer_offer(
            payment_coin=coin,
            payment_public_key=bytes(key.get_g1()),
            artifact=artifact,
            terms=terms,
        )

    prepared = prepare_chia_buyer_offer(
        payment_coin=coin,
        payment_public_key=bytes(key.get_g1()),
        artifact=artifact,
        terms=terms,
        cat_lineage_proof=LineageProof(
            parent_name=parent_coin.parent_coin_info,
            inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            amount=parent_coin.amount,
        ),
    )
    assert prepared.offer.get_offered_amounts() == {
        artifact.rail_asset_id: artifact.rail_amount
    }
    assert prepared.offer.driver_dict[artifact.rail_asset_id].info == (
        chia_cat_driver(artifact.rail_asset_id).info
    )


def test_stripe_success_emits_two_signatures_payment_and_delivery() -> None:
    artifact = _artifact()
    pending = _pending(artifact)
    resolution = _resolution(artifact)
    puzzle = make_payment_escrow_puzzle(
        artifact=artifact,
        pending_attestation=pending,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
    )
    coin = Coin(_b32(50), bytes32(puzzle.get_tree_hash()), 1)
    spend = build_payment_escrow_spend(
        escrow_coin=coin,
        artifact=artifact,
        pending_attestation=pending,
        resolution_attestation=resolution,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
        signer_indices=(0, 2),
    )
    conditions = spend.puzzle.run(spend.solution).as_python()
    signatures = [item for item in conditions if item[0] == AGG_SIG_ME]
    assert signatures == [
        [AGG_SIG_ME, VALIDATORS[0], bytes(resolution.attestation_hash)],
        [AGG_SIG_ME, VALIDATORS[2], bytes(resolution.attestation_hash)],
    ]
    payment = next(item for item in conditions if item[0] == CREATE_COIN)
    assert payment[1] == PROTOCOL_PUZHASH
    assert int.from_bytes(payment[2], "big") == 1
    sent = next(item for item in conditions if item[0] == SEND_MESSAGE)
    assert sent[2] == PROTOCOL_PREFIX + bytes(
        delivery_message(
            purchase_id=artifact.purchase_id,
            artifact_hash=artifact.artifact_hash,
            vault_p2_puzzle_hash=artifact.vault_p2_puzzle_hash,
        )
    )


def test_failed_payment_refunds_without_delivery_message() -> None:
    artifact = _artifact(PaymentRail.EVM_TEST_USD)
    pending = _pending(artifact)
    resolution = _resolution(
        artifact,
        transition=PaymentTransition.FAILED,
        resolution=PaymentResolution.REFUND,
    )
    puzzle = make_payment_escrow_puzzle(
        artifact=artifact,
        pending_attestation=pending,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
    )
    coin = Coin(
        _b32(51),
        bytes32(puzzle.get_tree_hash()),
        escrow_coin_amount(artifact),
    )
    spend = build_payment_escrow_spend(
        escrow_coin=coin,
        artifact=artifact,
        pending_attestation=pending,
        resolution_attestation=resolution,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
        signer_indices=(0, 1),
    )
    conditions = spend.puzzle.run(spend.solution).as_python()
    refund = next(item for item in conditions if item[0] == CREATE_COIN)
    assert refund[1] == REFUND_PUZHASH
    assert int.from_bytes(refund[2], "big") == 1
    assert not any(item[0] == SEND_MESSAGE for item in conditions)


def test_manual_release_is_seven_day_locked_and_resolution_bound() -> None:
    artifact = _artifact()
    pending = _pending(artifact)
    release = _resolution(
        artifact,
        transition=PaymentTransition.MANUAL_RELEASE,
        resolution=PaymentResolution.REFUND,
        observed_at=pending.observed_at + MANUAL_RELEASE_DELAY_SECONDS,
        reason_hash=_b32(33),
    )
    puzzle = make_payment_escrow_puzzle(
        artifact=artifact,
        pending_attestation=pending,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
    )
    coin = Coin(_b32(52), bytes32(puzzle.get_tree_hash()), 1)
    spend = build_payment_escrow_spend(
        escrow_coin=coin,
        artifact=artifact,
        pending_attestation=pending,
        resolution_attestation=release,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
        signer_indices=(1, 2),
    )
    conditions = spend.puzzle.run(spend.solution).as_python()
    absolute_times = [
        int.from_bytes(item[1], "big")
        for item in conditions
        if item[0] == ASSERT_SECONDS_ABSOLUTE
    ]
    assert pending.observed_at + MANUAL_RELEASE_DELAY_SECONDS in absolute_times
    assert any(item[0] == ASSERT_BEFORE_SECONDS_ABSOLUTE for item in conditions)


def test_driver_rejects_early_manual_release_and_duplicate_signers() -> None:
    artifact = _artifact()
    pending = _pending(artifact)
    release = _resolution(
        artifact,
        transition=PaymentTransition.MANUAL_RELEASE,
        resolution=PaymentResolution.DELIVER,
        observed_at=pending.observed_at + MANUAL_RELEASE_DELAY_SECONDS - 1,
        reason_hash=_b32(33),
    )
    puzzle = make_payment_escrow_puzzle(
        artifact=artifact,
        pending_attestation=pending,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
    )
    coin = Coin(_b32(53), bytes32(puzzle.get_tree_hash()), 1)
    with pytest.raises(PaymentArtifactError, match="seven-day"):
        build_payment_escrow_spend(
            escrow_coin=coin,
            artifact=artifact,
            pending_attestation=pending,
            resolution_attestation=release,
            protocol_puzhash=PROTOCOL_PUZHASH,
            refund_puzhash=REFUND_PUZHASH,
            validator_pubkeys=VALIDATORS,
            signer_indices=(0, 2),
        )
    with pytest.raises(PaymentArtifactError, match="unique sorted"):
        build_payment_escrow_spend(
            escrow_coin=coin,
            artifact=artifact,
            pending_attestation=pending,
            resolution_attestation=_resolution(artifact),
            protocol_puzhash=PROTOCOL_PUZHASH,
            refund_puzhash=REFUND_PUZHASH,
            validator_pubkeys=VALIDATORS,
            signer_indices=(0, 0),
        )


@pytest.mark.parametrize(
    "rail",
    [PaymentRail.STRIPE, PaymentRail.EVM_TEST_USD],
)
def test_mint_offer_accepts_exact_escrow_and_delivers_to_p2_vault(
    rail: PaymentRail,
) -> None:
    artifact = _artifact(rail)
    pending = _pending(artifact)
    terms = _mint_terms(artifact)
    inner = make_mint_offer_v2_inner(terms)
    solution = mint_offer_v2_solution(
        deed_coin_id=_b32(60),
        artifact=artifact,
        pending_attestation=pending,
        refund_puzhash=REFUND_PUZHASH,
        terms=terms,
    )
    conditions = inner.run(solution).as_python()
    deed_output = next(item for item in conditions if item[0] == CREATE_COIN)
    assert deed_output[1] == VAULT_P2
    assert int.from_bytes(deed_output[2], "big") == 1

    received = next(item for item in conditions if item[0] == RECEIVE_MESSAGE)
    escrow = make_payment_escrow_puzzle(
        artifact=artifact,
        pending_attestation=pending,
        protocol_puzhash=PROTOCOL_PUZHASH,
        refund_puzhash=REFUND_PUZHASH,
        validator_pubkeys=VALIDATORS,
    )
    assert received[2] == PROTOCOL_PREFIX + bytes(
        delivery_message(
            purchase_id=artifact.purchase_id,
            artifact_hash=artifact.artifact_hash,
            vault_p2_puzzle_hash=artifact.vault_p2_puzzle_hash,
        )
    )
    assert received[3] == escrow.get_tree_hash()


@pytest.mark.parametrize(
    "rail",
    [PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT],
)
def test_native_chia_rails_cannot_enter_external_escrow(
    rail: PaymentRail,
) -> None:
    artifact = _artifact(rail)
    with pytest.raises(PaymentArtifactError, match="offer files"):
        escrow_coin_amount(artifact)
    with pytest.raises(PaymentArtifactError, match="cannot create"):
        make_payment_escrow_puzzle(
            artifact=artifact,
            pending_attestation=_pending(artifact),
            protocol_puzhash=PROTOCOL_PUZHASH,
            refund_puzhash=REFUND_PUZHASH,
            validator_pubkeys=VALIDATORS,
        )


def test_xch_buyer_offer_and_governed_deed_offer_balance_atomically() -> None:
    artifact = _artifact(PaymentRail.CHIA_XCH)
    terms = _mint_terms(artifact)
    buyer_offer = _buyer_xch_offer(artifact, terms)
    inner = make_mint_offer_v2_inner(terms)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    full_puzzle = SINGLETON_MOD.curry(singleton_struct, inner)
    deed_coin = Coin(
        _b32(71),
        bytes32(full_puzzle.get_tree_hash()),
        uint64(1),
    )
    purchase = build_chia_primary_offer(
        buyer_offer=buyer_offer,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            parent_name=_b32(72),
            inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            amount=uint64(1),
        ),
        artifact=artifact,
        signer_indices=(0, 2),
        terms=terms,
    )

    assert buyer_offer.get_offered_amounts() == {
        None: artifact.rail_amount
    }
    assert purchase.aggregate_offer.is_valid()
    assert purchase.aggregate_offer.arbitrage() == {
        artifact.deed_launcher_id: 0,
        None: 0,
    }
    encoded = purchase.aggregate_offer.to_bech32()
    restored = Offer.from_bech32(encoded)
    assert restored.is_valid()
    assert restored.name() == purchase.aggregate_offer.name()
    assert len(restored.to_valid_spend().coin_spends) == 4

    native_conditions = inner.run(
        chia_offer_v2_solution(
            deed_coin=deed_coin,
            artifact=artifact,
            buyer_offer_nonce=next(
                iter(buyer_offer.requested_payments.values())
            )[0].nonce,
            signer_indices=(0, 2),
            terms=terms,
        )
    ).as_python()
    assert len(
        actual_announcements := {
            bytes32(item[1])
            for item in native_conditions
            if item[0] == ASSERT_PUZZLE_ANNOUNCEMENT
        }
    ) == 2
    expected_announcements = {
        item.msg_calc
        for offer in (buyer_offer, purchase.issuer_offer)
        for item in Offer.calculate_announcements(
            offer.requested_payments,
            offer.driver_dict,
        )
    }
    assert actual_announcements == expected_announcements
    assert [
        item[1]
        for item in native_conditions
        if item[0] == AGG_SIG_ME
    ] == [VALIDATORS[0], VALIDATORS[2]]


def test_cat_buyer_offer_and_governed_deed_offer_balance_atomically() -> None:
    tail = Program.to([3, [], [1, b"solslot-test-cat"], []])
    artifact = replace(
        _artifact(PaymentRail.CHIA_CAT),
        rail_asset_id=bytes32(tail.get_tree_hash()),
    )
    terms = _mint_terms(artifact)
    buyer_offer = _buyer_cat_offer(artifact, terms, tail)
    inner = make_mint_offer_v2_inner(terms)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (artifact.deed_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    full_puzzle = SINGLETON_MOD.curry(singleton_struct, inner)
    deed_coin = Coin(
        _b32(74),
        bytes32(full_puzzle.get_tree_hash()),
        uint64(1),
    )
    purchase = build_chia_primary_offer(
        buyer_offer=buyer_offer,
        deed_coin=deed_coin,
        deed_singleton_struct=singleton_struct,
        lineage_proof=LineageProof(
            parent_name=_b32(75),
            inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            amount=uint64(1),
        ),
        artifact=artifact,
        signer_indices=(1, 2),
        terms=terms,
    )

    assert buyer_offer.get_offered_amounts() == {
        artifact.rail_asset_id: artifact.rail_amount
    }
    assert purchase.aggregate_offer.is_valid()
    assert purchase.aggregate_offer.arbitrage() == {
        artifact.deed_launcher_id: 0,
        artifact.rail_asset_id: 0,
    }
    restored = Offer.from_bech32(
        purchase.aggregate_offer.to_bech32()
    )
    assert restored.is_valid()
    assert restored.name() == purchase.aggregate_offer.name()
    assert len(restored.to_valid_spend().coin_spends) == 4

    native_conditions = inner.run(
        chia_offer_v2_solution(
            deed_coin=deed_coin,
            artifact=artifact,
            buyer_offer_nonce=next(
                iter(buyer_offer.requested_payments.values())
            )[0].nonce,
            signer_indices=(1, 2),
            terms=terms,
        )
    ).as_python()
    actual_announcements = {
        bytes32(item[1])
        for item in native_conditions
        if item[0] == ASSERT_PUZZLE_ANNOUNCEMENT
    }
    expected_announcements = {
        item.msg_calc
        for offer in (buyer_offer, purchase.issuer_offer)
        for item in Offer.calculate_announcements(
            offer.requested_payments,
            offer.driver_dict,
        )
    }
    assert actual_announcements == expected_announcements


def test_mint_offer_rejects_noncanonical_vault_destination() -> None:
    artifact = replace(_artifact(), vault_p2_puzzle_hash=_b32(61))
    with pytest.raises(PaymentArtifactError, match="not canonical"):
        mint_offer_v2_solution(
            deed_coin_id=_b32(60),
            artifact=artifact,
            pending_attestation=_pending(artifact),
            refund_puzhash=REFUND_PUZHASH,
            terms=_mint_terms(artifact),
        )
