from __future__ import annotations

from dataclasses import replace

import pytest
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    MANUAL_RELEASE_DELAY_SECONDS,
    XCH_ASSET_DECIMALS,
    DeedPriceV1,
    OracleObservationV1,
    PaymentArtifactError,
    PaymentAttestationV1,
    PaymentRail,
    PaymentResolution,
    PaymentTransition,
    PurchaseArtifactV2,
    VaultAuthScheme,
    VaultPurchaseAuthorizationV1,
    asset_units_for_usd,
    assert_provider_threshold,
    build_cat_purchase_artifact,
    build_evm_test_usd_purchase_artifact,
    build_oracle_round,
    build_stripe_purchase_artifact,
    build_xch_purchase_artifact,
    oracle_round_from_json,
    oracle_operator_set_root,
    oracle_round_signature_message,
    oracle_round_to_json,
    purchase_artifact_from_json,
    purchase_artifact_to_json,
    test_usd_units as convert_test_usd_units,
    validate_deed_price_plan,
    validate_manual_release,
    xch_mojos_for_usd,
)
from solslot_puzzles.vault_driver import (
    puzzle_for_p2_vault,
    puzzle_hash_for_p2_vault,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _observations() -> tuple[OracleObservationV1, ...]:
    return (
        OracleObservationV1(
            source_id=_b32(1),
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            price_usd_minor_per_asset=2_100,
            observed_at=1_700_000_000,
            valid_until=1_700_000_600,
            evidence_hash=_b32(11),
        ),
        OracleObservationV1(
            source_id=_b32(2),
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            price_usd_minor_per_asset=2_125,
            observed_at=1_700_000_010,
            valid_until=1_700_000_610,
            evidence_hash=_b32(12),
        ),
        OracleObservationV1(
            source_id=_b32(3),
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            price_usd_minor_per_asset=2_150,
            observed_at=1_700_000_020,
            valid_until=1_700_000_620,
            evidence_hash=_b32(13),
        ),
    )


def _oracle_round():
    return build_oracle_round(
        network="testnet11",
        sequence=17,
        asset_id=bytes32.zeros,
        asset_decimals=XCH_ASSET_DECIMALS,
        operator_set_root=_b32(9),
        observations=_observations(),
    )


def _stripe_artifact() -> PurchaseArtifactV2:
    return PurchaseArtifactV2(
        network="testnet11",
        collection_id=_b32(20),
        deed_launcher_id=_b32(21),
        metadata_root=_b32(22),
        metadata_anchor_id=_b32(23),
        share_ppm=250_000,
        usd_amount_minor=125_000,
        rail=PaymentRail.STRIPE,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=2,
        rail_amount=125_000,
        vault_launcher_id=_b32(24),
        vault_p2_puzzle_hash=_b32(25),
        authorization_nonce=_b32(26),
        authorization_expires_at=1_700_001_200,
        quote_expires_at=1_700_000_600,
    )


def test_sealed_deed_price_plan_is_order_independent() -> None:
    deeds = (
        DeedPriceV1(_b32(31), 400_000, 200_000),
        DeedPriceV1(_b32(30), 600_000, 300_000),
    )
    root = validate_deed_price_plan(
        deeds,
        target_raise_usd_minor=500_000,
    )
    assert root == validate_deed_price_plan(
        tuple(reversed(deeds)),
        target_raise_usd_minor=500_000,
    )


@pytest.mark.parametrize(
    "deeds,target,error",
    [
        (
            (
                DeedPriceV1(_b32(30), 500_000, 250_000),
                DeedPriceV1(_b32(31), 499_999, 250_000),
            ),
            500_000,
            "shares",
        ),
        (
            (
                DeedPriceV1(_b32(30), 500_000, 250_000),
                DeedPriceV1(_b32(31), 500_000, 249_999),
            ),
            500_000,
            "USD prices",
        ),
        (
            (
                DeedPriceV1(_b32(30), 500_000, 250_000),
                DeedPriceV1(_b32(30), 500_000, 250_000),
            ),
            500_000,
            "duplicate",
        ),
    ],
)
def test_sealed_deed_price_plan_rejects_drift(
    deeds: tuple[DeedPriceV1, ...],
    target: int,
    error: str,
) -> None:
    with pytest.raises(PaymentArtifactError, match=error):
        validate_deed_price_plan(deeds, target_raise_usd_minor=target)


def test_integer_only_payment_unit_conversions() -> None:
    assert convert_test_usd_units(12_345) == 123_450_000
    assert xch_mojos_for_usd(10_000, 2_500) == 4_000_000_000_000
    assert xch_mojos_for_usd(1, 3) == 333_333_333_334
    assert asset_units_for_usd(
        125_000,
        asset_decimals=3,
        asset_price_usd_minor=100,
    ) == 1_250_000


def test_oracle_round_uses_sorted_sources_and_upper_median() -> None:
    oracle_round = _oracle_round()
    assert oracle_round.asset_id == bytes32.zeros
    assert oracle_round.asset_decimals == XCH_ASSET_DECIMALS
    assert oracle_round.price_usd_minor_per_asset == 2_125
    assert oracle_round.valid_from == 1_700_000_020
    assert oracle_round.valid_until == 1_700_000_600
    assert tuple(item.source_id for item in oracle_round.observations) == (
        _b32(1),
        _b32(2),
        _b32(3),
    )
    oracle_round.assert_live(1_700_000_300)


def test_oracle_round_rejects_duplicate_sources() -> None:
    duplicate = replace(_observations()[1], source_id=_b32(1))
    with pytest.raises(PaymentArtifactError, match="unique"):
        build_oracle_round(
            network="testnet11",
            sequence=17,
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            operator_set_root=_b32(9),
            observations=(_observations()[0], duplicate),
        )


def test_oracle_round_rejects_excessive_dispersion() -> None:
    divergent = replace(
        _observations()[1],
        price_usd_minor_per_asset=2_300,
    )
    with pytest.raises(PaymentArtifactError, match="dispersion"):
        build_oracle_round(
            network="testnet11",
            sequence=17,
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            operator_set_root=_b32(9),
            observations=(_observations()[0], divergent),
        )


def test_oracle_observation_rejects_overlong_validity() -> None:
    with pytest.raises(PaymentArtifactError, match="validity"):
        OracleObservationV1(
            source_id=_b32(1),
            asset_id=bytes32.zeros,
            asset_decimals=XCH_ASSET_DECIMALS,
            price_usd_minor_per_asset=2_100,
            observed_at=1_700_000_000,
            valid_until=1_700_000_901,
            evidence_hash=_b32(11),
        )


def test_xch_artifact_binds_oracle_and_ceil_amount() -> None:
    artifact = build_xch_purchase_artifact(
        network="testnet11",
        collection_id=_b32(20),
        deed_launcher_id=_b32(21),
        metadata_root=_b32(22),
        metadata_anchor_id=_b32(23),
        share_ppm=250_000,
        usd_amount_minor=125_000,
        vault_launcher_id=_b32(24),
        vault_p2_puzzle_hash=_b32(25),
        authorization_nonce=_b32(26),
        authorization_expires_at=1_700_001_200,
        quote_expires_at=1_700_000_590,
        oracle_round=_oracle_round(),
    )
    assert artifact.rail == PaymentRail.CHIA_XCH
    assert artifact.rail_asset_decimals == XCH_ASSET_DECIMALS
    assert artifact.rail_amount == xch_mojos_for_usd(125_000, 2_125)
    assert artifact.oracle_round_hash == _oracle_round().round_hash
    assert artifact.purchase_id != artifact.artifact_hash
    artifact.assert_live(1_700_000_500)


def test_strict_json_transports_round_trip_canonical_clvm() -> None:
    round_ = _oracle_round()
    assert oracle_round_from_json(oracle_round_to_json(round_)) == round_

    artifact = _stripe_artifact()
    assert (
        purchase_artifact_from_json(purchase_artifact_to_json(artifact))
        == artifact
    )


def test_strict_json_transports_reject_unknown_and_tampered_fields() -> None:
    artifact_json = purchase_artifact_to_json(_stripe_artifact())
    artifact_json["extra"] = "not canonical"
    with pytest.raises(PaymentArtifactError, match="unknown extra"):
        purchase_artifact_from_json(artifact_json)

    round_json = oracle_round_to_json(_oracle_round())
    round_json["observations"][0]["priceUsdMinorPerAsset"] += 1
    with pytest.raises(
        PaymentArtifactError,
        match="oracle observation hash",
    ):
        oracle_round_from_json(round_json)


def test_oracle_roster_and_signature_message_are_domain_bound() -> None:
    keys = tuple(
        AugSchemeMPL.key_gen(bytes([seed]) * 32)
        for seed in (61, 62, 63)
    )
    pubkeys = tuple(bytes(key.get_g1()) for key in keys)
    root = oracle_operator_set_root(pubkeys)
    assert root != bytes32.zeros

    message = oracle_round_signature_message(_oracle_round().round_hash)
    signature = AugSchemeMPL.sign(keys[0], message)
    assert AugSchemeMPL.verify(keys[0].get_g1(), message, signature)
    assert not AugSchemeMPL.verify(
        keys[0].get_g1(),
        bytes(_oracle_round().round_hash),
        signature,
    )


def test_p2_vault_tree_hash_fast_path_matches_full_curry() -> None:
    launcher_id = _b32(91)
    assert puzzle_hash_for_p2_vault(launcher_id) == bytes32(
        puzzle_for_p2_vault(launcher_id).get_tree_hash()
    )


def test_xch_quote_cannot_outlive_oracle_round() -> None:
    with pytest.raises(PaymentArtifactError, match="outlive"):
        build_xch_purchase_artifact(
            network="testnet11",
            collection_id=_b32(20),
            deed_launcher_id=_b32(21),
            metadata_root=_b32(22),
            metadata_anchor_id=_b32(23),
            share_ppm=250_000,
            usd_amount_minor=125_000,
            vault_launcher_id=_b32(24),
            vault_p2_puzzle_hash=_b32(25),
            authorization_nonce=_b32(26),
            authorization_expires_at=1_700_001_200,
            quote_expires_at=1_700_000_601,
            oracle_round=_oracle_round(),
        )


def test_each_rail_enforces_its_exact_amount_and_evidence() -> None:
    stripe = _stripe_artifact()
    assert stripe.purchase_id == _stripe_artifact().purchase_id
    with pytest.raises(PaymentArtifactError, match="Stripe rail_amount"):
        replace(stripe, rail_amount=stripe.rail_amount + 1)

    evm = replace(
        stripe,
        rail=PaymentRail.EVM_TEST_USD,
        rail_chain_id=84532,
        rail_asset_id=_b32(40),
        rail_asset_decimals=6,
        rail_amount=convert_test_usd_units(stripe.usd_amount_minor),
    )
    assert evm.rail_chain_id == 84532
    with pytest.raises(PaymentArtifactError, match="six-decimal"):
        replace(evm, rail_amount=evm.rail_amount - 1)


def test_external_rail_builders_bind_exact_minor_and_base_units() -> None:
    common = {
        "network": "testnet11",
        "collection_id": _b32(20),
        "deed_launcher_id": _b32(21),
        "metadata_root": _b32(22),
        "metadata_anchor_id": _b32(23),
        "share_ppm": 250_000,
        "usd_amount_minor": 125_000,
        "vault_launcher_id": _b32(24),
        "vault_p2_puzzle_hash": _b32(25),
        "authorization_nonce": _b32(26),
        "authorization_expires_at": 1_700_001_200,
        "quote_expires_at": 1_700_000_600,
    }
    stripe = build_stripe_purchase_artifact(**common)
    assert stripe.rail == PaymentRail.STRIPE
    assert stripe.rail_amount == 125_000

    evm = build_evm_test_usd_purchase_artifact(
        **common,
        chain_id=84532,
        token_asset_id=_b32(40),
    )
    assert evm.rail == PaymentRail.EVM_TEST_USD
    assert evm.rail_amount == 1_250_000_000
    assert evm.rail_asset_decimals == 6


def test_cat_artifact_binds_asset_decimals_oracle_and_ceil_amount() -> None:
    cat_asset_id = _b32(40)
    observations = tuple(
        replace(
            item,
            asset_id=cat_asset_id,
            asset_decimals=3,
            price_usd_minor_per_asset=price,
        )
        for item, price in zip(_observations(), (99, 100, 101), strict=True)
    )
    oracle_round = build_oracle_round(
        network="testnet11",
        sequence=18,
        asset_id=cat_asset_id,
        asset_decimals=3,
        operator_set_root=_b32(9),
        observations=observations,
    )
    artifact = build_cat_purchase_artifact(
        network="testnet11",
        collection_id=_b32(20),
        deed_launcher_id=_b32(21),
        metadata_root=_b32(22),
        metadata_anchor_id=_b32(23),
        share_ppm=250_000,
        usd_amount_minor=125_000,
        cat_asset_id=cat_asset_id,
        cat_decimals=3,
        vault_launcher_id=_b32(24),
        vault_p2_puzzle_hash=_b32(25),
        authorization_nonce=_b32(26),
        authorization_expires_at=1_700_001_200,
        quote_expires_at=1_700_000_590,
        oracle_round=oracle_round,
    )
    assert artifact.rail == PaymentRail.CHIA_CAT
    assert artifact.rail_asset_id == cat_asset_id
    assert artifact.rail_asset_decimals == 3
    assert artifact.rail_amount == 1_250_000
    with pytest.raises(PaymentArtifactError, match="does not match"):
        build_cat_purchase_artifact(
            network="testnet11",
            collection_id=_b32(20),
            deed_launcher_id=_b32(21),
            metadata_root=_b32(22),
            metadata_anchor_id=_b32(23),
            share_ppm=250_000,
            usd_amount_minor=125_000,
            cat_asset_id=_b32(41),
            cat_decimals=3,
            vault_launcher_id=_b32(24),
            vault_p2_puzzle_hash=_b32(25),
            authorization_nonce=_b32(26),
            authorization_expires_at=1_700_001_200,
            quote_expires_at=1_700_000_590,
            oracle_round=oracle_round,
        )


def test_vault_authorization_is_bound_to_exact_artifact() -> None:
    artifact = _stripe_artifact()
    authorization = VaultPurchaseAuthorizationV1.for_artifact(
        artifact=artifact,
        auth_scheme=VaultAuthScheme.CHIA_BLS,
        signer_id=bytes([41]) * 48,
        issued_at=1_700_000_100,
    )
    authorization.assert_matches(artifact)
    assert authorization.authorization_hash != artifact.artifact_hash
    with pytest.raises(PaymentArtifactError, match="does not match"):
        authorization.assert_matches(
            replace(artifact, authorization_nonce=_b32(27))
        )


def test_vault_authorization_rejects_wrong_signer_shape() -> None:
    with pytest.raises(PaymentArtifactError, match="48 bytes"):
        VaultPurchaseAuthorizationV1.for_artifact(
            artifact=_stripe_artifact(),
            auth_scheme=VaultAuthScheme.CHIA_BLS,
            signer_id=bytes([41]) * 20,
            issued_at=1_700_000_100,
        )


def test_payment_attestation_manual_release_requires_delay_and_reason() -> None:
    artifact = _stripe_artifact()
    pending = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=_b32(50),
        external_reference_hash=_b32(51),
        evidence_hash=_b32(52),
        previous_attestation_hash=bytes32.zeros,
        observed_at=1_700_000_000,
    )
    release = PaymentAttestationV1(
        purchase_id=artifact.purchase_id,
        artifact_hash=artifact.artifact_hash,
        transition=PaymentTransition.MANUAL_RELEASE,
        resolution=PaymentResolution.REFUND,
        provider_id=_b32(50),
        external_reference_hash=_b32(51),
        evidence_hash=_b32(53),
        previous_attestation_hash=pending.attestation_hash,
        observed_at=1_700_000_000 + MANUAL_RELEASE_DELAY_SECONDS,
        reason_hash=_b32(54),
    )
    validate_manual_release(
        pending_attestation=pending,
        release_attestation=release,
    )
    with pytest.raises(PaymentArtifactError, match="seven-day"):
        validate_manual_release(
            pending_attestation=pending,
            release_attestation=replace(
                release,
                observed_at=release.observed_at - 1,
            ),
        )


def test_provider_threshold_rejects_duplicates_unknowns_and_one_signer() -> None:
    allowed = {_b32(60): object(), _b32(61): object(), _b32(62): object()}
    assert_provider_threshold(
        signer_ids=(_b32(60), _b32(61)),
        allowed_signers=allowed,
    )
    with pytest.raises(PaymentArtifactError, match="duplicate"):
        assert_provider_threshold(
            signer_ids=(_b32(60), _b32(60)),
            allowed_signers=allowed,
        )
    with pytest.raises(PaymentArtifactError, match="unknown"):
        assert_provider_threshold(
            signer_ids=(_b32(60), _b32(63)),
            allowed_signers=allowed,
        )
    with pytest.raises(PaymentArtifactError, match="2 distinct"):
        assert_provider_threshold(
            signer_ids=(_b32(60),),
            allowed_signers=allowed,
        )
