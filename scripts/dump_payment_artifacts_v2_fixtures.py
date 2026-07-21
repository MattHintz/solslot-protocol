"""Generate cross-runtime payment, vault authorization, and oracle vectors."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.payment_artifacts_v2 import (
    MANUAL_RELEASE_DELAY_SECONDS,
    PAYMENT_ARTIFACT_SCHEMA,
    PAYMENT_ATTESTATION_SCHEMA,
    VAULT_AUTHORIZATION_SCHEMA,
    DeedPriceV1,
    OracleObservationV1,
    PaymentAttestationV1,
    PaymentRail,
    PaymentResolution,
    PaymentTransition,
    PurchaseArtifactV2,
    VaultAuthScheme,
    VaultPurchaseAuthorizationV1,
    build_cat_purchase_artifact,
    build_oracle_round,
    build_xch_purchase_artifact,
    test_usd_units,
    validate_deed_price_plan,
)


def _b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


def _hex(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


def _program_hex(program: Program) -> str:
    return _hex(bytes(program))


def _observation_dict(item: OracleObservationV1) -> dict[str, Any]:
    return {
        "sourceId": _hex(item.source_id),
        "assetId": _hex(item.asset_id),
        "assetDecimals": item.asset_decimals,
        "priceUsdMinorPerAsset": item.price_usd_minor_per_asset,
        "observedAt": item.observed_at,
        "validUntil": item.valid_until,
        "evidenceHash": _hex(item.evidence_hash),
        "programHex": _program_hex(item.to_program()),
        "observationHash": _hex(item.observation_hash),
    }


def _artifact_dict(item: PurchaseArtifactV2) -> dict[str, Any]:
    return {
        "network": item.network,
        "collectionId": _hex(item.collection_id),
        "deedLauncherId": _hex(item.deed_launcher_id),
        "metadataRoot": _hex(item.metadata_root),
        "metadataAnchorId": _hex(item.metadata_anchor_id),
        "sharePpm": item.share_ppm,
        "usdAmountMinor": item.usd_amount_minor,
        "rail": int(item.rail),
        "railChainId": item.rail_chain_id,
        "railAssetId": _hex(item.rail_asset_id),
        "railAssetDecimals": item.rail_asset_decimals,
        "railAmount": item.rail_amount,
        "vaultLauncherId": _hex(item.vault_launcher_id),
        "vaultP2PuzzleHash": _hex(item.vault_p2_puzzle_hash),
        "authorizationNonce": _hex(item.authorization_nonce),
        "authorizationExpiresAt": item.authorization_expires_at,
        "quoteExpiresAt": item.quote_expires_at,
        "oracleRoundHash": _hex(item.oracle_round_hash),
        "oraclePriceUsdMinorPerAsset": (
            item.oracle_price_usd_minor_per_asset
        ),
        "sourceEvidenceRoot": _hex(item.source_evidence_root),
        "programHex": _program_hex(item.to_program()),
        "artifactHash": _hex(item.artifact_hash),
        "purchaseId": _hex(item.purchase_id),
    }


def _authorization_dict(
    item: VaultPurchaseAuthorizationV1,
) -> dict[str, Any]:
    return {
        "artifactHash": _hex(item.artifact_hash),
        "purchaseId": _hex(item.purchase_id),
        "vaultLauncherId": _hex(item.vault_launcher_id),
        "vaultP2PuzzleHash": _hex(item.vault_p2_puzzle_hash),
        "authScheme": int(item.auth_scheme),
        "signerId": _hex(item.signer_id),
        "nonce": _hex(item.nonce),
        "issuedAt": item.issued_at,
        "expiresAt": item.expires_at,
        "programHex": _program_hex(item.to_program()),
        "authorizationHash": _hex(item.authorization_hash),
    }


def _attestation_dict(item: PaymentAttestationV1) -> dict[str, Any]:
    return {
        "purchaseId": _hex(item.purchase_id),
        "artifactHash": _hex(item.artifact_hash),
        "transition": int(item.transition),
        "resolution": int(item.resolution),
        "providerId": _hex(item.provider_id),
        "externalReferenceHash": _hex(item.external_reference_hash),
        "evidenceHash": _hex(item.evidence_hash),
        "previousAttestationHash": _hex(item.previous_attestation_hash),
        "observedAt": item.observed_at,
        "reasonHash": _hex(item.reason_hash),
        "programHex": _program_hex(item.to_program()),
        "attestationHash": _hex(item.attestation_hash),
    }


def build_fixture() -> dict[str, Any]:
    deeds = (
        DeedPriceV1(_b32(31), 400_000, 200_000),
        DeedPriceV1(_b32(30), 600_000, 300_000),
    )
    plan_root = validate_deed_price_plan(
        deeds,
        target_raise_usd_minor=500_000,
    )
    observations = (
        OracleObservationV1(
            source_id=_b32(1),
            asset_id=bytes32.zeros,
            asset_decimals=12,
            price_usd_minor_per_asset=2_100,
            observed_at=1_700_000_000,
            valid_until=1_700_000_600,
            evidence_hash=_b32(11),
        ),
        OracleObservationV1(
            source_id=_b32(2),
            asset_id=bytes32.zeros,
            asset_decimals=12,
            price_usd_minor_per_asset=2_125,
            observed_at=1_700_000_010,
            valid_until=1_700_000_610,
            evidence_hash=_b32(12),
        ),
        OracleObservationV1(
            source_id=_b32(3),
            asset_id=bytes32.zeros,
            asset_decimals=12,
            price_usd_minor_per_asset=2_150,
            observed_at=1_700_000_020,
            valid_until=1_700_000_620,
            evidence_hash=_b32(13),
        ),
    )
    oracle_round = build_oracle_round(
        network="testnet11",
        sequence=17,
        asset_id=bytes32.zeros,
        asset_decimals=12,
        operator_set_root=_b32(9),
        observations=observations,
    )
    cat_asset_id = _b32(40)
    cat_observations = tuple(
        OracleObservationV1(
            source_id=item.source_id,
            asset_id=cat_asset_id,
            asset_decimals=3,
            price_usd_minor_per_asset=price,
            observed_at=item.observed_at,
            valid_until=item.valid_until,
            evidence_hash=item.evidence_hash,
        )
        for item, price in zip(observations, (99, 100, 101), strict=True)
    )
    cat_oracle_round = build_oracle_round(
        network="testnet11",
        sequence=18,
        asset_id=cat_asset_id,
        asset_decimals=3,
        operator_set_root=_b32(9),
        observations=cat_observations,
    )
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
        "quote_expires_at": 1_700_000_590,
    }
    stripe = PurchaseArtifactV2(
        **common,
        rail=PaymentRail.STRIPE,
        rail_chain_id=0,
        rail_asset_id=bytes32.zeros,
        rail_asset_decimals=2,
        rail_amount=common["usd_amount_minor"],
    )
    evm = PurchaseArtifactV2(
        **common,
        rail=PaymentRail.EVM_TEST_USD,
        rail_chain_id=84532,
        rail_asset_id=bytes32(bytes(12) + bytes([40]) * 20),
        rail_asset_decimals=6,
        rail_amount=test_usd_units(common["usd_amount_minor"]),
    )
    xch = build_xch_purchase_artifact(
        **common,
        oracle_round=oracle_round,
    )
    cat = build_cat_purchase_artifact(
        **common,
        cat_asset_id=cat_asset_id,
        cat_decimals=3,
        oracle_round=cat_oracle_round,
    )
    bls_authorization = VaultPurchaseAuthorizationV1.for_artifact(
        artifact=xch,
        auth_scheme=VaultAuthScheme.CHIA_BLS,
        signer_id=bytes([41]) * 48,
        issued_at=1_700_000_100,
    )
    evm_authorization = VaultPurchaseAuthorizationV1.for_artifact(
        artifact=evm,
        auth_scheme=VaultAuthScheme.EVM_EIP712,
        signer_id=bytes([42]) * 20,
        issued_at=1_700_000_100,
    )
    pending = PaymentAttestationV1(
        purchase_id=stripe.purchase_id,
        artifact_hash=stripe.artifact_hash,
        transition=PaymentTransition.PENDING,
        resolution=PaymentResolution.NONE,
        provider_id=_b32(50),
        external_reference_hash=_b32(51),
        evidence_hash=_b32(52),
        previous_attestation_hash=bytes32.zeros,
        observed_at=1_700_000_000,
    )
    succeeded = PaymentAttestationV1(
        purchase_id=stripe.purchase_id,
        artifact_hash=stripe.artifact_hash,
        transition=PaymentTransition.SUCCEEDED,
        resolution=PaymentResolution.DELIVER,
        provider_id=_b32(50),
        external_reference_hash=_b32(51),
        evidence_hash=_b32(53),
        previous_attestation_hash=pending.attestation_hash,
        observed_at=1_700_000_030,
    )
    manual_release = PaymentAttestationV1(
        purchase_id=stripe.purchase_id,
        artifact_hash=stripe.artifact_hash,
        transition=PaymentTransition.MANUAL_RELEASE,
        resolution=PaymentResolution.REFUND,
        provider_id=_b32(50),
        external_reference_hash=_b32(51),
        evidence_hash=_b32(54),
        previous_attestation_hash=pending.attestation_hash,
        observed_at=1_700_000_000 + MANUAL_RELEASE_DELAY_SECONDS,
        reason_hash=_b32(55),
    )
    return {
        "schema": "solslot.payment-artifacts.cross-runtime.v1",
        "contracts": {
            "purchaseArtifact": PAYMENT_ARTIFACT_SCHEMA,
            "vaultAuthorization": VAULT_AUTHORIZATION_SCHEMA,
            "paymentAttestation": PAYMENT_ATTESTATION_SCHEMA,
        },
        "deedPricePlan": {
            "targetRaiseUsdMinor": 500_000,
            "deeds": [
                {
                    "deedId": _hex(item.deed_id),
                    "sharePpm": item.share_ppm,
                    "usdAmountMinor": item.usd_amount_minor,
                }
                for item in deeds
            ],
            "planRoot": _hex(plan_root),
        },
        "oracle": {
            "observations": [_observation_dict(item) for item in observations],
            "network": oracle_round.network,
            "sequence": oracle_round.sequence,
            "assetId": _hex(oracle_round.asset_id),
            "assetDecimals": oracle_round.asset_decimals,
            "operatorSetRoot": _hex(oracle_round.operator_set_root),
            "operatorThreshold": oracle_round.operator_threshold,
            "priceUsdMinorPerAsset": (
                oracle_round.price_usd_minor_per_asset
            ),
            "validFrom": oracle_round.valid_from,
            "validUntil": oracle_round.valid_until,
            "sourceEvidenceRoot": _hex(oracle_round.source_evidence_root),
            "programHex": _program_hex(oracle_round.to_program()),
            "roundHash": _hex(oracle_round.round_hash),
        },
        "purchaseArtifacts": {
            "stripe": _artifact_dict(stripe),
            "evmTestUsdBaseSepolia": _artifact_dict(evm),
            "chiaXch": _artifact_dict(xch),
            "chiaCat": _artifact_dict(cat),
        },
        "vaultAuthorizations": {
            "chiaBls": _authorization_dict(bls_authorization),
            "evmEip712": _authorization_dict(evm_authorization),
        },
        "paymentAttestations": {
            "pending": _attestation_dict(pending),
            "succeeded": _attestation_dict(succeeded),
            "manualRelease": _attestation_dict(manual_release),
        },
    }


def fixture_destination() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "payment-artifacts-v2.fixture.json"
    )


def main() -> None:
    destination = fixture_destination()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build_fixture(), indent=2, sort_keys=True) + "\n"
    )
    print(destination)


if __name__ == "__main__":
    main()
