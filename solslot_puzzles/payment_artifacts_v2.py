"""Canonical payment, vault-authorization, and oracle artifacts.

These structures are deliberately encoded as fixed-order CLVM lists.  Their
tree hashes are the cross-runtime contract used by Chia puzzles, Solidity,
TypeScript, Python, Samuel, and Key of Solomon.  JSON representations are for
transport only and must never replace these hashes in authorization checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Iterable, Mapping, Sequence

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32


PAYMENT_ARTIFACT_SCHEMA = "solslot.purchase-artifact.v2"
VAULT_AUTHORIZATION_SCHEMA = "solslot.vault-purchase-authorization.v1"
PAYMENT_ATTESTATION_SCHEMA = "solslot.payment-attestation.v1"
ORACLE_OBSERVATION_SCHEMA = "solslot.oracle-observation.v1"
ORACLE_ROUND_SCHEMA = "solslot.oracle-round.v1"

PAYMENT_ARTIFACT_VERSION = 2
VAULT_AUTHORIZATION_VERSION = 1
PAYMENT_ATTESTATION_VERSION = 1
ORACLE_OBSERVATION_VERSION = 1
ORACLE_ROUND_VERSION = 1

SHARE_PPM_TOTAL = 1_000_000
USD_MINOR_PER_USD = 100
TEST_USD_DECIMALS = 6
TEST_USD_UNITS_PER_MINOR = 10 ** TEST_USD_DECIMALS // USD_MINOR_PER_USD
MOJOS_PER_XCH = 1_000_000_000_000
XCH_ASSET_DECIMALS = 12

MIN_ORACLE_SOURCES = 2
MAX_ORACLE_SOURCE_TTL_SECONDS = 15 * 60
MAX_ORACLE_SPREAD_BPS = 300
MAX_XCH_QUOTE_TTL_SECONDS = 10 * 60
MANUAL_RELEASE_DELAY_SECONDS = 7 * 24 * 60 * 60

ZERO_32 = bytes32.zeros

_U64_MAX = (1 << 64) - 1
_PURCHASE_ID_TAG = b"SOLSLOT_PURCHASE_ID_V2"
_ORACLE_SIGNATURE_TAG = b"SOLSLOT_ORACLE_ROUND_AUTH_V1"


class PaymentArtifactError(ValueError):
    """Raised when a payment artifact cannot be authorized safely."""


class PaymentRail(IntEnum):
    STRIPE = 1
    EVM_TEST_USD = 2
    CHIA_XCH = 3
    CHIA_CAT = 4


class VaultAuthScheme(IntEnum):
    CHIA_BLS = 1
    EVM_EIP712 = 2


class PaymentTransition(IntEnum):
    PENDING = 1
    SUCCEEDED = 2
    FAILED = 3
    MANUAL_RELEASE = 4


class PaymentResolution(IntEnum):
    NONE = 0
    DELIVER = 1
    REFUND = 2


@dataclass(frozen=True)
class DeedPriceV1:
    deed_id: bytes32
    share_ppm: int
    usd_amount_minor: int

    def __post_init__(self) -> None:
        _require_bytes32(self.deed_id, "deed_id")
        _require_int_range(self.share_ppm, "share_ppm", minimum=1)
        if self.share_ppm > SHARE_PPM_TOTAL:
            raise PaymentArtifactError(
                f"share_ppm must be <= {SHARE_PPM_TOTAL}"
            )
        _require_int_range(
            self.usd_amount_minor,
            "usd_amount_minor",
            minimum=1,
        )

    def to_program(self) -> Program:
        return Program.to(
            [bytes(self.deed_id), self.share_ppm, self.usd_amount_minor]
        )


@dataclass(frozen=True)
class OracleObservationV1:
    source_id: bytes32
    asset_id: bytes32
    asset_decimals: int
    price_usd_minor_per_asset: int
    observed_at: int
    valid_until: int
    evidence_hash: bytes32

    def __post_init__(self) -> None:
        _require_bytes32(self.source_id, "source_id")
        _require_bytes32(self.asset_id, "asset_id")
        _require_int_range(
            self.asset_decimals,
            "asset_decimals",
            minimum=0,
        )
        if self.asset_decimals > 18:
            raise PaymentArtifactError("asset_decimals must be <= 18")
        _require_int_range(
            self.price_usd_minor_per_asset,
            "price_usd_minor_per_asset",
            minimum=1,
        )
        _require_int_range(self.observed_at, "observed_at", minimum=1)
        _require_int_range(self.valid_until, "valid_until", minimum=1)
        _require_bytes32(self.evidence_hash, "evidence_hash")
        if self.valid_until <= self.observed_at:
            raise PaymentArtifactError(
                "oracle observation valid_until must be after observed_at"
            )
        if (
            self.valid_until - self.observed_at
            > MAX_ORACLE_SOURCE_TTL_SECONDS
        ):
            raise PaymentArtifactError(
                "oracle observation validity exceeds "
                f"{MAX_ORACLE_SOURCE_TTL_SECONDS} seconds"
            )

    def to_program(self) -> Program:
        return Program.to(
            [
                ORACLE_OBSERVATION_VERSION,
                bytes(self.source_id),
                bytes(self.asset_id),
                self.asset_decimals,
                self.price_usd_minor_per_asset,
                self.observed_at,
                self.valid_until,
                bytes(self.evidence_hash),
            ]
        )

    @property
    def observation_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())


@dataclass(frozen=True)
class OracleRoundV1:
    network: str
    sequence: int
    asset_id: bytes32
    asset_decimals: int
    operator_set_root: bytes32
    operator_threshold: int
    observations: tuple[OracleObservationV1, ...]
    price_usd_minor_per_asset: int
    valid_from: int
    valid_until: int
    source_evidence_root: bytes32

    def __post_init__(self) -> None:
        _require_network(self.network)
        _require_int_range(self.sequence, "sequence", minimum=1)
        _require_bytes32(self.asset_id, "asset_id")
        _require_int_range(
            self.asset_decimals,
            "asset_decimals",
            minimum=0,
        )
        if self.asset_decimals > 18:
            raise PaymentArtifactError("asset_decimals must be <= 18")
        _require_bytes32(self.operator_set_root, "operator_set_root")
        _require_int_range(
            self.operator_threshold,
            "operator_threshold",
            minimum=2,
        )
        if self.operator_threshold != 2:
            raise PaymentArtifactError(
                "oracle operator threshold must be exactly 2 for alpha"
            )
        if len(self.observations) < MIN_ORACLE_SOURCES:
            raise PaymentArtifactError(
                f"oracle round requires at least {MIN_ORACLE_SOURCES} sources"
            )
        _require_int_range(
            self.price_usd_minor_per_asset,
            "price_usd_minor_per_asset",
            minimum=1,
        )
        _require_int_range(self.valid_from, "valid_from", minimum=1)
        _require_int_range(self.valid_until, "valid_until", minimum=1)
        _require_bytes32(self.source_evidence_root, "source_evidence_root")

        sorted_observations = _sorted_observations(self.observations)
        if self.observations != sorted_observations:
            raise PaymentArtifactError(
                "oracle observations must be sorted by source_id"
            )
        if len({item.source_id for item in self.observations}) != len(
            self.observations
        ):
            raise PaymentArtifactError("oracle source_id values must be unique")
        if any(
            item.asset_id != self.asset_id
            or item.asset_decimals != self.asset_decimals
            for item in self.observations
        ):
            raise PaymentArtifactError(
                "oracle observations must describe the round asset"
            )
        expected_price = _upper_median(
            item.price_usd_minor_per_asset for item in self.observations
        )
        if self.price_usd_minor_per_asset != expected_price:
            raise PaymentArtifactError(
                "oracle round price must equal the upper median"
            )
        if self.valid_from != max(
            item.observed_at for item in self.observations
        ):
            raise PaymentArtifactError(
                "oracle round valid_from must equal the newest observation"
            )
        if self.valid_until != min(
            item.valid_until for item in self.observations
        ):
            raise PaymentArtifactError(
                "oracle round valid_until must equal the earliest expiry"
            )
        if self.valid_until <= self.valid_from:
            raise PaymentArtifactError(
                "oracle observations have no overlapping validity window"
            )
        expected_root = _source_evidence_root(self.observations)
        if self.source_evidence_root != expected_root:
            raise PaymentArtifactError(
                "oracle source_evidence_root does not match observations"
            )
        _validate_oracle_spread(
            self.observations,
            median_price=self.price_usd_minor_per_asset,
        )

    def to_program(self) -> Program:
        return Program.to(
            [
                ORACLE_ROUND_VERSION,
                self.network.encode("ascii"),
                self.sequence,
                bytes(self.asset_id),
                self.asset_decimals,
                bytes(self.operator_set_root),
                self.operator_threshold,
                [bytes(item.observation_hash) for item in self.observations],
                self.price_usd_minor_per_asset,
                self.valid_from,
                self.valid_until,
                bytes(self.source_evidence_root),
            ]
        )

    @property
    def round_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())

    def assert_live(self, now: int) -> None:
        _require_int_range(now, "now", minimum=1)
        if now < self.valid_from or now >= self.valid_until:
            raise PaymentArtifactError("oracle round is not currently valid")


@dataclass(frozen=True)
class PurchaseArtifactV2:
    network: str
    collection_id: bytes32
    deed_launcher_id: bytes32
    metadata_root: bytes32
    metadata_anchor_id: bytes32
    share_ppm: int
    usd_amount_minor: int
    rail: PaymentRail
    rail_chain_id: int
    rail_asset_id: bytes32
    rail_asset_decimals: int
    rail_amount: int
    vault_launcher_id: bytes32
    vault_p2_puzzle_hash: bytes32
    authorization_nonce: bytes32
    authorization_expires_at: int
    quote_expires_at: int
    oracle_round_hash: bytes32 = ZERO_32
    oracle_price_usd_minor_per_asset: int = 0
    source_evidence_root: bytes32 = ZERO_32

    def __post_init__(self) -> None:
        _require_network(self.network)
        for name in (
            "collection_id",
            "deed_launcher_id",
            "metadata_root",
            "metadata_anchor_id",
            "rail_asset_id",
            "vault_launcher_id",
            "vault_p2_puzzle_hash",
            "authorization_nonce",
            "oracle_round_hash",
            "source_evidence_root",
        ):
            _require_bytes32(getattr(self, name), name)
        _require_int_range(self.share_ppm, "share_ppm", minimum=1)
        if self.share_ppm > SHARE_PPM_TOTAL:
            raise PaymentArtifactError(
                f"share_ppm must be <= {SHARE_PPM_TOTAL}"
            )
        _require_int_range(
            self.usd_amount_minor,
            "usd_amount_minor",
            minimum=1,
        )
        _require_int_range(self.rail_chain_id, "rail_chain_id", minimum=0)
        _require_int_range(
            self.rail_asset_decimals,
            "rail_asset_decimals",
            minimum=0,
        )
        if self.rail_asset_decimals > 18:
            raise PaymentArtifactError("rail_asset_decimals must be <= 18")
        _require_int_range(self.rail_amount, "rail_amount", minimum=1)
        _require_int_range(
            self.authorization_expires_at,
            "authorization_expires_at",
            minimum=1,
        )
        _require_int_range(
            self.quote_expires_at,
            "quote_expires_at",
            minimum=1,
        )
        _require_int_range(
            self.oracle_price_usd_minor_per_asset,
            "oracle_price_usd_minor_per_asset",
            minimum=0,
        )
        if self.authorization_expires_at < self.quote_expires_at:
            raise PaymentArtifactError(
                "vault authorization must remain valid through quote expiry"
            )
        _validate_rail(self)

    def to_program(self) -> Program:
        return Program.to(
            [
                PAYMENT_ARTIFACT_VERSION,
                self.network.encode("ascii"),
                bytes(self.collection_id),
                bytes(self.deed_launcher_id),
                bytes(self.metadata_root),
                bytes(self.metadata_anchor_id),
                self.share_ppm,
                self.usd_amount_minor,
                int(self.rail),
                self.rail_chain_id,
                bytes(self.rail_asset_id),
                self.rail_asset_decimals,
                self.rail_amount,
                bytes(self.vault_launcher_id),
                bytes(self.vault_p2_puzzle_hash),
                bytes(self.authorization_nonce),
                self.authorization_expires_at,
                self.quote_expires_at,
                bytes(self.oracle_round_hash),
                self.oracle_price_usd_minor_per_asset,
                bytes(self.source_evidence_root),
            ]
        )

    @property
    def artifact_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())

    @property
    def purchase_id(self) -> bytes32:
        return bytes32(
            Program.to(
                [_PURCHASE_ID_TAG, bytes(self.artifact_hash)]
            ).get_tree_hash()
        )

    def assert_live(self, now: int) -> None:
        _require_int_range(now, "now", minimum=1)
        if now >= self.quote_expires_at:
            raise PaymentArtifactError("purchase quote has expired")
        if now >= self.authorization_expires_at:
            raise PaymentArtifactError("vault authorization has expired")


@dataclass(frozen=True)
class VaultPurchaseAuthorizationV1:
    artifact_hash: bytes32
    purchase_id: bytes32
    vault_launcher_id: bytes32
    vault_p2_puzzle_hash: bytes32
    auth_scheme: VaultAuthScheme
    signer_id: bytes
    nonce: bytes32
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for name in (
            "artifact_hash",
            "purchase_id",
            "vault_launcher_id",
            "vault_p2_puzzle_hash",
            "nonce",
        ):
            _require_bytes32(getattr(self, name), name)
        _require_int_range(self.issued_at, "issued_at", minimum=1)
        _require_int_range(self.expires_at, "expires_at", minimum=1)
        if self.expires_at <= self.issued_at:
            raise PaymentArtifactError(
                "vault authorization expires_at must be after issued_at"
            )
        if self.auth_scheme not in (
            VaultAuthScheme.CHIA_BLS,
            VaultAuthScheme.EVM_EIP712,
        ):
            raise PaymentArtifactError(
                f"unsupported vault auth scheme: {self.auth_scheme}"
            )
        expected_length = (
            48 if self.auth_scheme == VaultAuthScheme.CHIA_BLS else 20
        )
        if len(self.signer_id) != expected_length:
            raise PaymentArtifactError(
                f"{self.auth_scheme.name} signer_id must be "
                f"{expected_length} bytes"
            )

    @classmethod
    def for_artifact(
        cls,
        *,
        artifact: PurchaseArtifactV2,
        auth_scheme: VaultAuthScheme,
        signer_id: bytes,
        issued_at: int,
    ) -> "VaultPurchaseAuthorizationV1":
        if issued_at >= artifact.authorization_expires_at:
            raise PaymentArtifactError(
                "authorization cannot be issued after its expiry"
            )
        return cls(
            artifact_hash=artifact.artifact_hash,
            purchase_id=artifact.purchase_id,
            vault_launcher_id=artifact.vault_launcher_id,
            vault_p2_puzzle_hash=artifact.vault_p2_puzzle_hash,
            auth_scheme=auth_scheme,
            signer_id=bytes(signer_id),
            nonce=artifact.authorization_nonce,
            issued_at=issued_at,
            expires_at=artifact.authorization_expires_at,
        )

    def to_program(self) -> Program:
        return Program.to(
            [
                VAULT_AUTHORIZATION_VERSION,
                bytes(self.artifact_hash),
                bytes(self.purchase_id),
                bytes(self.vault_launcher_id),
                bytes(self.vault_p2_puzzle_hash),
                int(self.auth_scheme),
                self.signer_id,
                bytes(self.nonce),
                self.issued_at,
                self.expires_at,
            ]
        )

    @property
    def authorization_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())

    def assert_matches(self, artifact: PurchaseArtifactV2) -> None:
        expected = VaultPurchaseAuthorizationV1.for_artifact(
            artifact=artifact,
            auth_scheme=self.auth_scheme,
            signer_id=self.signer_id,
            issued_at=self.issued_at,
        )
        if self != expected:
            raise PaymentArtifactError(
                "vault authorization does not match purchase artifact"
            )


@dataclass(frozen=True)
class PaymentAttestationV1:
    purchase_id: bytes32
    artifact_hash: bytes32
    transition: PaymentTransition
    resolution: PaymentResolution
    provider_id: bytes32
    external_reference_hash: bytes32
    evidence_hash: bytes32
    previous_attestation_hash: bytes32
    observed_at: int
    reason_hash: bytes32 = ZERO_32

    def __post_init__(self) -> None:
        for name in (
            "purchase_id",
            "artifact_hash",
            "provider_id",
            "external_reference_hash",
            "evidence_hash",
            "previous_attestation_hash",
            "reason_hash",
        ):
            _require_bytes32(getattr(self, name), name)
        _require_int_range(self.observed_at, "observed_at", minimum=1)
        if self.transition == PaymentTransition.PENDING:
            if self.resolution != PaymentResolution.NONE:
                raise PaymentArtifactError(
                    "PENDING cannot carry a payment resolution"
                )
            if self.previous_attestation_hash != ZERO_32:
                raise PaymentArtifactError(
                    "PENDING must be the first payment attestation"
                )
        else:
            if self.previous_attestation_hash == ZERO_32:
                raise PaymentArtifactError(
                    f"{self.transition.name} must reference a prior attestation"
                )
            expected_resolution = {
                PaymentTransition.SUCCEEDED: PaymentResolution.DELIVER,
                PaymentTransition.FAILED: PaymentResolution.REFUND,
            }.get(self.transition)
            if (
                expected_resolution is not None
                and self.resolution != expected_resolution
            ):
                raise PaymentArtifactError(
                    f"{self.transition.name} requires "
                    f"{expected_resolution.name}"
                )
            if (
                self.transition == PaymentTransition.MANUAL_RELEASE
                and self.resolution not in (
                    PaymentResolution.DELIVER,
                    PaymentResolution.REFUND,
                )
            ):
                raise PaymentArtifactError(
                    "MANUAL_RELEASE must choose DELIVER or REFUND"
                )
        if (
            self.transition == PaymentTransition.MANUAL_RELEASE
            and self.reason_hash == ZERO_32
        ):
            raise PaymentArtifactError(
                "MANUAL_RELEASE requires a non-zero reason_hash"
            )
        if (
            self.transition != PaymentTransition.MANUAL_RELEASE
            and self.reason_hash != ZERO_32
        ):
            raise PaymentArtifactError(
                "reason_hash is reserved for MANUAL_RELEASE"
            )

    def to_program(self) -> Program:
        return Program.to(
            [
                PAYMENT_ATTESTATION_VERSION,
                bytes(self.purchase_id),
                bytes(self.artifact_hash),
                int(self.transition),
                int(self.resolution),
                bytes(self.provider_id),
                bytes(self.external_reference_hash),
                bytes(self.evidence_hash),
                bytes(self.previous_attestation_hash),
                self.observed_at,
                bytes(self.reason_hash),
            ]
        )

    @property
    def attestation_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())


def validate_deed_price_plan(
    deeds: Sequence[DeedPriceV1],
    *,
    target_raise_usd_minor: int,
) -> bytes32:
    """Validate the sealed allocation and return its deterministic root."""

    _require_int_range(
        target_raise_usd_minor,
        "target_raise_usd_minor",
        minimum=1,
    )
    if not deeds:
        raise PaymentArtifactError("deed price plan cannot be empty")
    if len({deed.deed_id for deed in deeds}) != len(deeds):
        raise PaymentArtifactError("deed price plan contains duplicate deed IDs")
    if sum(deed.share_ppm for deed in deeds) != SHARE_PPM_TOTAL:
        raise PaymentArtifactError(
            f"deed shares must total exactly {SHARE_PPM_TOTAL} ppm"
        )
    if sum(deed.usd_amount_minor for deed in deeds) != target_raise_usd_minor:
        raise PaymentArtifactError(
            "deed USD prices must total the sealed target raise"
        )
    ordered = sorted(deeds, key=lambda deed: bytes(deed.deed_id))
    return bytes32(
        Program.to([deed.to_program() for deed in ordered]).get_tree_hash()
    )


def test_usd_units(usd_amount_minor: int) -> int:
    """Convert USD cents to a controlled six-decimal test token amount."""

    _require_int_range(usd_amount_minor, "usd_amount_minor", minimum=1)
    amount = usd_amount_minor * TEST_USD_UNITS_PER_MINOR
    _require_int_range(amount, "test_usd_amount", minimum=1)
    return amount


def xch_mojos_for_usd(
    usd_amount_minor: int,
    xch_price_usd_minor: int,
) -> int:
    """Return ceil(USD cents * mojos/XCH / USD cents per XCH)."""

    return asset_units_for_usd(
        usd_amount_minor,
        asset_decimals=XCH_ASSET_DECIMALS,
        asset_price_usd_minor=xch_price_usd_minor,
    )


def asset_units_for_usd(
    usd_amount_minor: int,
    *,
    asset_decimals: int,
    asset_price_usd_minor: int,
) -> int:
    """Return the ceiling base-unit amount for a USD-denominated quote."""

    _require_int_range(usd_amount_minor, "usd_amount_minor", minimum=1)
    _require_int_range(
        asset_decimals,
        "asset_decimals",
        minimum=0,
    )
    if asset_decimals > 18:
        raise PaymentArtifactError("asset_decimals must be <= 18")
    _require_int_range(
        asset_price_usd_minor,
        "asset_price_usd_minor",
        minimum=1,
    )
    numerator = usd_amount_minor * (10**asset_decimals)
    amount = (
        numerator + asset_price_usd_minor - 1
    ) // asset_price_usd_minor
    _require_int_range(amount, "asset_base_units", minimum=1)
    return amount


def build_oracle_round(
    *,
    network: str,
    sequence: int,
    asset_id: bytes32,
    asset_decimals: int,
    operator_set_root: bytes32,
    observations: Sequence[OracleObservationV1],
) -> OracleRoundV1:
    ordered = _sorted_observations(observations)
    if len(ordered) < MIN_ORACLE_SOURCES:
        raise PaymentArtifactError(
            f"oracle round requires at least {MIN_ORACLE_SOURCES} sources"
        )
    price = _upper_median(
        item.price_usd_minor_per_asset for item in ordered
    )
    return OracleRoundV1(
        network=network,
        sequence=sequence,
        asset_id=asset_id,
        asset_decimals=asset_decimals,
        operator_set_root=operator_set_root,
        operator_threshold=2,
        observations=ordered,
        price_usd_minor_per_asset=price,
        valid_from=max(item.observed_at for item in ordered),
        valid_until=min(item.valid_until for item in ordered),
        source_evidence_root=_source_evidence_root(ordered),
    )


def oracle_operator_set_root(pubkeys: Sequence[bytes]) -> bytes32:
    """Commit to the ordered three-key H-system oracle roster."""

    values = tuple(bytes(value) for value in pubkeys)
    if len(values) != 3:
        raise PaymentArtifactError(
            "oracle operator set must contain exactly three public keys"
        )
    if any(len(value) != 48 for value in values):
        raise PaymentArtifactError(
            "oracle operator public keys must be 48 bytes"
        )
    if len(set(values)) != len(values):
        raise PaymentArtifactError(
            "oracle operator public keys must be unique"
        )
    return bytes32(Program.to(list(values)).get_tree_hash())


def oracle_round_signature_message(round_hash: bytes32) -> bytes:
    """Domain-separate an oracle-round signature from Chia conditions."""

    _require_bytes32(round_hash, "round_hash")
    return bytes(
        bytes32(
            Program.to(
                [_ORACLE_SIGNATURE_TAG, bytes(round_hash)]
            ).get_tree_hash()
        )
    )


def build_stripe_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    usd_amount_minor: int,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
) -> PurchaseArtifactV2:
    """Build a card artifact denominated in exact USD minor units."""

    return PurchaseArtifactV2(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        usd_amount_minor=usd_amount_minor,
        rail=PaymentRail.STRIPE,
        rail_chain_id=0,
        rail_asset_id=ZERO_32,
        rail_asset_decimals=2,
        rail_amount=usd_amount_minor,
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
    )


def build_evm_test_usd_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    usd_amount_minor: int,
    chain_id: int,
    token_asset_id: bytes32,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
) -> PurchaseArtifactV2:
    """Build an allowlisted six-decimal EVM stablecoin artifact."""

    return PurchaseArtifactV2(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        usd_amount_minor=usd_amount_minor,
        rail=PaymentRail.EVM_TEST_USD,
        rail_chain_id=chain_id,
        rail_asset_id=token_asset_id,
        rail_asset_decimals=TEST_USD_DECIMALS,
        rail_amount=test_usd_units(usd_amount_minor),
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
    )


def build_xch_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    usd_amount_minor: int,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    oracle_round: OracleRoundV1,
) -> PurchaseArtifactV2:
    if quote_expires_at > oracle_round.valid_until:
        raise PaymentArtifactError(
            "XCH quote cannot outlive its oracle round"
        )
    oracle_round.assert_live(quote_expires_at - 1)
    if (
        quote_expires_at - oracle_round.valid_from
        > MAX_XCH_QUOTE_TTL_SECONDS
    ):
        raise PaymentArtifactError(
            f"XCH quote validity exceeds {MAX_XCH_QUOTE_TTL_SECONDS} seconds"
        )
    if (
        oracle_round.asset_id != ZERO_32
        or oracle_round.asset_decimals != XCH_ASSET_DECIMALS
    ):
        raise PaymentArtifactError(
            "native XCH quote requires the canonical XCH asset descriptor"
        )
    return PurchaseArtifactV2(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        usd_amount_minor=usd_amount_minor,
        rail=PaymentRail.CHIA_XCH,
        rail_chain_id=0,
        rail_asset_id=ZERO_32,
        rail_asset_decimals=XCH_ASSET_DECIMALS,
        rail_amount=xch_mojos_for_usd(
            usd_amount_minor,
            oracle_round.price_usd_minor_per_asset,
        ),
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        oracle_round_hash=oracle_round.round_hash,
        oracle_price_usd_minor_per_asset=(
            oracle_round.price_usd_minor_per_asset
        ),
        source_evidence_root=oracle_round.source_evidence_root,
    )


def build_cat_purchase_artifact(
    *,
    network: str,
    collection_id: bytes32,
    deed_launcher_id: bytes32,
    metadata_root: bytes32,
    metadata_anchor_id: bytes32,
    share_ppm: int,
    usd_amount_minor: int,
    cat_asset_id: bytes32,
    cat_decimals: int,
    vault_launcher_id: bytes32,
    vault_p2_puzzle_hash: bytes32,
    authorization_nonce: bytes32,
    authorization_expires_at: int,
    quote_expires_at: int,
    oracle_round: OracleRoundV1,
) -> PurchaseArtifactV2:
    if cat_asset_id == ZERO_32:
        raise PaymentArtifactError("CAT quote requires a non-zero asset ID")
    if quote_expires_at > oracle_round.valid_until:
        raise PaymentArtifactError(
            "CAT quote cannot outlive its oracle round"
        )
    oracle_round.assert_live(quote_expires_at - 1)
    if (
        quote_expires_at - oracle_round.valid_from
        > MAX_XCH_QUOTE_TTL_SECONDS
    ):
        raise PaymentArtifactError(
            f"CAT quote validity exceeds {MAX_XCH_QUOTE_TTL_SECONDS} seconds"
        )
    if (
        oracle_round.asset_id != cat_asset_id
        or oracle_round.asset_decimals != cat_decimals
    ):
        raise PaymentArtifactError(
            "CAT quote asset does not match its oracle round"
        )
    return PurchaseArtifactV2(
        network=network,
        collection_id=collection_id,
        deed_launcher_id=deed_launcher_id,
        metadata_root=metadata_root,
        metadata_anchor_id=metadata_anchor_id,
        share_ppm=share_ppm,
        usd_amount_minor=usd_amount_minor,
        rail=PaymentRail.CHIA_CAT,
        rail_chain_id=0,
        rail_asset_id=cat_asset_id,
        rail_asset_decimals=cat_decimals,
        rail_amount=asset_units_for_usd(
            usd_amount_minor,
            asset_decimals=cat_decimals,
            asset_price_usd_minor=(
                oracle_round.price_usd_minor_per_asset
            ),
        ),
        vault_launcher_id=vault_launcher_id,
        vault_p2_puzzle_hash=vault_p2_puzzle_hash,
        authorization_nonce=authorization_nonce,
        authorization_expires_at=authorization_expires_at,
        quote_expires_at=quote_expires_at,
        oracle_round_hash=oracle_round.round_hash,
        oracle_price_usd_minor_per_asset=(
            oracle_round.price_usd_minor_per_asset
        ),
        source_evidence_root=oracle_round.source_evidence_root,
    )


def purchase_artifact_to_json(
    artifact: PurchaseArtifactV2,
) -> dict[str, Any]:
    """Return the strict transport form of the canonical CLVM artifact."""

    return {
        "schema": PAYMENT_ARTIFACT_SCHEMA,
        "network": artifact.network,
        "collectionId": _hex32(artifact.collection_id),
        "deedLauncherId": _hex32(artifact.deed_launcher_id),
        "metadataRoot": _hex32(artifact.metadata_root),
        "metadataAnchorId": _hex32(artifact.metadata_anchor_id),
        "sharePpm": artifact.share_ppm,
        "usdAmountMinor": artifact.usd_amount_minor,
        "rail": int(artifact.rail),
        "railChainId": artifact.rail_chain_id,
        "railAssetId": _hex32(artifact.rail_asset_id),
        "railAssetDecimals": artifact.rail_asset_decimals,
        "railAmount": artifact.rail_amount,
        "vaultLauncherId": _hex32(artifact.vault_launcher_id),
        "vaultP2PuzzleHash": _hex32(artifact.vault_p2_puzzle_hash),
        "authorizationNonce": _hex32(artifact.authorization_nonce),
        "authorizationExpiresAt": artifact.authorization_expires_at,
        "quoteExpiresAt": artifact.quote_expires_at,
        "oracleRoundHash": _hex32(artifact.oracle_round_hash),
        "oraclePriceUsdMinorPerAsset": (
            artifact.oracle_price_usd_minor_per_asset
        ),
        "sourceEvidenceRoot": _hex32(artifact.source_evidence_root),
        "programHex": "0x" + bytes(artifact.to_program()).hex(),
        "artifactHash": _hex32(artifact.artifact_hash),
        "purchaseId": _hex32(artifact.purchase_id),
    }


def purchase_artifact_from_json(
    value: Mapping[str, Any],
) -> PurchaseArtifactV2:
    """Parse and re-derive a strict purchase artifact transport envelope."""

    expected_keys = {
        "schema",
        "network",
        "collectionId",
        "deedLauncherId",
        "metadataRoot",
        "metadataAnchorId",
        "sharePpm",
        "usdAmountMinor",
        "rail",
        "railChainId",
        "railAssetId",
        "railAssetDecimals",
        "railAmount",
        "vaultLauncherId",
        "vaultP2PuzzleHash",
        "authorizationNonce",
        "authorizationExpiresAt",
        "quoteExpiresAt",
        "oracleRoundHash",
        "oraclePriceUsdMinorPerAsset",
        "sourceEvidenceRoot",
        "programHex",
        "artifactHash",
        "purchaseId",
    }
    _require_mapping_keys(value, expected_keys, "purchase artifact")
    if value["schema"] != PAYMENT_ARTIFACT_SCHEMA:
        raise PaymentArtifactError("purchase artifact schema is unsupported")
    try:
        rail = PaymentRail(_json_int(value, "rail"))
    except ValueError as exc:
        raise PaymentArtifactError("purchase artifact rail is unsupported") from exc
    artifact = PurchaseArtifactV2(
        network=_json_string(value, "network"),
        collection_id=_json_bytes32(value, "collectionId"),
        deed_launcher_id=_json_bytes32(value, "deedLauncherId"),
        metadata_root=_json_bytes32(value, "metadataRoot"),
        metadata_anchor_id=_json_bytes32(value, "metadataAnchorId"),
        share_ppm=_json_int(value, "sharePpm"),
        usd_amount_minor=_json_int(value, "usdAmountMinor"),
        rail=rail,
        rail_chain_id=_json_int(value, "railChainId"),
        rail_asset_id=_json_bytes32(value, "railAssetId"),
        rail_asset_decimals=_json_int(value, "railAssetDecimals"),
        rail_amount=_json_int(value, "railAmount"),
        vault_launcher_id=_json_bytes32(value, "vaultLauncherId"),
        vault_p2_puzzle_hash=_json_bytes32(value, "vaultP2PuzzleHash"),
        authorization_nonce=_json_bytes32(value, "authorizationNonce"),
        authorization_expires_at=_json_int(
            value, "authorizationExpiresAt"
        ),
        quote_expires_at=_json_int(value, "quoteExpiresAt"),
        oracle_round_hash=_json_bytes32(value, "oracleRoundHash"),
        oracle_price_usd_minor_per_asset=_json_int(
            value, "oraclePriceUsdMinorPerAsset"
        ),
        source_evidence_root=_json_bytes32(value, "sourceEvidenceRoot"),
    )
    expected = purchase_artifact_to_json(artifact)
    for field in ("programHex", "artifactHash", "purchaseId"):
        if value[field] != expected[field]:
            raise PaymentArtifactError(
                f"purchase artifact {field} does not match canonical CLVM"
            )
    return artifact


def oracle_round_to_json(round_: OracleRoundV1) -> dict[str, Any]:
    """Return the strict transport form of a source-verifiable oracle round."""

    observations = []
    for item in round_.observations:
        observations.append(
            {
                "sourceId": _hex32(item.source_id),
                "assetId": _hex32(item.asset_id),
                "assetDecimals": item.asset_decimals,
                "priceUsdMinorPerAsset": item.price_usd_minor_per_asset,
                "observedAt": item.observed_at,
                "validUntil": item.valid_until,
                "evidenceHash": _hex32(item.evidence_hash),
                "observationHash": _hex32(item.observation_hash),
                "programHex": "0x" + bytes(item.to_program()).hex(),
            }
        )
    return {
        "schema": ORACLE_ROUND_SCHEMA,
        "network": round_.network,
        "sequence": round_.sequence,
        "assetId": _hex32(round_.asset_id),
        "assetDecimals": round_.asset_decimals,
        "operatorSetRoot": _hex32(round_.operator_set_root),
        "operatorThreshold": round_.operator_threshold,
        "observations": observations,
        "priceUsdMinorPerAsset": round_.price_usd_minor_per_asset,
        "validFrom": round_.valid_from,
        "validUntil": round_.valid_until,
        "sourceEvidenceRoot": _hex32(round_.source_evidence_root),
        "programHex": "0x" + bytes(round_.to_program()).hex(),
        "roundHash": _hex32(round_.round_hash),
    }


def oracle_round_from_json(value: Mapping[str, Any]) -> OracleRoundV1:
    """Parse an oracle round and verify every derived commitment."""

    expected_keys = {
        "schema",
        "network",
        "sequence",
        "assetId",
        "assetDecimals",
        "operatorSetRoot",
        "operatorThreshold",
        "observations",
        "priceUsdMinorPerAsset",
        "validFrom",
        "validUntil",
        "sourceEvidenceRoot",
        "programHex",
        "roundHash",
    }
    _require_mapping_keys(value, expected_keys, "oracle round")
    if value["schema"] != ORACLE_ROUND_SCHEMA:
        raise PaymentArtifactError("oracle round schema is unsupported")
    raw_observations = value["observations"]
    if not isinstance(raw_observations, list):
        raise PaymentArtifactError("oracle round observations must be a list")
    observations = tuple(
        _oracle_observation_from_json(item) for item in raw_observations
    )
    round_ = OracleRoundV1(
        network=_json_string(value, "network"),
        sequence=_json_int(value, "sequence"),
        asset_id=_json_bytes32(value, "assetId"),
        asset_decimals=_json_int(value, "assetDecimals"),
        operator_set_root=_json_bytes32(value, "operatorSetRoot"),
        operator_threshold=_json_int(value, "operatorThreshold"),
        observations=observations,
        price_usd_minor_per_asset=_json_int(
            value, "priceUsdMinorPerAsset"
        ),
        valid_from=_json_int(value, "validFrom"),
        valid_until=_json_int(value, "validUntil"),
        source_evidence_root=_json_bytes32(value, "sourceEvidenceRoot"),
    )
    expected = oracle_round_to_json(round_)
    for field in ("programHex", "roundHash"):
        if value[field] != expected[field]:
            raise PaymentArtifactError(
                f"oracle round {field} does not match canonical CLVM"
            )
    return round_


def validate_manual_release(
    *,
    pending_attestation: PaymentAttestationV1,
    release_attestation: PaymentAttestationV1,
) -> None:
    if pending_attestation.transition != PaymentTransition.PENDING:
        raise PaymentArtifactError("manual release requires a PENDING origin")
    if release_attestation.transition != PaymentTransition.MANUAL_RELEASE:
        raise PaymentArtifactError(
            "release attestation must use MANUAL_RELEASE"
        )
    if (
        release_attestation.purchase_id != pending_attestation.purchase_id
        or release_attestation.artifact_hash
        != pending_attestation.artifact_hash
    ):
        raise PaymentArtifactError(
            "manual release must reference the same purchase artifact"
        )
    if (
        release_attestation.previous_attestation_hash
        != pending_attestation.attestation_hash
    ):
        raise PaymentArtifactError(
            "manual release does not reference the pending attestation"
        )
    if (
        release_attestation.observed_at - pending_attestation.observed_at
        < MANUAL_RELEASE_DELAY_SECONDS
    ):
        raise PaymentArtifactError(
            "manual release is unavailable before the seven-day delay"
        )


def _validate_rail(artifact: PurchaseArtifactV2) -> None:
    if artifact.rail == PaymentRail.STRIPE:
        if artifact.rail_chain_id != 0 or artifact.rail_asset_id != ZERO_32:
            raise PaymentArtifactError(
                "Stripe artifacts cannot declare a chain or asset"
            )
        if artifact.rail_asset_decimals != 2:
            raise PaymentArtifactError(
                "Stripe artifacts use two-decimal USD minor units"
            )
        if artifact.rail_amount != artifact.usd_amount_minor:
            raise PaymentArtifactError(
                "Stripe rail_amount must equal USD minor units"
            )
        _require_no_oracle(artifact)
        return
    if artifact.rail == PaymentRail.EVM_TEST_USD:
        if artifact.rail_chain_id == 0:
            raise PaymentArtifactError(
                "EVM test USD artifacts require a chain ID"
            )
        if artifact.rail_asset_id == ZERO_32:
            raise PaymentArtifactError(
                "EVM test USD artifacts require a token address"
            )
        if artifact.rail_asset_decimals != TEST_USD_DECIMALS:
            raise PaymentArtifactError(
                "EVM test USD artifacts require six decimals"
            )
        if artifact.rail_amount != test_usd_units(artifact.usd_amount_minor):
            raise PaymentArtifactError(
                "EVM test USD rail_amount does not match six-decimal USD"
            )
        _require_no_oracle(artifact)
        return
    if artifact.rail == PaymentRail.CHIA_XCH:
        if artifact.rail_chain_id != 0 or artifact.rail_asset_id != ZERO_32:
            raise PaymentArtifactError(
                "native XCH artifacts cannot declare a chain or asset"
            )
        if artifact.rail_asset_decimals != XCH_ASSET_DECIMALS:
            raise PaymentArtifactError(
                "native XCH artifacts require twelve decimal places"
            )
        if artifact.oracle_round_hash == ZERO_32:
            raise PaymentArtifactError(
                "native XCH artifacts require an oracle round"
            )
        if artifact.source_evidence_root == ZERO_32:
            raise PaymentArtifactError(
                "native XCH artifacts require source evidence"
            )
        expected = asset_units_for_usd(
            artifact.usd_amount_minor,
            asset_decimals=artifact.rail_asset_decimals,
            asset_price_usd_minor=(
                artifact.oracle_price_usd_minor_per_asset
            ),
        )
        if artifact.rail_amount != expected:
            raise PaymentArtifactError(
                "native XCH rail_amount does not match the oracle price"
            )
        return
    if artifact.rail == PaymentRail.CHIA_CAT:
        if artifact.rail_chain_id != 0:
            raise PaymentArtifactError(
                "Chia CAT artifacts cannot declare an EVM chain"
            )
        if artifact.rail_asset_id == ZERO_32:
            raise PaymentArtifactError(
                "Chia CAT artifacts require a CAT asset ID"
            )
        if artifact.oracle_round_hash == ZERO_32:
            raise PaymentArtifactError(
                "Chia CAT artifacts require an oracle round"
            )
        if artifact.source_evidence_root == ZERO_32:
            raise PaymentArtifactError(
                "Chia CAT artifacts require source evidence"
            )
        expected = asset_units_for_usd(
            artifact.usd_amount_minor,
            asset_decimals=artifact.rail_asset_decimals,
            asset_price_usd_minor=(
                artifact.oracle_price_usd_minor_per_asset
            ),
        )
        if artifact.rail_amount != expected:
            raise PaymentArtifactError(
                "Chia CAT rail_amount does not match the oracle price"
            )
        return
    raise PaymentArtifactError(f"unsupported payment rail: {artifact.rail}")


def _require_no_oracle(artifact: PurchaseArtifactV2) -> None:
    if (
        artifact.oracle_round_hash != ZERO_32
        or artifact.oracle_price_usd_minor_per_asset != 0
        or artifact.source_evidence_root != ZERO_32
    ):
        raise PaymentArtifactError(
            f"{artifact.rail.name} artifacts cannot carry XCH oracle data"
        )


def _source_evidence_root(
    observations: Sequence[OracleObservationV1],
) -> bytes32:
    return bytes32(
        Program.to(
            [bytes(item.observation_hash) for item in observations]
        ).get_tree_hash()
    )


def _sorted_observations(
    observations: Sequence[OracleObservationV1],
) -> tuple[OracleObservationV1, ...]:
    return tuple(sorted(observations, key=lambda item: bytes(item.source_id)))


def _upper_median(values: Iterable[int]) -> int:
    ordered = sorted(values)
    if not ordered:
        raise PaymentArtifactError("cannot compute an empty oracle median")
    return ordered[len(ordered) // 2]


def _validate_oracle_spread(
    observations: Sequence[OracleObservationV1],
    *,
    median_price: int,
) -> None:
    prices = [item.price_usd_minor_per_asset for item in observations]
    spread = max(prices) - min(prices)
    if spread * 10_000 > median_price * MAX_ORACLE_SPREAD_BPS:
        raise PaymentArtifactError(
            f"oracle source dispersion exceeds {MAX_ORACLE_SPREAD_BPS} bps"
        )


def _require_network(network: str) -> None:
    if not isinstance(network, str) or not network:
        raise PaymentArtifactError("network must be a non-empty string")
    try:
        encoded = network.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PaymentArtifactError("network must contain ASCII only") from exc
    if len(encoded) > 32:
        raise PaymentArtifactError("network must be at most 32 bytes")


def _require_bytes32(value: bytes32, name: str) -> None:
    if not isinstance(value, bytes32) or len(value) != 32:
        raise PaymentArtifactError(f"{name} must be bytes32")


def _require_int_range(
    value: int,
    name: str,
    *,
    minimum: int,
    maximum: int = _U64_MAX,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PaymentArtifactError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise PaymentArtifactError(
            f"{name} must be in {minimum}..{maximum}, got {value}"
        )


def _oracle_observation_from_json(
    value: Any,
) -> OracleObservationV1:
    if not isinstance(value, Mapping):
        raise PaymentArtifactError("oracle observation must be an object")
    expected_keys = {
        "sourceId",
        "assetId",
        "assetDecimals",
        "priceUsdMinorPerAsset",
        "observedAt",
        "validUntil",
        "evidenceHash",
        "observationHash",
        "programHex",
    }
    _require_mapping_keys(value, expected_keys, "oracle observation")
    observation = OracleObservationV1(
        source_id=_json_bytes32(value, "sourceId"),
        asset_id=_json_bytes32(value, "assetId"),
        asset_decimals=_json_int(value, "assetDecimals"),
        price_usd_minor_per_asset=_json_int(
            value, "priceUsdMinorPerAsset"
        ),
        observed_at=_json_int(value, "observedAt"),
        valid_until=_json_int(value, "validUntil"),
        evidence_hash=_json_bytes32(value, "evidenceHash"),
    )
    expected_hash = _hex32(observation.observation_hash)
    expected_program = "0x" + bytes(observation.to_program()).hex()
    if value["observationHash"] != expected_hash:
        raise PaymentArtifactError(
            "oracle observation hash does not match canonical CLVM"
        )
    if value["programHex"] != expected_program:
        raise PaymentArtifactError(
            "oracle observation programHex does not match canonical CLVM"
        )
    return observation


def _require_mapping_keys(
    value: Mapping[str, Any],
    expected: set[str],
    label: str,
) -> None:
    if not isinstance(value, Mapping):
        raise PaymentArtifactError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise PaymentArtifactError(
            f"{label} fields are invalid: {'; '.join(details)}"
        )


def _json_string(value: Mapping[str, Any], field: str) -> str:
    result = value[field]
    if not isinstance(result, str):
        raise PaymentArtifactError(f"{field} must be a string")
    return result


def _json_int(value: Mapping[str, Any], field: str) -> int:
    result = value[field]
    if isinstance(result, bool) or not isinstance(result, int):
        raise PaymentArtifactError(f"{field} must be an integer")
    return result


def _json_bytes32(value: Mapping[str, Any], field: str) -> bytes32:
    raw = _json_string(value, field)
    if not raw.startswith("0x") or len(raw) != 66:
        raise PaymentArtifactError(f"{field} must be 0x-prefixed bytes32")
    try:
        return bytes32.from_hexstr(raw)
    except ValueError as exc:
        raise PaymentArtifactError(f"{field} must be valid bytes32") from exc


def _hex32(value: bytes32) -> str:
    return "0x" + bytes(value).hex()


def assert_provider_threshold(
    *,
    signer_ids: Sequence[bytes32],
    allowed_signers: Mapping[bytes32, object],
    threshold: int = 2,
) -> None:
    """Validate signer membership before curve-specific verification."""

    _require_int_range(threshold, "threshold", minimum=2)
    unique = set(signer_ids)
    if len(unique) != len(signer_ids):
        raise PaymentArtifactError("duplicate provider signer")
    unknown = unique.difference(allowed_signers)
    if unknown:
        raise PaymentArtifactError("unknown provider signer")
    if len(unique) < threshold:
        raise PaymentArtifactError(
            f"provider transition requires {threshold} distinct signers"
        )
