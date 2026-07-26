"""RC20 refundable voucher commitments and deterministic state transitions.

V1 remains frozen as an unlaunched prototype.  This module is the only RC20
source of voucher terms: drivers and services consume its canonical Program
commitments instead of reconstructing security-critical fields independently.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any, Final, Iterable, Mapping

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


VOUCHER_V2_DOMAIN: Final[bytes] = b"SOLSLOT_REFUNDABLE_VOUCHER_V2"
TARGET_ALLOCATION_PPM: Final[int] = 1_000_000
MAX_TECHNOLOGY_FEE_BPS: Final[int] = 1_000
DELIVERY_WINDOW_SECONDS: Final[int] = 48 * 60 * 60


class VoucherV2Error(ValueError):
    pass


class VoucherSeriesState(IntEnum):
    PRESALE = 1
    LIVE = 2
    CANCELED = 3


class VoucherState(IntEnum):
    ESCROWED = 1
    REFUNDING = 2
    REFUNDED = 3
    REDEEMING = 4
    REDEEMED = 5


class VoucherPaymentRail(IntEnum):
    BASE_SEPOLIA_USDC = 1
    CHIA_XCH = 2


@dataclass(frozen=True)
class DeedAllocationCommitmentV2:
    deed_id: bytes32
    share_ppm: int
    par_value_mojos: int
    deed_launcher_id: bytes32

    def __post_init__(self) -> None:
        _b32(self.deed_id, "deed_id", nonzero=True)
        _b32(self.deed_launcher_id, "deed_launcher_id", nonzero=True)
        _uint64(self.share_ppm, "share_ppm", positive=True)
        if self.share_ppm > TARGET_ALLOCATION_PPM:
            raise VoucherV2Error("share_ppm exceeds collection allocation")
        _uint64(self.par_value_mojos, "par_value_mojos", positive=True)

    def to_program(self) -> Program:
        return Program.to(
            [self.deed_id, self.share_ppm, self.par_value_mojos, self.deed_launcher_id]
        )


def allocation_root(rows: Iterable[DeedAllocationCommitmentV2]) -> bytes32:
    values = tuple(rows)
    if not values:
        raise VoucherV2Error("deed allocation cannot be empty")
    if len({row.deed_id for row in values}) != len(values):
        raise VoucherV2Error("deed IDs must be unique")
    if len({row.deed_launcher_id for row in values}) != len(values):
        raise VoucherV2Error("deed launcher IDs must be unique")
    if sum(row.share_ppm for row in values) != TARGET_ALLOCATION_PPM:
        raise VoucherV2Error("deed allocation must total exactly 1,000,000 ppm")
    ordered = sorted(values, key=lambda row: bytes(row.deed_id))
    return bytes32(
        Program.to([VOUCHER_V2_DOMAIN, b"ALLOCATION", [row.to_program() for row in ordered]])
        .get_tree_hash()
    )


def technology_fee_minor(base_minor: int, fee_bps: int) -> int:
    _uint64(base_minor, "base_minor", positive=True)
    _uint64(fee_bps, "fee_bps")
    if fee_bps > MAX_TECHNOLOGY_FEE_BPS:
        raise VoucherV2Error("technology fee exceeds 1000 bps")
    return (base_minor * fee_bps + 9_999) // 10_000


@dataclass(frozen=True)
class VoucherSeriesTermsV2:
    series_singleton_id: bytes32
    collection_id: bytes32
    metadata_root: bytes32
    metadata_anchor_id: bytes32
    allocation_root: bytes32
    trusted_protocol_treasury: bytes32
    base_return_puzzle_hash: bytes32
    inventory_cap: int
    sale_open: int
    sale_close: int
    refund_deadline: int
    launch_deadline: int
    validator_pubkeys: tuple[bytes, bytes, bytes]

    def __post_init__(self) -> None:
        for name in (
            "series_singleton_id",
            "collection_id",
            "metadata_root",
            "metadata_anchor_id",
            "allocation_root",
            "trusted_protocol_treasury",
            "base_return_puzzle_hash",
        ):
            _b32(getattr(self, name), name, nonzero=True)
        _uint64(self.inventory_cap, "inventory_cap", positive=True)
        for name in ("sale_open", "sale_close", "refund_deadline", "launch_deadline"):
            _uint64(getattr(self, name), name, positive=True)
        if not self.sale_open < self.sale_close <= self.refund_deadline <= self.launch_deadline:
            raise VoucherV2Error(
                "must satisfy sale_open < sale_close <= refund_deadline <= launch_deadline"
            )
        _validator_set(self.validator_pubkeys)

    def to_program(self) -> Program:
        return Program.to(
            [
                VOUCHER_V2_DOMAIN,
                self.series_singleton_id,
                self.collection_id,
                self.metadata_root,
                self.metadata_anchor_id,
                self.allocation_root,
                self.trusted_protocol_treasury,
                self.base_return_puzzle_hash,
                self.inventory_cap,
                self.sale_open,
                self.sale_close,
                self.refund_deadline,
                self.launch_deadline,
                list(self.validator_pubkeys),
            ]
        )

    @property
    def terms_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())


@dataclass(frozen=True)
class VoucherCommitmentV2:
    series_terms_hash: bytes32
    series_singleton_id: bytes32
    collection_id: bytes32
    metadata_root: bytes32
    allocation_root: bytes32
    serial: int
    payment_rail: VoucherPaymentRail
    payment_chain_id: int
    payment_asset_id: bytes32
    payment_asset_decimals: int
    external_escrow_contract: bytes32
    base_price_minor: int
    technology_fee_bps: int
    technology_fee_minor: int
    gross_price_minor: int
    payment_principal: int
    original_payer: bytes32
    approved_vault_launcher_id: bytes32
    approved_vault_p2_puzzle_hash: bytes32
    refund_deadline: int
    delivery_window_seconds: int
    trusted_protocol_treasury: bytes32
    deed_launcher_id: bytes32
    smart_deed_inner_hash: bytes32
    purchase_artifact_hash: bytes32
    global_payment_id: bytes32
    state: VoucherState = VoucherState.ESCROWED

    def __post_init__(self) -> None:
        for name in (
            "series_terms_hash",
            "series_singleton_id",
            "collection_id",
            "metadata_root",
            "allocation_root",
            "original_payer",
            "approved_vault_launcher_id",
            "approved_vault_p2_puzzle_hash",
            "trusted_protocol_treasury",
            "deed_launcher_id",
            "smart_deed_inner_hash",
            "purchase_artifact_hash",
            "global_payment_id",
        ):
            _b32(getattr(self, name), name, nonzero=True)
        _b32(self.payment_asset_id, "payment_asset_id")
        _b32(self.external_escrow_contract, "external_escrow_contract")
        _uint64(self.serial, "serial")
        _uint64(self.payment_chain_id, "payment_chain_id")
        _uint64(self.payment_asset_decimals, "payment_asset_decimals")
        if self.payment_asset_decimals > 18:
            raise VoucherV2Error("payment_asset_decimals exceeds 18")
        if self.payment_rail not in (
            VoucherPaymentRail.CHIA_XCH,
            VoucherPaymentRail.BASE_SEPOLIA_USDC,
        ):
            raise VoucherV2Error("payment_rail is unsupported")
        if self.payment_rail == VoucherPaymentRail.CHIA_XCH:
            if (
                self.payment_chain_id != 0
                or self.payment_asset_id != bytes32.zeros
                or self.payment_asset_decimals != 12
                or self.external_escrow_contract != bytes32.zeros
            ):
                raise VoucherV2Error("XCH voucher rail coordinates are invalid")
        elif (
            self.payment_chain_id == 0
            or self.payment_asset_id == bytes32.zeros
            or self.payment_asset_decimals != 6
            or self.external_escrow_contract == bytes32.zeros
        ):
            raise VoucherV2Error("Base USDC voucher rail coordinates are invalid")
        for name in (
            "base_price_minor",
            "technology_fee_bps",
            "technology_fee_minor",
            "gross_price_minor",
            "payment_principal",
            "refund_deadline",
            "delivery_window_seconds",
        ):
            _uint64(getattr(self, name), name, positive=name not in {"technology_fee_bps", "technology_fee_minor"})
        expected_fee = technology_fee_minor(
            self.base_price_minor, self.technology_fee_bps
        )
        if self.technology_fee_minor != expected_fee:
            raise VoucherV2Error("technology_fee_minor is not the required ceil fee")
        if self.gross_price_minor != self.base_price_minor + expected_fee:
            raise VoucherV2Error("gross_price_minor does not equal base plus fee")
        if self.delivery_window_seconds != DELIVERY_WINDOW_SECONDS:
            raise VoucherV2Error("delivery window must be exactly 48 hours")
        expected_vault = puzzle_hash_for_p2_vault(self.approved_vault_launcher_id)
        if self.approved_vault_p2_puzzle_hash != expected_vault:
            raise VoucherV2Error("approved vault puzzle hash is not canonical p2_vault")

    def to_program(self, *, include_state: bool = True) -> Program:
        fields: list[object] = [
            VOUCHER_V2_DOMAIN,
            self.series_terms_hash,
            self.series_singleton_id,
            self.collection_id,
            self.metadata_root,
            self.allocation_root,
            self.serial,
            int(self.payment_rail),
            self.payment_chain_id,
            self.payment_asset_id,
            self.payment_asset_decimals,
            self.external_escrow_contract,
            self.base_price_minor,
            self.technology_fee_bps,
            self.technology_fee_minor,
            self.gross_price_minor,
            self.payment_principal,
            self.original_payer,
            self.approved_vault_launcher_id,
            self.approved_vault_p2_puzzle_hash,
            self.refund_deadline,
            self.delivery_window_seconds,
            self.trusted_protocol_treasury,
            self.deed_launcher_id,
            self.smart_deed_inner_hash,
            self.purchase_artifact_hash,
            self.global_payment_id,
        ]
        if include_state:
            fields.append(int(self.state))
        return Program.to(fields)

    @property
    def commitment_hash(self) -> bytes32:
        return bytes32(self.to_program(include_state=False).get_tree_hash())

    @property
    def voucher_id(self) -> bytes32:
        return bytes32(
            Program.to(
                [VOUCHER_V2_DOMAIN, b"VOUCHER", self.series_singleton_id, self.serial]
            ).get_tree_hash()
        )

    def begin_refund(self) -> "VoucherCommitmentV2":
        if self.state != VoucherState.ESCROWED:
            raise VoucherV2Error("only ESCROWED vouchers may begin a refund")
        return replace(self, state=VoucherState.REFUNDING)

    def finish_refund(self) -> "VoucherCommitmentV2":
        if self.state != VoucherState.REFUNDING:
            raise VoucherV2Error("refund completion requires REFUNDING state")
        return replace(self, state=VoucherState.REFUNDED)

    def begin_redemption(self) -> "VoucherCommitmentV2":
        if self.state != VoucherState.ESCROWED:
            raise VoucherV2Error("only ESCROWED vouchers may begin redemption")
        return replace(self, state=VoucherState.REDEEMING)

    def finish_redemption(self) -> "VoucherCommitmentV2":
        if self.state != VoucherState.REDEEMING:
            raise VoucherV2Error("redemption completion requires REDEEMING state")
        return replace(self, state=VoucherState.REDEEMED)

    def delivery_deadline(self, launched_at: int) -> int:
        _uint64(launched_at, "launched_at", positive=True)
        deadline = launched_at + self.delivery_window_seconds
        _uint64(deadline, "delivery_deadline", positive=True)
        return deadline

    def delivery_is_overdue(self, *, launched_at: int, now_seconds: int) -> bool:
        _uint64(now_seconds, "now_seconds")
        return now_seconds >= self.delivery_deadline(launched_at)


def validate_purchase(
    *,
    series: VoucherSeriesTermsV2,
    voucher: VoucherCommitmentV2,
    now_seconds: int,
) -> None:
    _uint64(now_seconds, "now_seconds")
    if voucher.series_terms_hash != series.terms_hash:
        raise VoucherV2Error("voucher does not commit to the series terms")
    for name in (
        "series_singleton_id",
        "collection_id",
        "metadata_root",
        "allocation_root",
        "trusted_protocol_treasury",
        "refund_deadline",
    ):
        voucher_name = name
        if getattr(voucher, voucher_name) != getattr(series, name):
            raise VoucherV2Error(f"voucher {voucher_name} differs from series")
    if not series.sale_open <= now_seconds < series.sale_close:
        raise VoucherV2Error("presale is not open")
    if voucher.serial >= series.inventory_cap:
        raise VoucherV2Error("voucher serial exceeds inventory")


def series_terms_from_json(value: Mapping[str, Any]) -> VoucherSeriesTermsV2:
    """Parse the strict public camel-case series contract."""
    try:
        pubkeys = value["validatorPubkeys"]
        if not isinstance(pubkeys, list):
            raise TypeError("validatorPubkeys must be a list")
        return VoucherSeriesTermsV2(
            series_singleton_id=_json_b32(value, "seriesSingletonId"),
            collection_id=_json_b32(value, "collectionId"),
            metadata_root=_json_b32(value, "metadataRoot"),
            metadata_anchor_id=_json_b32(value, "metadataAnchorId"),
            allocation_root=_json_b32(value, "allocationRoot"),
            trusted_protocol_treasury=_json_b32(
                value, "trustedProtocolTreasury"
            ),
            base_return_puzzle_hash=_json_b32(
                value, "baseReturnPuzzleHash"
            ),
            inventory_cap=_json_int(value, "inventoryCap"),
            sale_open=_json_int(value, "saleOpen"),
            sale_close=_json_int(value, "saleClose"),
            refund_deadline=_json_int(value, "refundDeadline"),
            launch_deadline=_json_int(value, "launchDeadline"),
            validator_pubkeys=tuple(_json_bytes(item, 48) for item in pubkeys),  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VoucherV2Error("series JSON is malformed") from exc


def voucher_commitment_from_json(
    value: Mapping[str, Any],
) -> VoucherCommitmentV2:
    """Parse the strict public camel-case voucher commitment contract."""
    try:
        return VoucherCommitmentV2(
            series_terms_hash=_json_b32(value, "seriesTermsHash"),
            series_singleton_id=_json_b32(value, "seriesSingletonId"),
            collection_id=_json_b32(value, "collectionId"),
            metadata_root=_json_b32(value, "metadataRoot"),
            allocation_root=_json_b32(value, "allocationRoot"),
            serial=_json_int(value, "serial"),
            payment_rail=VoucherPaymentRail(_json_int(value, "paymentRail")),
            payment_chain_id=_json_int(value, "paymentChainId"),
            payment_asset_id=_json_b32(value, "paymentAssetId", nonzero=False),
            payment_asset_decimals=_json_int(value, "paymentAssetDecimals"),
            external_escrow_contract=_json_b32(
                value, "externalEscrowContract", nonzero=False
            ),
            base_price_minor=_json_int(value, "basePriceMinor"),
            technology_fee_bps=_json_int(value, "technologyFeeBps"),
            technology_fee_minor=_json_int(value, "technologyFeeMinor"),
            gross_price_minor=_json_int(value, "grossPriceMinor"),
            payment_principal=_json_int(value, "paymentPrincipal"),
            original_payer=_json_b32(value, "originalPayer"),
            approved_vault_launcher_id=_json_b32(
                value, "approvedVaultLauncherId"
            ),
            approved_vault_p2_puzzle_hash=_json_b32(
                value, "approvedVaultP2PuzzleHash"
            ),
            refund_deadline=_json_int(value, "refundDeadline"),
            delivery_window_seconds=_json_int(value, "deliveryWindowSeconds"),
            trusted_protocol_treasury=_json_b32(
                value, "trustedProtocolTreasury"
            ),
            deed_launcher_id=_json_b32(value, "deedLauncherId"),
            smart_deed_inner_hash=_json_b32(value, "smartDeedInnerHash"),
            purchase_artifact_hash=_json_b32(value, "purchaseArtifactHash"),
            global_payment_id=_json_b32(value, "globalPaymentId"),
            state=VoucherState.ESCROWED,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VoucherV2Error("voucher commitment JSON is malformed") from exc


def _json_int(value: Mapping[str, Any], field: str) -> int:
    result = value[field]
    if isinstance(result, bool) or not isinstance(result, int):
        raise TypeError(f"{field} must be an integer")
    return result


def _json_bytes(value: object, size: int) -> bytes:
    if not isinstance(value, str):
        raise TypeError("hex value must be a string")
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != size:
        raise ValueError(f"hex value must be {size} bytes")
    return raw


def _json_b32(
    value: Mapping[str, Any],
    field: str,
    *,
    nonzero: bool = True,
) -> bytes32:
    result = bytes32(_json_bytes(value[field], 32))
    if nonzero and result == bytes32.zeros:
        raise ValueError(f"{field} cannot be zero")
    return result


def _b32(value: bytes32, name: str, *, nonzero: bool = False) -> None:
    if not isinstance(value, bytes32) or len(value) != 32:
        raise VoucherV2Error(f"{name} must be bytes32")
    if nonzero and value == bytes32.zeros:
        raise VoucherV2Error(f"{name} cannot be zero")


def _uint64(value: int, name: str, *, positive: bool = False) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise VoucherV2Error(f"{name} must be uint64")
    if positive and value == 0:
        raise VoucherV2Error(f"{name} must be positive")


def _validator_set(pubkeys: tuple[bytes, bytes, bytes]) -> None:
    if len(pubkeys) != 3 or any(len(key) != 48 for key in pubkeys):
        raise VoucherV2Error("validator set must contain three 48-byte BLS keys")
    if len(set(pubkeys)) != 3:
        raise VoucherV2Error("validator keys must be unique")


__all__ = [
    "DELIVERY_WINDOW_SECONDS",
    "DeedAllocationCommitmentV2",
    "MAX_TECHNOLOGY_FEE_BPS",
    "VoucherCommitmentV2",
    "VoucherPaymentRail",
    "VoucherSeriesState",
    "VoucherSeriesTermsV2",
    "VoucherState",
    "VoucherV2Error",
    "allocation_root",
    "technology_fee_minor",
    "validate_purchase",
    "series_terms_from_json",
    "voucher_commitment_from_json",
]
