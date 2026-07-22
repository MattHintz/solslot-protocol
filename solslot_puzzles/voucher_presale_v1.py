from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault


DOMAIN: Final[bytes] = b"SOLSLOT_VOUCHER_PRESALE_V1"


class VoucherPresaleError(ValueError):
    pass


class PresalePhase(IntEnum):
    PRESALE = 1
    LIVE = 2
    CANCELED = 3


class VoucherPaymentRail(IntEnum):
    BASE_SEPOLIA_USDC = 1
    CHIA_XCH = 2


@dataclass(frozen=True)
class VoucherPresaleTermsV1:
    series_id: bytes32
    property_id: bytes32
    collection_id: bytes32
    metadata_root: bytes32
    metadata_anchor_id: bytes32
    identity_attest_root: bytes32
    bridge_policy_hash: bytes32
    admin_authority_launcher_id: bytes32
    governance_launcher_id: bytes32
    voucher_collection_launcher_id: bytes32
    inventory_cap: int
    xch_price_mojos: int
    base_usdc_price_units: int
    sale_open: int
    sale_close: int
    launch_deadline: int
    governance_quorum_bps: int = 5000
    governance_sgt_total_supply: int = 1_000_000

    def __post_init__(self) -> None:
        for name in (
            "series_id",
            "property_id",
            "collection_id",
            "metadata_root",
            "metadata_anchor_id",
            "identity_attest_root",
            "bridge_policy_hash",
            "admin_authority_launcher_id",
            "governance_launcher_id",
            "voucher_collection_launcher_id",
        ):
            if len(getattr(self, name)) != 32:
                raise VoucherPresaleError(f"{name} must be bytes32")
        if self.inventory_cap <= 0:
            raise VoucherPresaleError("inventory_cap must be positive")
        if self.xch_price_mojos <= 0 or self.base_usdc_price_units <= 0:
            raise VoucherPresaleError("payment prices must be positive")
        if not 0 < self.sale_open < self.sale_close <= self.launch_deadline:
            raise VoucherPresaleError("must satisfy sale_open < sale_close <= launch_deadline")
        if not 0 < self.governance_quorum_bps <= 10_000:
            raise VoucherPresaleError("governance_quorum_bps must be in 1..10000")
        if self.governance_sgt_total_supply <= 0:
            raise VoucherPresaleError("governance_sgt_total_supply must be positive")

    @property
    def quorum_required(self) -> int:
        return (self.governance_quorum_bps * self.governance_sgt_total_supply) // 10_000

    def to_program(self) -> Program:
        return Program.to(
            [
                DOMAIN,
                self.series_id,
                self.property_id,
                self.collection_id,
                self.metadata_root,
                self.metadata_anchor_id,
                self.identity_attest_root,
                self.bridge_policy_hash,
                self.admin_authority_launcher_id,
                self.governance_launcher_id,
                self.voucher_collection_launcher_id,
                self.inventory_cap,
                self.xch_price_mojos,
                self.base_usdc_price_units,
                self.sale_open,
                self.sale_close,
                self.launch_deadline,
                self.governance_quorum_bps,
                self.governance_sgt_total_supply,
            ]
        )

    @property
    def terms_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())


@dataclass(frozen=True)
class VoucherRecordV1:
    terms_hash: bytes32
    serial: int
    payment_rail: VoucherPaymentRail
    payment_principal: int
    vault_launcher_id: bytes32
    holder_member_hash: bytes32
    base_depositor_commitment: bytes32
    global_payment_id: bytes32
    phase: PresalePhase = PresalePhase.PRESALE

    def __post_init__(self) -> None:
        for name in (
            "terms_hash",
            "vault_launcher_id",
            "holder_member_hash",
            "base_depositor_commitment",
            "global_payment_id",
        ):
            if len(getattr(self, name)) != 32:
                raise VoucherPresaleError(f"{name} must be bytes32")
        if self.serial < 0:
            raise VoucherPresaleError("serial must be non-negative")
        if self.payment_principal <= 0:
            raise VoucherPresaleError("payment_principal must be positive")

    @property
    def custody_puzzle_hash(self) -> bytes32:
        return puzzle_hash_for_p2_vault(self.vault_launcher_id)

    @property
    def voucher_id(self) -> bytes32:
        return bytes32(
            Program.to([DOMAIN, b"VOUCHER", self.terms_hash, self.serial, self.global_payment_id]).get_tree_hash()
        )

    @property
    def child_deed_id(self) -> bytes32:
        return bytes32(
            Program.to([DOMAIN, b"CHILD_DEED", self.terms_hash, self.serial]).get_tree_hash()
        )

    def refund(self) -> VoucherRecordV1:
        if self.phase != PresalePhase.PRESALE:
            raise VoucherPresaleError("only presale vouchers may refund")
        return VoucherRecordV1(
            terms_hash=self.terms_hash,
            serial=self.serial,
            payment_rail=self.payment_rail,
            payment_principal=self.payment_principal,
            vault_launcher_id=self.vault_launcher_id,
            holder_member_hash=self.holder_member_hash,
            base_depositor_commitment=self.base_depositor_commitment,
            global_payment_id=self.global_payment_id,
            phase=PresalePhase.CANCELED,
        )

    def redeem(self) -> VoucherRecordV1:
        if self.phase != PresalePhase.LIVE:
            raise VoucherPresaleError("only live vouchers may redeem")
        return VoucherRecordV1(
            terms_hash=self.terms_hash,
            serial=self.serial,
            payment_rail=self.payment_rail,
            payment_principal=self.payment_principal,
            vault_launcher_id=self.vault_launcher_id,
            holder_member_hash=self.holder_member_hash,
            base_depositor_commitment=self.base_depositor_commitment,
            global_payment_id=self.global_payment_id,
            phase=PresalePhase.CANCELED,
        )


def validate_purchase(
    *,
    terms: VoucherPresaleTermsV1,
    serial: int,
    rail: VoucherPaymentRail,
    principal: int,
    now_seconds: int,
) -> None:
    if not terms.sale_open <= now_seconds < terms.sale_close:
        raise VoucherPresaleError("presale is not open")
    if serial < 0 or serial >= terms.inventory_cap:
        raise VoucherPresaleError("serial is outside inventory cap")
    expected = (
        terms.base_usdc_price_units
        if rail == VoucherPaymentRail.BASE_SEPOLIA_USDC
        else terms.xch_price_mojos
    )
    if principal != expected:
        raise VoucherPresaleError("payment principal does not match terms")


def validate_launch(
    *,
    terms: VoucherPresaleTermsV1,
    now_seconds: int,
    vote_tally: int,
    admin_approved: bool,
) -> None:
    if not admin_approved:
        raise VoucherPresaleError("admin approval is required")
    if now_seconds > terms.launch_deadline:
        raise VoucherPresaleError("launch deadline has passed")
    if vote_tally < terms.quorum_required:
        raise VoucherPresaleError("governance quorum is not met")
