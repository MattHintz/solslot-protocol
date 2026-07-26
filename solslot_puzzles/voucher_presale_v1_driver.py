"""Voucher NFT inner-puzzle spend-bundle driver.

Curries ``voucher_nft_inner_v1.clsp`` with immutable record commitments and
builds spends for the two terminal actions: **refund** (phase PRESALE → emit
REMARK + conditions) and **redeem** (phase LIVE → CREATE_COIN child deed +
REMARK).

The driver deliberately does **not** wrap the result in a full singleton
``CoinSpend``; callers (e.g. the mint-publish or ceremony drivers) are
responsible for wrapping the inner puzzle in the singleton top-level and
producing the final ``SpendBundle``.

All curried values are derived from the frozen ``VoucherRecordV1`` and the
parent ``VoucherPresaleTermsV1`` so that no mutable parameter can be injected
at spend time.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import puzzle_hash_for_p2_vault
from solslot_puzzles.voucher_presale_v1 import (
    PresalePhase,
    VoucherPresaleError,
    VoucherRecordV1,
)

# ── Constants matching the CLSP ──────────────────────────────────────────
_PHASE_PRESALE = 1
_PHASE_LIVE = 2
_ACTION_REFUND = 1
_ACTION_REDEEM = 2


def _voucher_nft_inner_mod() -> Program:
    return load_puzzle("voucher_nft_inner_v1.clsp")


def voucher_nft_inner_mod_hash() -> bytes32:
    return bytes32(_voucher_nft_inner_mod().get_tree_hash())


# ── Curried puzzle construction ──────────────────────────────────────────

def curry_voucher_nft_inner(record: VoucherRecordV1) -> Program:
    """Return the fully curried inner puzzle for a specific voucher record.

    The curried parameters are all immutable commitments from the record:
      PRESALE_TERMS_HASH, SERIAL, PAYMENT_RECORD_HASH,
      ORIGINAL_VAULT_LAUNCHER_ID, ORIGINAL_VAULT_PUZZLE_HASH,
      BASE_DEPOSITOR_COMMITMENT, PAYMENT_PRINCIPAL, PAYMENT_RAIL,
      SERIES_SINGLETON_ID (zero placeholder — bound by series singleton).

    The three solution arguments (phase, action, child_deed_puzzle_hash) are
    left unbound and supplied at spend time.
    """
    payment_record_hash = bytes32(
        Program.to([
            record.terms_hash,
            record.serial,
            record.global_payment_id,
            int(record.payment_rail),
            record.payment_principal,
        ]).get_tree_hash()
    )
    original_vault_puzzle_hash = puzzle_hash_for_p2_vault(record.vault_launcher_id)

    return _voucher_nft_inner_mod().curry(
        record.terms_hash,
        record.serial,
        payment_record_hash,
        record.vault_launcher_id,
        original_vault_puzzle_hash,
        record.base_depositor_commitment,
        record.payment_principal,
        int(record.payment_rail),
        bytes32(b"\x00" * 32),  # SERIES_SINGLETON_ID — resolved at mint time
    )


def curried_voucher_puzzle_hash(record: VoucherRecordV1) -> bytes32:
    """Derive the tree hash of the curried voucher inner puzzle."""
    return bytes32(curry_voucher_nft_inner(record).get_tree_hash())


# ── Solution builders ────────────────────────────────────────────────────

@dataclass(frozen=True)
class VoucherSpendResult:
    """Output of a voucher inner-puzzle spend."""
    inner_puzzle: Program
    inner_solution: Program
    expected_conditions: list


def build_refund_spend(record: VoucherRecordV1) -> VoucherSpendResult:
    """Build the inner-puzzle solution for a voucher refund.

    Requires ``record.phase == PresalePhase.PRESALE``.
    The CLSP enforces phase == PHASE_PRESALE and emits a REMARK with all
    immutable refund commitments (terms, serial, payment, depositor, etc.).
    """
    if record.phase != PresalePhase.PRESALE:
        raise VoucherPresaleError("refund requires phase PRESALE")

    inner = curry_voucher_nft_inner(record)
    solution = Program.to([
        _PHASE_PRESALE,      # phase
        _ACTION_REFUND,      # action
        bytes32(b"\x00" * 32),  # child_deed_puzzle_hash (unused for refund)
    ])
    return VoucherSpendResult(
        inner_puzzle=inner,
        inner_solution=solution,
        expected_conditions=["REMARK:SOLSLOT_VOUCHER_REFUND_V1"],
    )


def build_redeem_spend(
    record: VoucherRecordV1,
    child_deed_puzzle_hash: bytes32,
) -> VoucherSpendResult:
    """Build the inner-puzzle solution for a voucher redemption.

    Requires ``record.phase == PresalePhase.LIVE``.
    The CLSP enforces phase == PHASE_LIVE, creates a child deed coin at the
    provided puzzle hash with amount 1, and emits a REMARK with the
    redemption commitments.
    """
    if record.phase != PresalePhase.LIVE:
        raise VoucherPresaleError("redeem requires phase LIVE")
    if not isinstance(child_deed_puzzle_hash, bytes32):
        raise TypeError("child_deed_puzzle_hash must be bytes32")

    inner = curry_voucher_nft_inner(record)
    solution = Program.to([
        _PHASE_LIVE,         # phase
        _ACTION_REDEEM,      # action
        child_deed_puzzle_hash,
    ])
    return VoucherSpendResult(
        inner_puzzle=inner,
        inner_solution=solution,
        expected_conditions=["CREATE_COIN:child_deed", "REMARK:SOLSLOT_VOUCHER_REDEEM_V1"],
    )


# ── Condition verification ───────────────────────────────────────────────

def verify_refund_remark(
    conditions: list,
    record: VoucherRecordV1,
) -> bool:
    """Check that a REMARK condition from a refund spend matches expectations.

    Returns True if any condition is a REMARK whose arguments start with
    ``SOLSLOT_VOUCHER_REFUND_V1`` and contain the expected immutable fields.
    """
    for cond in conditions:
        if not isinstance(cond, (list, tuple)) or len(cond) < 2:
            continue
        if cond[0] == 1 and len(cond) >= 10:  # REMARK = opcode 1
            tag = cond[1]
            if isinstance(tag, bytes) and tag == b"SOLSLOT_VOUCHER_REFUND_V1":
                return True
    return False


def verify_redeem_create_coin(
    conditions: list,
    child_deed_puzzle_hash: bytes32,
) -> bool:
    """Check that a CREATE_COIN condition targets the expected child deed.

    Returns True if any condition is CREATE_COIN with the expected puzzle
    hash and amount 1.
    """
    for cond in conditions:
        if not isinstance(cond, (list, tuple)) or len(cond) < 3:
            continue
        if cond[0] == 51:  # CREATE_COIN = opcode 51
            if bytes(cond[1]) == bytes(child_deed_puzzle_hash) and cond[2] == 1:
                return True
    return False
