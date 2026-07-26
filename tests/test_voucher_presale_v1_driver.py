"""Tests for the voucher NFT inner-puzzle spend-bundle driver.

Covers currying, refund spend, redeem spend, phase guards, condition
verification, and deterministic puzzle-hash stability.
"""
from __future__ import annotations

import pytest
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.voucher_presale_v1 import (
    PresalePhase,
    VoucherPaymentRail,
    VoucherPresaleError,
    VoucherRecordV1,
)
from solslot_puzzles.voucher_presale_v1_driver import (
    build_redeem_spend,
    build_refund_spend,
    curried_voucher_puzzle_hash,
    curry_voucher_nft_inner,
    verify_redeem_create_coin,
    verify_refund_remark,
    voucher_nft_inner_mod_hash,
)


def b32(value: int) -> bytes32:
    return bytes32(bytes([value]) * 32)


def _record(phase: PresalePhase = PresalePhase.PRESALE) -> VoucherRecordV1:
    return VoucherRecordV1(
        terms_hash=b32(1),
        serial=3,
        payment_rail=VoucherPaymentRail.BASE_SEPOLIA_USDC,
        payment_principal=250_000_000,
        vault_launcher_id=b32(11),
        holder_member_hash=b32(12),
        base_depositor_commitment=b32(13),
        global_payment_id=b32(14),
        phase=phase,
    )


class TestCurrying:
    def test_mod_hash_is_bytes32(self) -> None:
        h = voucher_nft_inner_mod_hash()
        assert isinstance(h, bytes32)
        assert len(h) == 32

    def test_curried_puzzle_is_deterministic(self) -> None:
        a = curried_voucher_puzzle_hash(_record())
        b = curried_voucher_puzzle_hash(_record())
        assert a == b

    def test_different_records_produce_different_hashes(self) -> None:
        r1 = _record()
        r2 = VoucherRecordV1(
            terms_hash=b32(99),
            serial=0,
            payment_rail=VoucherPaymentRail.CHIA_XCH,
            payment_principal=2_000_000_000,
            vault_launcher_id=b32(20),
            holder_member_hash=b32(21),
            base_depositor_commitment=b32(22),
            global_payment_id=b32(23),
        )
        assert curried_voucher_puzzle_hash(r1) != curried_voucher_puzzle_hash(r2)

    def test_curry_returns_program(self) -> None:
        p = curry_voucher_nft_inner(_record())
        assert p.get_tree_hash() is not None


class TestRefundSpend:
    def test_refund_succeeds_in_presale_phase(self) -> None:
        result = build_refund_spend(_record(PresalePhase.PRESALE))
        assert result.inner_puzzle is not None
        assert result.inner_solution is not None
        assert "REMARK:SOLSLOT_VOUCHER_REFUND_V1" in result.expected_conditions

    def test_refund_runs_without_error(self) -> None:
        result = build_refund_spend(_record(PresalePhase.PRESALE))
        conditions = result.inner_puzzle.run(result.inner_solution)
        assert conditions is not None

    def test_refund_rejects_live_phase(self) -> None:
        with pytest.raises(VoucherPresaleError, match="PRESALE"):
            build_refund_spend(_record(PresalePhase.LIVE))

    def test_refund_rejects_canceled_phase(self) -> None:
        with pytest.raises(VoucherPresaleError, match="PRESALE"):
            build_refund_spend(_record(PresalePhase.CANCELED))


class TestRedeemSpend:
    def test_redeem_succeeds_in_live_phase(self) -> None:
        child_ph = b32(50)
        result = build_redeem_spend(_record(PresalePhase.LIVE), child_ph)
        assert result.inner_puzzle is not None
        assert "CREATE_COIN:child_deed" in result.expected_conditions

    def test_redeem_runs_and_creates_coin(self) -> None:
        child_ph = b32(50)
        result = build_redeem_spend(_record(PresalePhase.LIVE), child_ph)
        output = result.inner_puzzle.run(result.inner_solution)
        conditions = []
        node = output
        while node.pair is not None:
            conditions.append(node.pair[0])
            node = node.pair[1]
        found_create = False
        for c in conditions:
            parts = []
            n = c
            while n.pair is not None:
                parts.append(n.pair[0])
                n = n.pair[1]
            if len(parts) >= 3 and int.from_bytes(parts[0].atom, "big") == 51:
                found_create = True
                assert bytes(parts[1].atom) == bytes(child_ph)
                assert int.from_bytes(parts[2].atom, "big") == 1
        assert found_create, "CREATE_COIN condition not found in redeem output"

    def test_redeem_rejects_presale_phase(self) -> None:
        with pytest.raises(VoucherPresaleError, match="LIVE"):
            build_redeem_spend(_record(PresalePhase.PRESALE), b32(50))

    def test_redeem_rejects_non_bytes32_child(self) -> None:
        with pytest.raises(TypeError, match="bytes32"):
            build_redeem_spend(_record(PresalePhase.LIVE), b"\x00" * 32)  # type: ignore[arg-type]


class TestConditionVerification:
    def test_verify_refund_remark(self) -> None:
        good = [[1, b"SOLSLOT_VOUCHER_REFUND_V1", b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"]]
        assert verify_refund_remark(good, _record()) is True
        bad = [[1, b"WRONG_TAG"]]
        assert verify_refund_remark(bad, _record()) is False
        assert verify_refund_remark([], _record()) is False

    def test_verify_redeem_create_coin(self) -> None:
        child_ph = b32(50)
        good = [[51, bytes(child_ph), 1]]
        assert verify_redeem_create_coin(good, child_ph) is True
        wrong_amount = [[51, bytes(child_ph), 2]]
        assert verify_redeem_create_coin(wrong_amount, child_ph) is False
        wrong_ph = [[51, bytes(b32(99)), 1]]
        assert verify_redeem_create_coin(wrong_ph, child_ph) is False
        assert verify_redeem_create_coin([], child_ph) is False
