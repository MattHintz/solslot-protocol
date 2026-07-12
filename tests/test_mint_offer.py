"""Unit tests for mint_offer_delegate.clsp + purchase_payment.clsp.

Tests verify:
  1. purchase_payment produces correct conditions (payment + SEND_MESSAGE)
  2. mint_offer_delegate produces correct conditions (transition + RECEIVE_MESSAGE)
  3. Cross-puzzle message bytes match (SEND vs RECEIVE use identical message)
  4. Underpayment rejected by purchase_payment
  5. Invalid inputs rejected by both puzzles
"""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

PURCHASE_PAYMENT_MOD: Program = load_clvm(
    "purchase_payment.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
MINT_OFFER_MOD: Program = load_clvm(
    "mint_offer_delegate.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

# Test constants
PAR_VALUE = uint64(1_000_000)  # 1 million mojos
PROTOCOL_PUZHASH = bytes32(b"\xaa" * 32)
SMART_DEED_INNER_HASH = bytes32(b"\xbb" * 32)
BUYER_PUZHASH = bytes32(b"\xcc" * 32)
DEED_COIN_ID = bytes32(b"\xdd" * 32)

# Protocol prefix
PROTOCOL_PREFIX = b"\x53"

# Condition opcodes
CREATE_COIN = 51
SEND_MESSAGE = 66
RECEIVE_MESSAGE = 67
ASSERT_MY_COIN_ID = 70
ASSERT_MY_AMOUNT = 73
REMARK = 1


def curry_purchase_payment(par_value=PAR_VALUE, protocol_ph=PROTOCOL_PUZHASH):
    return PURCHASE_PAYMENT_MOD.curry(par_value, protocol_ph)


def curry_mint_offer(
    smart_deed_inner_hash=SMART_DEED_INNER_HASH,
    purchase_mod_hash=None,
    par_value=PAR_VALUE,
    protocol_ph=PROTOCOL_PUZHASH,
):
    if purchase_mod_hash is None:
        purchase_mod_hash = PURCHASE_PAYMENT_MOD.get_tree_hash()
    return MINT_OFFER_MOD.curry(
        smart_deed_inner_hash, purchase_mod_hash, par_value, protocol_ph
    )


class TestPurchasePayment:
    """Test purchase_payment.clsp conditions."""

    def test_exact_payment_no_change(self):
        """Pay exactly par_value — no change coin created."""
        curried = curry_purchase_payment()
        sol = Program.to([BUYER_PUZHASH, PAR_VALUE])
        result = curried.run(sol)
        conditions = result.as_python()

        # 3 conditions: CREATE_COIN (payment), SEND_MESSAGE, ASSERT_MY_AMOUNT
        assert len(conditions) == 3

        # CREATE_COIN to protocol
        assert conditions[0][0] == bytes([CREATE_COIN])
        assert conditions[0][1] == PROTOCOL_PUZHASH
        assert int.from_bytes(conditions[0][2], "big") == PAR_VALUE

        # SEND_MESSAGE 0x10
        assert conditions[1][0] == bytes([SEND_MESSAGE])
        assert conditions[1][1] == bytes([0x10])
        assert conditions[1][2][:1] == PROTOCOL_PREFIX

        # ASSERT_MY_AMOUNT
        assert conditions[2][0] == bytes([ASSERT_MY_AMOUNT])

    def test_overpayment_produces_change(self):
        """Pay more than par_value — change coin goes to buyer."""
        curried = curry_purchase_payment()
        overpay = uint64(PAR_VALUE + 500_000)
        sol = Program.to([BUYER_PUZHASH, overpay])
        result = curried.run(sol)
        conditions = result.as_python()

        # 4 conditions: change CREATE_COIN, payment CREATE_COIN, SEND_MESSAGE, ASSERT_MY_AMOUNT
        assert len(conditions) == 4

        # First: change to buyer
        assert conditions[0][0] == bytes([CREATE_COIN])
        assert conditions[0][1] == BUYER_PUZHASH
        change_amount = int.from_bytes(conditions[0][2], "big")
        assert change_amount == 500_000

        # Second: payment to protocol
        assert conditions[1][0] == bytes([CREATE_COIN])
        assert conditions[1][1] == PROTOCOL_PUZHASH

    def test_underpayment_fails(self):
        """Amount less than par_value must fail."""
        curried = curry_purchase_payment()
        underpay = uint64(PAR_VALUE - 1)
        sol = Program.to([BUYER_PUZHASH, underpay])
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_zero_par_value_fails(self):
        """PAR_VALUE of 0 is rejected at curry-time validation."""
        curried = PURCHASE_PAYMENT_MOD.curry(0, PROTOCOL_PUZHASH)
        sol = Program.to([BUYER_PUZHASH, uint64(100)])
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_invalid_buyer_puzhash_fails(self):
        """Non-32-byte buyer puzzle hash fails."""
        curried = curry_purchase_payment()
        sol = Program.to([b"\xcc" * 16, PAR_VALUE])
        with pytest.raises(ValueError):
            curried.run(sol)


class TestMintOfferDelegate:
    """Test mint_offer_delegate.clsp conditions."""

    def test_valid_spend_produces_correct_conditions(self):
        """Happy path: correct conditions emitted."""
        curried = curry_mint_offer()
        sol = Program.to([DEED_COIN_ID])
        result = curried.run(sol)
        conditions = result.as_python()

        # 4 conditions: ASSERT_MY_COIN_ID, CREATE_COIN, RECEIVE_MESSAGE, REMARK
        assert len(conditions) == 4

        # ASSERT_MY_COIN_ID
        assert conditions[0][0] == bytes([ASSERT_MY_COIN_ID])
        assert conditions[0][1] == DEED_COIN_ID

        # CREATE_COIN — transition to smart_deed_inner
        assert conditions[1][0] == bytes([CREATE_COIN])
        assert conditions[1][1] == SMART_DEED_INNER_HASH
        assert int.from_bytes(conditions[1][2], "big") == 1

        # RECEIVE_MESSAGE 0x10
        assert conditions[2][0] == bytes([RECEIVE_MESSAGE])
        assert conditions[2][1] == bytes([0x10])
        assert conditions[2][2][:1] == PROTOCOL_PREFIX

        # REMARK
        assert conditions[3][0] == bytes([REMARK])

    def test_invalid_coin_id_fails(self):
        """Non-32-byte coin ID fails validation."""
        curried = curry_mint_offer()
        sol = Program.to([b"\xdd" * 16])
        with pytest.raises(ValueError):
            curried.run(sol)


class TestCrossMessageMatch:
    """Verify SEND_MESSAGE and RECEIVE_MESSAGE use identical message bytes."""

    def test_message_bytes_match(self):
        """The message sent by purchase_payment must exactly match
        what mint_offer_delegate expects to receive."""
        # Run purchase_payment
        pp_curried = curry_purchase_payment()
        pp_sol = Program.to([BUYER_PUZHASH, PAR_VALUE])
        pp_conditions = pp_curried.run(pp_sol).as_python()

        # Extract SEND_MESSAGE condition
        send_cond = [c for c in pp_conditions if c[0] == bytes([SEND_MESSAGE])][0]
        sent_mode = send_cond[1]
        sent_msg = send_cond[2]

        # Run mint_offer_delegate
        mod_curried = curry_mint_offer()
        mod_sol = Program.to([DEED_COIN_ID])
        mod_conditions = mod_curried.run(mod_sol).as_python()

        # Extract RECEIVE_MESSAGE condition
        recv_cond = [c for c in mod_conditions if c[0] == bytes([RECEIVE_MESSAGE])][0]
        recv_mode = recv_cond[1]
        recv_msg = recv_cond[2]

        # Mode and message must match
        assert sent_mode == recv_mode, "SEND/RECEIVE mode mismatch"
        assert sent_msg == recv_msg, "SEND/RECEIVE message mismatch"

    def test_receive_expects_correct_purchase_puzhash(self):
        """The third arg of RECEIVE_MESSAGE must be the curry_hashes of
        purchase_payment with the same PAR_VALUE and PROTOCOL_PUZHASH."""
        mod_curried = curry_mint_offer()
        mod_sol = Program.to([DEED_COIN_ID])
        mod_conditions = mod_curried.run(mod_sol).as_python()

        recv_cond = [c for c in mod_conditions if c[0] == bytes([RECEIVE_MESSAGE])][0]
        expected_sender_ph = recv_cond[3]

        # Compute what the curried purchase_payment puzzle hash should be
        actual_pp_ph = curry_purchase_payment().get_tree_hash()
        assert expected_sender_ph == actual_pp_ph, (
            f"RECEIVE_MESSAGE sender puzzle hash mismatch: "
            f"expected {actual_pp_ph.hex()}, got {expected_sender_ph.hex()}"
        )

    def test_mismatched_par_value_breaks_message(self):
        """If purchase_payment is curried with different PAR_VALUE,
        the messages won't match."""
        # Purchase payment with par_value + 1
        pp_curried = PURCHASE_PAYMENT_MOD.curry(PAR_VALUE + 1, PROTOCOL_PUZHASH)
        pp_sol = Program.to([BUYER_PUZHASH, uint64(PAR_VALUE + 1)])
        pp_conditions = pp_curried.run(pp_sol).as_python()
        send_cond = [c for c in pp_conditions if c[0] == bytes([SEND_MESSAGE])][0]
        sent_msg = send_cond[2]

        # mint_offer_delegate with original PAR_VALUE
        mod_curried = curry_mint_offer()
        mod_sol = Program.to([DEED_COIN_ID])
        mod_conditions = mod_curried.run(mod_sol).as_python()
        recv_cond = [c for c in mod_conditions if c[0] == bytes([RECEIVE_MESSAGE])][0]
        recv_msg = recv_cond[2]

        # Messages must NOT match
        assert sent_msg != recv_msg, "Different PAR_VALUE should produce different messages"
