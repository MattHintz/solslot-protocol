"""Unit tests for quorum_did_inner.clsp — the governance-gated DID inner puzzle.

Tests verify:
  1. DID produces RECEIVE_MESSAGE + CREATE_PUZZLE_ANNOUNCEMENT when given valid inputs
  2. Invalid inputs (non-b32) fail
"""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

QUORUM_DID_MOD: Program = load_clvm(
    "quorum_did_inner.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

# Test constants
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)
GOV_LAUNCHER_ID = bytes32(b"\xab" * 32)
GOV_SINGLETON_STRUCT = Program.to((SINGLETON_MOD_HASH, (GOV_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH)))

# Protocol prefix
PROTOCOL_PREFIX = b"\x53"


def curry_quorum_did() -> Program:
    """Curry quorum_did_inner with governance singleton struct."""
    return QUORUM_DID_MOD.curry(GOV_SINGLETON_STRUCT)


class TestQuorumDidInner:
    """Test quorum_did_inner.clsp produces correct conditions."""

    def test_valid_inputs_return_conditions(self):
        curried = curry_quorum_did()
        singleton_full_puzzle_hash = bytes32(b"\xcc" * 32)
        gov_inner_puzhash = bytes32(b"\xdd" * 32)

        sol = Program.to([singleton_full_puzzle_hash, gov_inner_puzhash])
        result = curried.run(sol)
        conditions = result.as_python()

        # 2 conditions: RECEIVE_MESSAGE, CREATE_PUZZLE_ANNOUNCEMENT
        assert len(conditions) == 2

        # RECEIVE_MESSAGE 0x10 (from governance)
        assert conditions[0][0] == bytes([67])  # RECEIVE_MESSAGE
        assert conditions[0][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        assert conditions[0][2][:1] == PROTOCOL_PREFIX

        # CREATE_PUZZLE_ANNOUNCEMENT (the announcement the launcher asserts)
        assert conditions[1][0] == bytes([62])  # CREATE_PUZZLE_ANNOUNCEMENT
        assert conditions[1][1] == singleton_full_puzzle_hash

    def test_invalid_singleton_hash_fails(self):
        curried = curry_quorum_did()
        # Non-32-byte input should fail validation
        sol = Program.to([b"\xcc" * 16, bytes32(b"\xdd" * 32)])
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_invalid_gov_inner_puzhash_fails(self):
        curried = curry_quorum_did()
        sol = Program.to([bytes32(b"\xcc" * 32), b"\xdd" * 16])
        with pytest.raises(ValueError):
            curried.run(sol)
