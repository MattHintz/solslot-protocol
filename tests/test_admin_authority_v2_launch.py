"""Tests for the v2 admin-authority genesis launch helpers.

Phase 9-Hermes-D D-2.1: validates ``compute_launch_outputs`` and
``singleton_full_puzzle_hash`` against:
  * The reference ``puzzle_for_singleton`` from chia-blockchain (gold
    standard) — guards against drift in our hand-rolled tree-hash
    computation.
  * Determinism — same inputs always produce same outputs.
  * Cross-input independence — varying inputs surfaces in outputs.
  * The on-chain announcement formula — sha256(coin_id || message).
"""
from __future__ import annotations

import hashlib

from chia.types.blockchain_format.coin import Coin
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    puzzle_for_singleton,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.admin_authority_v2_driver import (
    EMPTY_LIST_HASH,
    SINGLETON_AMOUNT,
    compute_launch_outputs,
    make_inner_puzzle_hash,
    singleton_full_puzzle_hash,
)


# Sentinel funding-coin parent ids; deliberately distinct so a swap in
# the launcher-id derivation surfaces immediately.
PARENT_A = bytes32(b"\xa1" * 32)
PARENT_B = bytes32(b"\xb2" * 32)

# Sentinel inner puzzle hashes (distinct from parents so a confusion
# between roles surfaces).
INNER_X = bytes32(b"\xcc" * 32)
INNER_Y = bytes32(b"\xdd" * 32)


class TestSingletonFullPuzzleHash:
    """Cross-check the hand-rolled hasher against chia's reference.

    The strict cross-check is in ``test_full_round_trip_matches``: it
    constructs a real inner Program, hashes it, and verifies our helper
    (which takes the hash) and ``puzzle_for_singleton`` (which takes the
    Program) produce the same final puzzle hash.  Distinct-input tests
    here just guard against trivial implementation collapse.
    """

    def test_changes_with_launcher_id(self) -> None:
        """Different launcher_ids → different full puzzle hashes."""
        a = singleton_full_puzzle_hash(PARENT_A, INNER_X)
        b = singleton_full_puzzle_hash(PARENT_B, INNER_X)
        assert a != b

    def test_changes_with_inner(self) -> None:
        """Different inner puzzle hashes → different full puzzle hashes."""
        a = singleton_full_puzzle_hash(PARENT_A, INNER_X)
        b = singleton_full_puzzle_hash(PARENT_A, INNER_Y)
        assert a != b


class TestSingletonFullPuzzleHashAgainstReference:
    """Strict cross-check: align both sides with the same Program input."""

    def test_full_round_trip_matches(self) -> None:
        """Build an inner Program, hash it, pass hash to ours, compare."""
        from chia.types.blockchain_format.program import Program

        launcher_id = bytes32(b"\xfe" * 32)
        # Some arbitrary "inner puzzle" — content doesn't matter, only
        # that we use the same Program in both branches.
        inner_program = Program.to([1, 2, 3, [4, 5]])
        inner_hash = bytes32(inner_program.get_tree_hash())

        ours = singleton_full_puzzle_hash(launcher_id, inner_hash)
        reference = bytes32(
            puzzle_for_singleton(launcher_id, inner_program).get_tree_hash()
        )

        assert ours == reference, (
            f"Full round-trip mismatch:\n"
            f"  inner program: {inner_program}\n"
            f"  inner hash:    0x{inner_hash.hex()}\n"
            f"  ours:          0x{ours.hex()}\n"
            f"  reference:     0x{reference.hex()}"
        )


class TestComputeLaunchOutputs:
    """End-to-end determinism + correctness for the launch helper."""

    def _default_inner_hash(self) -> bytes32:
        """A representative v2 inner puzzle hash for tests."""
        return make_inner_puzzle_hash(
            mips_root_hash=bytes32(b"\x11" * 32),
            admins_hash=bytes32(b"\x22" * 32),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=1,
        )

    def test_launcher_coin_uses_standard_constants(self) -> None:
        """Launcher coin is derived from the standard chia constants."""
        out = compute_launch_outputs(
            parent_coin_id=PARENT_A,
            eve_inner_puzzle_hash=self._default_inner_hash(),
        )
        assert out.launcher_coin.parent_coin_info == PARENT_A
        assert out.launcher_coin.puzzle_hash == SINGLETON_LAUNCHER_HASH
        assert out.launcher_coin.amount == SINGLETON_AMOUNT

    def test_launcher_id_equals_launcher_coin_name(self) -> None:
        """``launcher_id`` is just a convenience alias for ``launcher_coin.name()``."""
        out = compute_launch_outputs(
            parent_coin_id=PARENT_A,
            eve_inner_puzzle_hash=self._default_inner_hash(),
        )
        assert out.launcher_id == bytes32(out.launcher_coin.name())

    def test_eve_coin_lineage_parent_is_launcher_id(self) -> None:
        """The eve coin's parent IS the launcher coin — that's what makes
        the singleton's lineage walkable from launcher_id forward."""
        out = compute_launch_outputs(
            parent_coin_id=PARENT_A,
            eve_inner_puzzle_hash=self._default_inner_hash(),
        )
        assert out.eve_coin.parent_coin_info == out.launcher_id

    def test_eve_full_puzzle_hash_uses_singleton_wrapping(self) -> None:
        """Eve coin lives at ``singleton_top_layer.curry(struct, inner)``."""
        inner_hash = self._default_inner_hash()
        out = compute_launch_outputs(
            parent_coin_id=PARENT_A,
            eve_inner_puzzle_hash=inner_hash,
        )
        expected = singleton_full_puzzle_hash(out.launcher_id, inner_hash)
        assert out.eve_full_puzzle_hash == expected
        assert out.eve_coin.puzzle_hash == expected

    def test_announcement_id_follows_standard_formula(self) -> None:
        """``ASSERT_PUZZLE_ANNOUNCEMENT`` consumers expect
        ``sha256(coin_id || sha256tree(solution))``."""
        out = compute_launch_outputs(
            parent_coin_id=PARENT_A,
            eve_inner_puzzle_hash=self._default_inner_hash(),
        )
        expected = bytes32(
            hashlib.sha256(
                out.launcher_id + out.launcher_announcement_message
            ).digest()
        )
        assert out.launcher_announcement_id == expected

    def test_launcher_solution_shape(self) -> None:
        """Solution is ``(eve_full_ph eve_amount key_value_list)`` per the
        standard chia singleton launcher contract."""
        out = compute_launch_outputs(
            parent_coin_id=PARENT_A,
            eve_inner_puzzle_hash=self._default_inner_hash(),
            eve_amount=1,
        )
        as_list = list(out.launcher_solution.as_iter())
        # First element: the eve coin's full puzzle hash.
        assert bytes(as_list[0].atom) == out.eve_full_puzzle_hash
        # Second element: the eve amount as an atom.
        assert int(as_list[1].as_int()) == 1
        # Third element: empty key_value_list (we don't use launch memos
        # for v2; reserved for future protocol extensions).
        assert as_list[2].atom == b"" or as_list[2].as_iter().__next__ is None

    def test_changing_parent_changes_launcher_id(self) -> None:
        """Different funding coin → different launcher_id → different
        eve coin location.  Critical for the launch being uniquely
        identified by the funding decision."""
        inner_hash = self._default_inner_hash()
        a = compute_launch_outputs(parent_coin_id=PARENT_A, eve_inner_puzzle_hash=inner_hash)
        b = compute_launch_outputs(parent_coin_id=PARENT_B, eve_inner_puzzle_hash=inner_hash)
        assert a.launcher_id != b.launcher_id
        assert a.eve_full_puzzle_hash != b.eve_full_puzzle_hash
        assert a.eve_coin != b.eve_coin

    def test_changing_inner_puzzle_hash_changes_eve(self) -> None:
        """Same parent but different inner state → different eve coin
        but SAME launcher_id (launcher only depends on parent + standard
        constants, so launcher_id is a function of the funding decision
        alone)."""
        a = compute_launch_outputs(parent_coin_id=PARENT_A, eve_inner_puzzle_hash=INNER_X)
        b = compute_launch_outputs(parent_coin_id=PARENT_A, eve_inner_puzzle_hash=INNER_Y)
        # Launcher_id is the same (same parent + same launcher constants).
        assert a.launcher_id == b.launcher_id
        # But the eve coins differ because the inner puzzle differs.
        assert a.eve_full_puzzle_hash != b.eve_full_puzzle_hash
        assert a.eve_coin != b.eve_coin

    def test_helper_is_pure(self) -> None:
        """Calling twice with same inputs returns equal outputs."""
        kwargs = {
            "parent_coin_id": PARENT_A,
            "eve_inner_puzzle_hash": self._default_inner_hash(),
        }
        a = compute_launch_outputs(**kwargs)
        b = compute_launch_outputs(**kwargs)
        # Compare every field individually since LaunchOutputs is a frozen
        # dataclass and dataclass __eq__ compares fields anyway, but
        # explicit unpacking gives a clearer failure message.
        assert a.launcher_id == b.launcher_id
        assert a.eve_full_puzzle_hash == b.eve_full_puzzle_hash
        assert a.launcher_announcement_id == b.launcher_announcement_id
        assert a.eve_coin == b.eve_coin
