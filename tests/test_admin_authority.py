"""Unit tests for admin_authority_inner.clsp + admin_authority_driver.py.

The admin-authority singleton (A.2) is the on-chain replacement for
the off-chain admin allowlist env var.  These tests verify the puzzle's
m-of-n rotation logic, replay protection, and the cross-repo content-
hash contract that lets the API verify on-chain authority state.
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_driver import (
    AdminAuthorityState,
    RotationSpendArtifacts,
    admin_authority_inner_mod,
    admin_authority_inner_mod_hash,
    build_rotation_spend,
    compute_state_hash,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    parse_inner_puzzle,
)


# ── Test fixtures ────────────────────────────────────────────────────────

# Distinct sentinel BLS G1 pubkeys (48 bytes each).  Real BLS keys are
# G1 group elements; these sentinels are intentionally not real keys
# (they would never validate AGG_SIG_ME at consensus time) but the
# Chialisp puzzle does not check group-element validity — that's
# delegated to consensus.  Tests run the puzzle and inspect emitted
# conditions, never actually verify signatures.
ADMIN_A = b"\x11" * 48
ADMIN_B = b"\x22" * 48
ADMIN_C = b"\x33" * 48
ADMIN_D = b"\x44" * 48

INITIAL_ALLOWLIST = [ADMIN_A, ADMIN_B, ADMIN_C]
INITIAL_QUORUM = 2
INITIAL_VERSION = 1

NEW_ALLOWLIST = [ADMIN_A, ADMIN_B, ADMIN_D]  # rotated out C, rotated in D
NEW_QUORUM = 2
NEW_VERSION = 2

SINGLETON_AMOUNT = 1


def _make_state() -> AdminAuthorityState:
    return AdminAuthorityState(
        self_mod_hash=admin_authority_inner_mod_hash(),
        allowlist=tuple(INITIAL_ALLOWLIST),
        quorum_m=INITIAL_QUORUM,
        authority_version=INITIAL_VERSION,
    )


def _run_rotation(
    *,
    new_allowlist=None,
    new_quorum_m=None,
    new_version=None,
    signer_indices=(0, 1),
) -> tuple[list, RotationSpendArtifacts]:
    state = _make_state()
    artifacts = build_rotation_spend(
        current=state,
        new_allowlist=new_allowlist or NEW_ALLOWLIST,
        new_quorum_m=new_quorum_m if new_quorum_m is not None else NEW_QUORUM,
        new_authority_version=new_version
        if new_version is not None
        else NEW_VERSION,
        signer_indices=list(signer_indices),
        my_amount=SINGLETON_AMOUNT,
    )
    curried = make_inner_puzzle(
        allowlist=INITIAL_ALLOWLIST,
        quorum_m=INITIAL_QUORUM,
        authority_version=INITIAL_VERSION,
    )
    result = curried.run(artifacts.inner_solution)
    return result.as_python(), artifacts


# ── Compile + module-hash sanity ────────────────────────────────────────


class TestCompile:
    def test_module_compiles(self):
        mod = admin_authority_inner_mod()
        assert mod is not None
        assert mod.get_tree_hash() is not None

    def test_module_hash_is_stable(self):
        h1 = admin_authority_inner_mod_hash()
        h2 = admin_authority_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32


# ── State hash determinism ──────────────────────────────────────────────


class TestStateHash:
    def test_determinism(self):
        h1 = compute_state_hash(INITIAL_ALLOWLIST, 2, 1)
        h2 = compute_state_hash(INITIAL_ALLOWLIST, 2, 1)
        assert h1 == h2
        assert len(h1) == 32

    def test_allowlist_change_changes_hash(self):
        h1 = compute_state_hash(INITIAL_ALLOWLIST, 2, 1)
        h2 = compute_state_hash(NEW_ALLOWLIST, 2, 1)
        assert h1 != h2

    def test_allowlist_order_matters(self):
        h1 = compute_state_hash([ADMIN_A, ADMIN_B], 1, 1)
        h2 = compute_state_hash([ADMIN_B, ADMIN_A], 1, 1)
        assert h1 != h2

    def test_quorum_change_changes_hash(self):
        h1 = compute_state_hash(INITIAL_ALLOWLIST, 2, 1)
        h2 = compute_state_hash(INITIAL_ALLOWLIST, 3, 1)
        assert h1 != h2

    def test_version_change_changes_hash(self):
        h1 = compute_state_hash(INITIAL_ALLOWLIST, 2, 1)
        h2 = compute_state_hash(INITIAL_ALLOWLIST, 2, 2)
        assert h1 != h2

    def test_state_hash_matches_on_chain(self):
        """The Python ``compute_state_hash`` MUST equal the Chialisp
        ``state-hash`` defun.  Asserted via the rotation spend's
        CREATE_PUZZLE_ANNOUNCEMENT (which embeds the same hash with
        PROTOCOL_PREFIX = 0x50 prepended).
        """
        conditions, artifacts = _run_rotation()
        announcements = [c for c in conditions if c[0] == bytes([62])]
        assert len(announcements) == 1
        msg = announcements[0][1]
        assert msg[:1] == b"\x50"  # PROTOCOL_PREFIX
        on_chain_hash = msg[1:]
        off_chain_hash = compute_state_hash(NEW_ALLOWLIST, NEW_QUORUM, NEW_VERSION)
        assert on_chain_hash == bytes(off_chain_hash)


# ── Round-trip: curry → parse ───────────────────────────────────────────


class TestParse:
    def test_round_trip(self):
        puzzle = make_inner_puzzle(
            allowlist=INITIAL_ALLOWLIST,
            quorum_m=INITIAL_QUORUM,
            authority_version=INITIAL_VERSION,
        )
        state = parse_inner_puzzle(puzzle)
        assert state.allowlist == tuple(INITIAL_ALLOWLIST)
        assert state.quorum_m == INITIAL_QUORUM
        assert state.authority_version == INITIAL_VERSION
        assert state.self_mod_hash == admin_authority_inner_mod_hash()

    def test_has_member(self):
        state = _make_state()
        assert state.has_member(ADMIN_A)
        assert state.has_member(ADMIN_B)
        assert state.has_member(ADMIN_C)
        assert not state.has_member(ADMIN_D)

    def test_state_hash_property(self):
        state = _make_state()
        assert state.state_hash == compute_state_hash(
            INITIAL_ALLOWLIST, INITIAL_QUORUM, INITIAL_VERSION
        )

    def test_parse_rejects_wrong_module(self):
        from chia.wallet.puzzles.load_clvm import load_clvm
        other = load_clvm(
            "quorum_did_inner.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        ).curry(b"\x00" * 32)
        with pytest.raises(ValueError, match="admin_authority_inner"):
            parse_inner_puzzle(other)


# ── Rotation spend conditions ────────────────────────────────────────────


class TestRotationSpend:
    """Drive a full rotation spend and assert every emitted condition."""

    def test_emits_correct_condition_count(self):
        # 2 AGG_SIG_ME (one per signer) + CREATE_COIN +
        # CREATE_PUZZLE_ANNOUNCEMENT + ASSERT_MY_AMOUNT = 5
        conditions, _ = _run_rotation()
        assert len(conditions) == 5

    def test_agg_sig_me_per_signer(self):
        conditions, artifacts = _run_rotation(signer_indices=(0, 1))
        agg_sigs = [c for c in conditions if c[0] == bytes([50])]
        assert len(agg_sigs) == 2
        # Signer at index 0 = ADMIN_A, index 1 = ADMIN_B
        signer_pubkeys = {agg_sigs[0][1], agg_sigs[1][1]}
        assert signer_pubkeys == {ADMIN_A, ADMIN_B}
        # Both signers commit to the same state hash.
        for sig in agg_sigs:
            assert sig[2] == bytes(artifacts.agg_sig_me_message)

    def test_three_of_three_quorum(self):
        # All three current admins sign — exceeds quorum_m=2 minimum.
        conditions, _ = _run_rotation(signer_indices=(0, 1, 2))
        agg_sigs = [c for c in conditions if c[0] == bytes([50])]
        assert len(agg_sigs) == 3
        signer_pubkeys = {sig[1] for sig in agg_sigs}
        assert signer_pubkeys == {ADMIN_A, ADMIN_B, ADMIN_C}

    def test_create_coin_recreates_self_with_new_state(self):
        conditions, artifacts = _run_rotation()
        creates = [c for c in conditions if c[0] == bytes([51])]
        assert len(creates) == 1
        dest_puzhash = creates[0][1]
        assert dest_puzhash == bytes(artifacts.new_inner_puzzle_hash)
        amount = int.from_bytes(creates[0][2], "big")
        assert amount == SINGLETON_AMOUNT

    def test_create_puzzle_announcement_carries_new_state_hash(self):
        conditions, artifacts = _run_rotation()
        announcements = [c for c in conditions if c[0] == bytes([62])]
        assert len(announcements) == 1
        msg = announcements[0][1]
        assert msg[:1] == b"\x50"
        assert msg[1:] == bytes(artifacts.new_state_hash)

    def test_assert_my_amount(self):
        conditions, _ = _run_rotation()
        amount_asserts = [c for c in conditions if c[0] == bytes([73])]
        assert len(amount_asserts) == 1
        assert int.from_bytes(amount_asserts[0][1], "big") == SINGLETON_AMOUNT


# ── Replay / version protection ─────────────────────────────────────────


class TestReplayProtection:
    def test_python_rejects_version_downgrade(self):
        state = _make_state()
        with pytest.raises(ValueError, match="strictly exceed"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=NEW_QUORUM,
                new_authority_version=INITIAL_VERSION,  # same — must reject
                signer_indices=[0, 1],
                my_amount=SINGLETON_AMOUNT,
            )

    def test_clvm_rejects_version_downgrade(self):
        # Bypass Python's check by hand-rolling the solution.
        curried = make_inner_puzzle(
            allowlist=INITIAL_ALLOWLIST,
            quorum_m=INITIAL_QUORUM,
            authority_version=10,  # higher current version
        )
        sol = Program.to(
            [SINGLETON_AMOUNT, NEW_ALLOWLIST, 2, 5, [0, 1]]  # downgrade to v5
        )
        with pytest.raises(ValueError):
            curried.run(sol)


# ── Quorum enforcement ───────────────────────────────────────────────────


class TestQuorumEnforcement:
    def test_python_rejects_too_few_signers(self):
        state = _make_state()
        with pytest.raises(ValueError, match="need ≥"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=NEW_QUORUM,
                new_authority_version=NEW_VERSION,
                signer_indices=[0],  # only 1, but quorum_m=2
                my_amount=SINGLETON_AMOUNT,
            )

    def test_clvm_rejects_too_few_signers(self):
        # Hand-roll a solution with fewer signers than QUORUM_M.
        curried = make_inner_puzzle(
            allowlist=INITIAL_ALLOWLIST,
            quorum_m=INITIAL_QUORUM,
            authority_version=INITIAL_VERSION,
        )
        sol = Program.to(
            [SINGLETON_AMOUNT, NEW_ALLOWLIST, NEW_QUORUM, NEW_VERSION, [0]]
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_python_rejects_unsorted_signer_indices(self):
        state = _make_state()
        with pytest.raises(ValueError, match="sorted strictly ascending"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=NEW_QUORUM,
                new_authority_version=NEW_VERSION,
                signer_indices=[1, 0],  # backwards
                my_amount=SINGLETON_AMOUNT,
            )

    def test_python_rejects_duplicate_signers(self):
        state = _make_state()
        with pytest.raises(ValueError, match="sorted strictly ascending"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=NEW_QUORUM,
                new_authority_version=NEW_VERSION,
                signer_indices=[0, 0],  # duplicate
                my_amount=SINGLETON_AMOUNT,
            )

    def test_clvm_rejects_duplicate_signers(self):
        curried = make_inner_puzzle(
            allowlist=INITIAL_ALLOWLIST,
            quorum_m=INITIAL_QUORUM,
            authority_version=INITIAL_VERSION,
        )
        sol = Program.to(
            [SINGLETON_AMOUNT, NEW_ALLOWLIST, NEW_QUORUM, NEW_VERSION, [0, 0]]
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_python_rejects_out_of_range_signer_index(self):
        state = _make_state()
        with pytest.raises(ValueError, match="out of range"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=NEW_QUORUM,
                new_authority_version=NEW_VERSION,
                signer_indices=[0, 5],  # 5 is out of range (allowlist has 3)
                my_amount=SINGLETON_AMOUNT,
            )

    def test_clvm_rejects_out_of_range_signer_index(self):
        curried = make_inner_puzzle(
            allowlist=INITIAL_ALLOWLIST,
            quorum_m=INITIAL_QUORUM,
            authority_version=INITIAL_VERSION,
        )
        sol = Program.to(
            [SINGLETON_AMOUNT, NEW_ALLOWLIST, NEW_QUORUM, NEW_VERSION, [0, 5]]
        )
        with pytest.raises(ValueError):
            curried.run(sol)


# ── New-state validation ────────────────────────────────────────────────


class TestNewStateValidation:
    def test_python_rejects_zero_quorum(self):
        state = _make_state()
        with pytest.raises(ValueError, match=r"quorum_m must be in"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=0,
                new_authority_version=NEW_VERSION,
                signer_indices=[0, 1],
                my_amount=SINGLETON_AMOUNT,
            )

    def test_python_rejects_quorum_exceeds_allowlist_size(self):
        state = _make_state()
        with pytest.raises(ValueError, match=r"quorum_m must be in"):
            build_rotation_spend(
                current=state,
                new_allowlist=[ADMIN_A, ADMIN_B],
                new_quorum_m=5,  # exceeds 2-element allowlist
                new_authority_version=NEW_VERSION,
                signer_indices=[0, 1],
                my_amount=SINGLETON_AMOUNT,
            )

    def test_clvm_rejects_quorum_exceeds_allowlist_size(self):
        curried = make_inner_puzzle(
            allowlist=INITIAL_ALLOWLIST,
            quorum_m=INITIAL_QUORUM,
            authority_version=INITIAL_VERSION,
        )
        sol = Program.to(
            [
                SINGLETON_AMOUNT,
                [ADMIN_A, ADMIN_B],  # 2-element allowlist
                5,                     # quorum exceeds size
                NEW_VERSION,
                [0, 1],
            ]
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_python_rejects_short_pubkey(self):
        state = _make_state()
        with pytest.raises(ValueError, match="48-byte"):
            build_rotation_spend(
                current=state,
                new_allowlist=[b"\xaa" * 16, ADMIN_B, ADMIN_C],  # too short
                new_quorum_m=NEW_QUORUM,
                new_authority_version=NEW_VERSION,
                signer_indices=[0, 1],
                my_amount=SINGLETON_AMOUNT,
            )

    def test_python_rejects_even_amount(self):
        state = _make_state()
        with pytest.raises(ValueError, match="amount must be odd"):
            build_rotation_spend(
                current=state,
                new_allowlist=NEW_ALLOWLIST,
                new_quorum_m=NEW_QUORUM,
                new_authority_version=NEW_VERSION,
                signer_indices=[0, 1],
                my_amount=2,
            )


# ── Construction validation ─────────────────────────────────────────────


class TestConstruction:
    def test_make_inner_puzzle_rejects_zero_quorum(self):
        with pytest.raises(ValueError, match="quorum_m must be in"):
            make_inner_puzzle(
                allowlist=INITIAL_ALLOWLIST,
                quorum_m=0,
                authority_version=INITIAL_VERSION,
            )

    def test_make_inner_puzzle_rejects_quorum_too_large(self):
        with pytest.raises(ValueError, match="quorum_m must be in"):
            make_inner_puzzle(
                allowlist=INITIAL_ALLOWLIST,
                quorum_m=10,
                authority_version=INITIAL_VERSION,
            )

    def test_make_inner_puzzle_rejects_short_pubkey(self):
        with pytest.raises(ValueError, match="48-byte"):
            make_inner_puzzle(
                allowlist=[ADMIN_A, b"\xbb" * 16, ADMIN_C],
                quorum_m=2,
                authority_version=1,
            )
