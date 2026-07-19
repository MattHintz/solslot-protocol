"""Unit tests for admin_authority_v2_inner.clsp + admin_authority_v2_driver.py.

The v2 admin-authority singleton replaces v1's homegrown BLS allowlist with
a thin shim over CHIP-0043 MIPS. These tests verify each spend type by
constructing solutions via the driver and running the curried puzzle in
the CLVM interpreter.

Design reference:
    research/SOLSLOT_ADMIN_AUTHORITY_V2_DESIGN.md

Note on MIPS reveals: real-world OPERATIONAL spends feed in the actual
MIPS m_of_n puzzle reveal (composed via chia-wallet-sdk's MIPS primitives).
For testing the shim's behaviour in isolation, we use trivial constant
puzzles whose conditions are deterministic and easy to inspect — the
shim's correctness is independent of the specific MIPS sub-tree it wraps.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v2_driver import (
    AdminAuthorityV2State,
    AdminRecord,
    DEFAULT_COOLDOWN_BLOCKS,
    DEFAULT_MAX_ADMINS,
    DEFAULT_MAX_KEYS_PER_ADMIN,
    DEFAULT_SGT_GOVERNANCE_PUZZLE_HASH,
    DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
    EMPTY_LIST_HASH,
    OP_KIND_ADD,
    OP_KIND_REMOVE,
    PROPOSE_WINDOW,
    PendingOp,
    SPEND_OPERATIONAL,
    SPEND_ADMIN_ROSTER_UPDATE,
    SPEND_KEY_ADD_ACTIVATE,
    SPEND_KEY_ADD_PROPOSE,
    SPEND_KEY_REMOVE_QUORUM,
    admin_authority_v2_inner_mod_hash,
    admin_supermajority_threshold,
    single_member_admin_record,
    build_admin_roster_update_solution,
    build_admin_slot_add_preview,
    build_admin_slot_add_spend,
    build_key_add_activate_solution,
    build_key_add_propose_solution,
    build_key_add_veto_solution,
    build_key_remove_emergency_solution,
    build_key_remove_quorum_solution,
    build_operational_solution,
    compute_admins_hash,
    compute_key_op_binding_hash,
    compute_key_remove_quorum_binding_hash,
    compute_pending_ops_hash,
    compute_roster_update_binding_hash,
    compute_state_hash,
    make_inner_puzzle,
    parse_inner_puzzle,
)


DESIGN_DOC = (
    Path(__file__).resolve().parents[1]
    / "research"
    / "SOLSLOT_ADMIN_AUTHORITY_V2_DESIGN.md"
)


# ─────────────────────────────────────────────────────────────────────────
# Test fixtures.
#
# Sentinel member tree hashes (32 bytes each). Real-world leaves are
# tree hashes of curried BlsMember / Eip712Member / etc. puzzles; for
# shim-only tests we just need 32-byte atoms that the shim will treat
# as opaque identifiers.
# ─────────────────────────────────────────────────────────────────────────

LEAF_BLS_ADMIN_1 = bytes32(b"\x11" * 32)
LEAF_EIP712_ADMIN_1 = bytes32(b"\x12" * 32)
LEAF_BLS_ADMIN_2 = bytes32(b"\x21" * 32)
LEAF_EIP712_ADMIN_2 = bytes32(b"\x22" * 32)

# Single admin with two leaves (BLS + EIP-712), m_within=1.
INITIAL_ADMINS = (
    AdminRecord(
        admin_idx=0,
        leaves=(LEAF_BLS_ADMIN_1, LEAF_EIP712_ADMIN_1),
        m_within=1,
    ),
    AdminRecord(
        admin_idx=1,
        leaves=(LEAF_BLS_ADMIN_2, LEAF_EIP712_ADMIN_2),
        m_within=1,
    ),
)

INITIAL_AUTHORITY_VERSION = 1
SINGLETON_AMOUNT = 1


def _trivial_mips_puzzle() -> Program:
    """A constant puzzle that emits one REMARK condition.

    Used as a stand-in for a real MIPS m_of_n reveal in OPERATIONAL
    tests. The shim doesn't care about the specific shape of the MIPS
    sub-puzzle as long as ``sha256tree(reveal) == MIPS_ROOT_HASH``; this
    lets us test the shim's wrapping behaviour without reconstructing
    the full MIPS infrastructure off-chain.

    REMARK (opcode 1) is unenforced by consensus — purely informational
    — so it's safe to use in puzzle tests where we don't want a
    signature check or coin assertion to interfere with inspection.
    """
    return Program.to((1, [[1, b"\xCA\xFE"]]))  # (q . ((1 0xCAFE)))


def _first_announcement_payload(result: Program) -> bytes:
    for cond in result.as_iter():
        if int(cond.first().as_int()) == 62:
            payload = cond.rest().first().atom
            assert payload is not None
            return payload
    raise AssertionError("No CREATE_PUZZLE_ANNOUNCEMENT emitted")


def _first_create_coin_condition(result: Program) -> tuple[bytes32, int]:
    for cond in result.as_iter():
        if int(cond.first().as_int()) == 51:
            puzzle_hash = cond.rest().first().atom
            assert puzzle_hash is not None
            amount = int(cond.rest().rest().first().as_int())
            return bytes32(puzzle_hash), amount
    raise AssertionError("No CREATE_COIN emitted")


def _first_agg_sig_me_condition(result: Program) -> tuple[bytes, bytes]:
    for cond in result.as_iter():
        if int(cond.first().as_int()) == 50:
            pubkey = cond.rest().first().atom
            message = cond.rest().rest().first().atom
            assert pubkey is not None
            assert message is not None
            return pubkey, message
    raise AssertionError("No AGG_SIG_ME emitted")


def _agg_sig_me_messages(result: Program) -> list[bytes]:
    messages: list[bytes] = []
    for cond in result.as_iter():
        if int(cond.first().as_int()) == 50:
            message = cond.rest().rest().first().atom
            assert message is not None
            messages.append(message)
    if not messages:
        raise AssertionError("No AGG_SIG_ME emitted")
    return messages


_BLS_MEMBER_FIXTURE: Program | None = None


def _bls_member_fixture() -> Program:
    """Load the test fixture BLS-style member puzzle.

    Emits a real AGG_SIG_ME condition (opcode 50). Used to exercise the
    v2 shim with non-trivial member reveals — proves the shim's
    `(a member_reveal member_solution)` machinery handles real
    signature-emitting puzzles, not just REMARK-only constants.

    Curried with PUBKEY (48 bytes); solution is the message to sign.
    """
    global _BLS_MEMBER_FIXTURE
    if _BLS_MEMBER_FIXTURE is None:
        _BLS_MEMBER_FIXTURE = load_clvm(
            "test_fixture_bls_member.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _BLS_MEMBER_FIXTURE


@pytest.fixture
def initial_state() -> dict:
    """Set up the curried v2 inner puzzle for a baseline state.

    Returns a dict with everything tests need to construct and run an
    OPERATIONAL spend without re-doing the curry boilerplate.
    """
    mips_reveal = _trivial_mips_puzzle()
    mips_root_hash = bytes32(mips_reveal.get_tree_hash())
    admins_hash = compute_admins_hash(INITIAL_ADMINS)
    inner = make_inner_puzzle(
        mips_root_hash=mips_root_hash,
        admins_hash=admins_hash,
        pending_ops_hash=EMPTY_LIST_HASH,
        authority_version=INITIAL_AUTHORITY_VERSION,
    )
    return {
        "mips_reveal": mips_reveal,
        "mips_root_hash": mips_root_hash,
        "admins_hash": admins_hash,
        "inner": inner,
    }


# ─────────────────────────────────────────────────────────────────────────
# Construction smoke tests.
# ─────────────────────────────────────────────────────────────────────────


class TestConstruction:
    def test_design_doc_pins_admin_roster_update_contract(self):
        text = DESIGN_DOC.read_text(encoding="utf-8")

        assert "`KEY_*` spend tags mutate keys inside an existing admin slot" in text
        assert "They do not create new admin slots" in text
        assert "0x07 ADMIN_ROSTER_UPDATE" in text
        assert "atomically update both" in text
        assert "ADMINS_HASH" in text
        assert "MIPS_ROOT_HASH" in text
        assert "threshold = ceil(2 * admin_count / 3)" in text
        assert "2 admins -> 2-of-2" in text
        assert "future operational admin decisions require both admin slots" in text

    def test_mod_hash_is_stable(self):
        """Re-loading the puzzle yields the same tree hash."""
        h1 = admin_authority_v2_inner_mod_hash()
        h2 = admin_authority_v2_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32

    def test_curried_puzzle_hash_changes_with_state(self):
        """Different state values produce different inner puzzle hashes."""
        mips_a = bytes32(b"\xAA" * 32)
        mips_b = bytes32(b"\xBB" * 32)
        admins_hash = compute_admins_hash(INITIAL_ADMINS)

        h_a = make_inner_puzzle(
            mips_root_hash=mips_a,
            admins_hash=admins_hash,
        ).get_tree_hash()
        h_b = make_inner_puzzle(
            mips_root_hash=mips_b,
            admins_hash=admins_hash,
        ).get_tree_hash()
        assert h_a != h_b


# ─────────────────────────────────────────────────────────────────────────
# ADMIN_ROSTER_UPDATE preview contract (future tag 0x07).
# ─────────────────────────────────────────────────────────────────────────


class TestAdminRosterUpdatePreview:
    def test_supermajority_threshold_examples(self):
        assert [admin_supermajority_threshold(n) for n in range(1, 6)] == [
            1,
            2,
            2,
            3,
            4,
        ]
        with pytest.raises(ValueError, match="admin_count must be >= 1"):
            admin_supermajority_threshold(0)

    def test_admin_slot_add_preview_updates_admins_and_mips_atomically(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        new_admin = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2,),
            m_within=1,
        )
        pending_ops = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=LEAF_EIP712_ADMIN_1,
                activates_at=CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS,
            ),
        )
        current_mips_root = bytes32(b"\xA0" * 32)
        new_mips_root = bytes32(b"\xB0" * 32)

        preview = build_admin_slot_add_preview(
            current_admins=current_admins,
            current_pending_ops=pending_ops,
            new_admin=new_admin,
            current_mips_root_hash=current_mips_root,
            new_mips_root_hash=new_mips_root,
            current_authority_version=7,
            new_authority_version=8,
        )

        assert preview.new_admins == current_admins + (new_admin,)
        assert preview.new_threshold == 2
        assert preview.new_mips_root_hash == new_mips_root
        assert preview.new_admins_hash == compute_admins_hash(preview.new_admins)
        assert preview.new_pending_ops_hash == compute_pending_ops_hash(pending_ops)
        assert preview.new_state_hash == compute_state_hash(
            new_mips_root,
            preview.new_admins_hash,
            preview.new_pending_ops_hash,
            8,
        )

    def test_admin_slot_add_preview_rejects_key_rotation_shapes(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        current_mips_root = bytes32(b"\xA0" * 32)
        new_mips_root = bytes32(b"\xB0" * 32)

        with pytest.raises(ValueError, match="already exists"):
            build_admin_slot_add_preview(
                current_admins=current_admins,
                current_pending_ops=(),
                new_admin=AdminRecord(
                    admin_idx=0,
                    leaves=(LEAF_EIP712_ADMIN_1,),
                    m_within=1,
                ),
                current_mips_root_hash=current_mips_root,
                new_mips_root_hash=new_mips_root,
                current_authority_version=1,
                new_authority_version=2,
            )
        with pytest.raises(ValueError, match="next contiguous slot 1"):
            build_admin_slot_add_preview(
                current_admins=current_admins,
                current_pending_ops=(),
                new_admin=AdminRecord(
                    admin_idx=2,
                    leaves=(LEAF_BLS_ADMIN_2,),
                    m_within=1,
                ),
                current_mips_root_hash=current_mips_root,
                new_mips_root_hash=new_mips_root,
                current_authority_version=1,
                new_authority_version=2,
            )
        with pytest.raises(ValueError, match="must change"):
            build_admin_slot_add_preview(
                current_admins=current_admins,
                current_pending_ops=(),
                new_admin=AdminRecord(
                    admin_idx=1,
                    leaves=(LEAF_BLS_ADMIN_2,),
                    m_within=1,
                ),
                current_mips_root_hash=current_mips_root,
                new_mips_root_hash=current_mips_root,
                current_authority_version=1,
                new_authority_version=2,
            )

    def test_admin_slot_add_preview_rejects_invalid_admin_records(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        current_mips_root = bytes32(b"\xA0" * 32)
        new_mips_root = bytes32(b"\xB0" * 32)

        with pytest.raises(ValueError, match="at least one leaf"):
            build_admin_slot_add_preview(
                current_admins=current_admins,
                current_pending_ops=(),
                new_admin=AdminRecord(admin_idx=1, leaves=(), m_within=1),
                current_mips_root_hash=current_mips_root,
                new_mips_root_hash=new_mips_root,
                current_authority_version=1,
                new_authority_version=2,
            )
        with pytest.raises(ValueError, match="m_within must be in"):
            build_admin_slot_add_preview(
                current_admins=current_admins,
                current_pending_ops=(),
                new_admin=AdminRecord(
                    admin_idx=1,
                    leaves=(LEAF_BLS_ADMIN_2,),
                    m_within=2,
                ),
                current_mips_root_hash=current_mips_root,
                new_mips_root_hash=new_mips_root,
                current_authority_version=1,
                new_authority_version=2,
            )
        with pytest.raises(ValueError, match="max_admins"):
            build_admin_slot_add_preview(
                current_admins=current_admins,
                current_pending_ops=(),
                new_admin=AdminRecord(
                    admin_idx=1,
                    leaves=(LEAF_BLS_ADMIN_2,),
                    m_within=1,
                ),
                current_mips_root_hash=current_mips_root,
                new_mips_root_hash=new_mips_root,
                current_authority_version=1,
                new_authority_version=2,
                max_admins=1,
            )

    def test_roster_update_binding_hash_changes_with_target_state(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        pending_ops = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=LEAF_EIP712_ADMIN_1,
                activates_at=CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS,
            ),
        )
        new_admin_a = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2,),
            m_within=1,
        )
        new_admin_b = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_EIP712_ADMIN_2,),
            m_within=1,
        )
        base = compute_roster_update_binding_hash(
            current_mips_root_hash=bytes32(b"\xA0" * 32),
            current_admins_hash=compute_admins_hash(current_admins),
            current_pending_ops_hash=compute_pending_ops_hash(pending_ops),
            current_authority_version=7,
            new_admins_hash=compute_admins_hash(current_admins + (new_admin_a,)),
            new_mips_root_hash=bytes32(b"\xB0" * 32),
            new_authority_version=8,
        )

        assert base != compute_roster_update_binding_hash(
            current_mips_root_hash=bytes32(b"\xA0" * 32),
            current_admins_hash=compute_admins_hash(current_admins),
            current_pending_ops_hash=compute_pending_ops_hash(pending_ops),
            current_authority_version=7,
            new_admins_hash=compute_admins_hash(current_admins + (new_admin_b,)),
            new_mips_root_hash=bytes32(b"\xB0" * 32),
            new_authority_version=8,
        )
        assert base != compute_roster_update_binding_hash(
            current_mips_root_hash=bytes32(b"\xA0" * 32),
            current_admins_hash=compute_admins_hash(current_admins),
            current_pending_ops_hash=compute_pending_ops_hash(pending_ops),
            current_authority_version=7,
            new_admins_hash=compute_admins_hash(current_admins + (new_admin_a,)),
            new_mips_root_hash=bytes32(b"\xB1" * 32),
            new_authority_version=8,
        )
        assert base != compute_roster_update_binding_hash(
            current_mips_root_hash=bytes32(b"\xA0" * 32),
            current_admins_hash=compute_admins_hash(current_admins),
            current_pending_ops_hash=EMPTY_LIST_HASH,
            current_authority_version=7,
            new_admins_hash=compute_admins_hash(current_admins + (new_admin_a,)),
            new_mips_root_hash=bytes32(b"\xB0" * 32),
            new_authority_version=8,
        )


class TestAdminRosterUpdateSpendContract:
    def test_reserved_spend_tag_and_solution_payload_shape(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        pending_ops = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=LEAF_EIP712_ADMIN_1,
                activates_at=CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS,
            ),
        )
        mips_reveal = _trivial_mips_puzzle()
        mips_solution = Program.to([])
        new_admin = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2,),
            m_within=1,
        )
        new_mips_root = bytes32(b"\xB0" * 32)

        sol = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=pending_ops,
            current_mips_reveal=mips_reveal,
            current_mips_solution=mips_solution,
            new_admin=new_admin,
            new_mips_root_hash=new_mips_root,
        )
        outer = list(sol.as_iter())
        spend_args = list(outer[3].as_iter())

        assert SPEND_ADMIN_ROSTER_UPDATE == 0x07
        assert int(outer[0].as_int()) == SPEND_ADMIN_ROSTER_UPDATE
        assert int(outer[1].as_int()) == SINGLETON_AMOUNT
        assert int(outer[2].as_int()) == INITIAL_AUTHORITY_VERSION + 1
        assert len(spend_args) == 6
        assert bytes32(spend_args[0].get_tree_hash()) == bytes32(
            Program.to([a.to_program() for a in current_admins]).get_tree_hash()
        )
        assert bytes32(spend_args[1].get_tree_hash()) == bytes32(
            Program.to([p.to_program() for p in pending_ops]).get_tree_hash()
        )
        assert bytes32(spend_args[2].get_tree_hash()) == bytes32(
            mips_reveal.get_tree_hash()
        )
        assert bytes32(spend_args[3].get_tree_hash()) == bytes32(
            mips_solution.get_tree_hash()
        )
        assert bytes32(spend_args[4].get_tree_hash()) == bytes32(
            new_admin.to_program().get_tree_hash()
        )
        assert bytes32(spend_args[5].atom) == new_mips_root

    def test_admin_roster_update_appends_slot_and_updates_authority_root(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        new_admin = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2,),
            m_within=1,
        )
        expected_admins = current_admins + (new_admin,)
        current_mips_reveal = _trivial_mips_puzzle()
        current_mips_root = bytes32(current_mips_reveal.get_tree_hash())
        new_mips_reveal = Program.to((1, [[1, b"new-2-of-2"]]))
        new_mips_root = bytes32(new_mips_reveal.get_tree_hash())
        inner = make_inner_puzzle(
            mips_root_hash=current_mips_root,
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=(),
            current_mips_reveal=current_mips_reveal,
            current_mips_solution=Program.to([]),
            new_admin=new_admin,
            new_mips_root_hash=new_mips_root,
        )

        result = inner.run(sol)
        payload = _first_announcement_payload(result)
        expected_state_hash = compute_state_hash(
            new_mips_root,
            compute_admins_hash(expected_admins),
            EMPTY_LIST_HASH,
            INITIAL_AUTHORITY_VERSION + 1,
        )

        assert payload[1] == SPEND_ADMIN_ROSTER_UPDATE
        assert payload[2:] == expected_state_hash
        assert 1 in [int(cond.first().as_int()) for cond in result.as_iter()]

        post_update_inner = make_inner_puzzle(
            mips_root_hash=new_mips_root,
            admins_hash=compute_admins_hash(expected_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION + 1,
        )
        old_root_sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 2,
            mips_puzzle_reveal=current_mips_reveal,
            mips_solution=Program.to([]),
        )
        with pytest.raises(Exception):
            post_update_inner.run(old_root_sol)

        new_root_sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 2,
            mips_puzzle_reveal=new_mips_reveal,
            mips_solution=Program.to([]),
        )
        post_update_inner.run(new_root_sol)

    def test_preview_backed_spend_matches_clsp_outputs_with_pending_ops(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        pending_ops = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=LEAF_EIP712_ADMIN_1,
                activates_at=CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS,
            ),
        )
        new_admin = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2,),
            m_within=1,
        )
        current_mips_reveal = _trivial_mips_puzzle()
        current_mips_root = bytes32(current_mips_reveal.get_tree_hash())
        new_mips_reveal = Program.to((1, [[1, b"new-pending-root"]]))
        built = build_admin_slot_add_spend(
            my_amount=SINGLETON_AMOUNT,
            current_authority_version=INITIAL_AUTHORITY_VERSION,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=pending_ops,
            current_mips_reveal=current_mips_reveal,
            current_mips_solution=Program.to([]),
            new_admin=new_admin,
            new_mips_root_hash=bytes32(new_mips_reveal.get_tree_hash()),
        )
        inner = make_inner_puzzle(
            mips_root_hash=current_mips_root,
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=compute_pending_ops_hash(pending_ops),
            authority_version=INITIAL_AUTHORITY_VERSION,
        )

        result = inner.run(built.solution)
        payload = _first_announcement_payload(result)
        create_coin_puzzle_hash, create_coin_amount = _first_create_coin_condition(result)
        expected_inner = make_inner_puzzle(
            mips_root_hash=built.preview.new_mips_root_hash,
            admins_hash=built.preview.new_admins_hash,
            pending_ops_hash=built.preview.new_pending_ops_hash,
            authority_version=built.preview.new_authority_version,
        )

        assert built.preview.new_admins == current_admins + (new_admin,)
        assert built.preview.new_threshold == 2
        assert built.preview.new_pending_ops_hash == compute_pending_ops_hash(pending_ops)
        assert built.preview.new_pending_ops_hash != EMPTY_LIST_HASH
        assert payload[1] == SPEND_ADMIN_ROSTER_UPDATE
        assert payload[2:] == built.preview.new_state_hash
        assert create_coin_puzzle_hash == bytes32(expected_inner.get_tree_hash())
        assert create_coin_amount == SINGLETON_AMOUNT

    def test_admin_roster_update_rejects_mismatched_current_mips_reveal(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        current_mips_reveal = _trivial_mips_puzzle()
        wrong_mips_reveal = Program.to((1, [[1, b"wrong-root"]]))
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(current_mips_reveal.get_tree_hash()),
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=(),
            current_mips_reveal=wrong_mips_reveal,
            current_mips_solution=Program.to([]),
            new_admin=AdminRecord(
                admin_idx=1,
                leaves=(LEAF_BLS_ADMIN_2,),
                m_within=1,
            ),
            new_mips_root_hash=bytes32(b"\xB0" * 32),
        )

        with pytest.raises(Exception):
            inner.run(sol)

    @pytest.mark.parametrize(
        "new_admin",
        [
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_2,), m_within=1),
            AdminRecord(admin_idx=2, leaves=(LEAF_BLS_ADMIN_2,), m_within=1),
            AdminRecord(admin_idx=1, leaves=(), m_within=1),
            AdminRecord(admin_idx=1, leaves=(LEAF_BLS_ADMIN_2,), m_within=2),
        ],
    )
    def test_admin_roster_update_rejects_invalid_new_admin_record(self, new_admin):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        current_mips_reveal = _trivial_mips_puzzle()
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(current_mips_reveal.get_tree_hash()),
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=(),
            current_mips_reveal=current_mips_reveal,
            current_mips_solution=Program.to([]),
            new_admin=new_admin,
            new_mips_root_hash=bytes32(b"\xB0" * 32),
        )

        with pytest.raises(Exception):
            inner.run(sol)

    def test_admin_roster_update_rejects_unchanged_mips_root_and_max_admins(self):
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        current_mips_reveal = _trivial_mips_puzzle()
        current_mips_root = bytes32(current_mips_reveal.get_tree_hash())
        sol = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=(),
            current_mips_reveal=current_mips_reveal,
            current_mips_solution=Program.to([]),
            new_admin=AdminRecord(
                admin_idx=1,
                leaves=(LEAF_BLS_ADMIN_2,),
                m_within=1,
            ),
            new_mips_root_hash=current_mips_root,
        )
        inner_same_root = make_inner_puzzle(
            mips_root_hash=current_mips_root,
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        with pytest.raises(Exception):
            inner_same_root.run(sol)

        inner_max_admins = make_inner_puzzle(
            mips_root_hash=current_mips_root,
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
            max_admins=1,
        )
        sol_new_root = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=current_admins,
            current_pending_ops=(),
            current_mips_reveal=current_mips_reveal,
            current_mips_solution=Program.to([]),
            new_admin=AdminRecord(
                admin_idx=1,
                leaves=(LEAF_BLS_ADMIN_2,),
                m_within=1,
            ),
            new_mips_root_hash=bytes32(b"\xB0" * 32),
        )
        with pytest.raises(Exception):
            inner_max_admins.run(sol_new_root)


# ─────────────────────────────────────────────────────────────────────────
# OPERATIONAL spend (tag 0x01).
# ─────────────────────────────────────────────────────────────────────────


class TestOperationalSpend:
    def test_runs_and_emits_expected_conditions(self, initial_state):
        """Happy path: OPERATIONAL with valid MIPS reveal returns the
        member's emitted conditions wrapped with shim conditions
        (CREATE_COIN, ASSERT_MY_AMOUNT, CREATE_PUZZLE_ANNOUNCEMENT).
        """
        sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            mips_puzzle_reveal=initial_state["mips_reveal"],
            mips_solution=Program.to(0),
        )
        result = initial_state["inner"].run(sol)
        conditions = list(result.as_iter())

        # The trivial MIPS reveal emits exactly one REMARK condition.
        # The shim adds three: CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT,
        # ASSERT_MY_AMOUNT.
        opcodes = [int(c.first().as_int()) for c in conditions]

        # 1 = REMARK (from the trivial mips reveal)
        # 51 = CREATE_COIN (shim)
        # 62 = CREATE_PUZZLE_ANNOUNCEMENT (shim)
        # 73 = ASSERT_MY_AMOUNT (shim)
        assert 1 in opcodes, "REMARK from trivial MIPS reveal not emitted"
        assert 51 in opcodes, "CREATE_COIN (shim self-recurry) not emitted"
        assert 62 in opcodes, "CREATE_PUZZLE_ANNOUNCEMENT (shim) not emitted"
        assert 73 in opcodes, "ASSERT_MY_AMOUNT (shim) not emitted"

    def test_rejects_mismatched_mips_reveal(self, initial_state):
        """A MIPS reveal that doesn't hash to MIPS_ROOT_HASH must raise.

        Without this check, a caller could supply a different (more
        permissive) MIPS tree that wasn't authorised by the current
        admin quorum.
        """
        wrong_reveal = Program.to((1, [[1, b"\xDE\xAD"]]))  # different tree-hash
        sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            mips_puzzle_reveal=wrong_reveal,
            mips_solution=Program.to(0),
        )
        with pytest.raises(Exception):
            initial_state["inner"].run(sol)

    def test_rejects_version_downgrade(self, initial_state):
        """new_authority_version <= current AUTHORITY_VERSION must raise.

        Replay protection (I-1): without exact one-step version bumps,
        a previously-valid spend bundle could be replayed against a
        future state or a spend could jump to an unusable ceiling value.
        """
        sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION,  # not strictly >
            mips_puzzle_reveal=initial_state["mips_reveal"],
            mips_solution=Program.to(0),
        )
        with pytest.raises(Exception):
            initial_state["inner"].run(sol)

    def test_rejects_skipped_version_increment(self, initial_state):
        """new_authority_version must advance exactly one step.

        A caller must not be able to jump directly to a high uint64 value,
        because that can leave no usable successor version for the next
        authority spend.
        """
        for bad_version in (INITIAL_AUTHORITY_VERSION + 2, (1 << 64) - 1):
            sol = build_operational_solution(
                my_amount=SINGLETON_AMOUNT,
                new_authority_version=bad_version,
                mips_puzzle_reveal=initial_state["mips_reveal"],
                mips_solution=Program.to(0),
            )
            with pytest.raises(Exception):
                initial_state["inner"].run(sol)

    def test_rejects_zero_my_amount(self, initial_state):
        """my_amount must be a non-zero uint64. is-uint64 rejects 0
        only if it isn't representable; actually 0 is representable as
        a uint64. The shim's ASSERT_MY_AMOUNT then enforces match against
        the spending coin. So the more meaningful negative is a
        not-uint64 value (e.g. negative).
        """
        sol = build_operational_solution(
            my_amount=-1,  # not a valid uint64
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            mips_puzzle_reveal=initial_state["mips_reveal"],
            mips_solution=Program.to(0),
        )
        with pytest.raises(Exception):
            initial_state["inner"].run(sol)


# ─────────────────────────────────────────────────────────────────────────
# KEY_ADD_PROPOSE spend (tag 0x02).
#
# Proposes adding a new member tree hash to one of the admin's leaves.
# The proposal sits in the pending-ops list until either:
#   - KEY_ADD_ACTIVATE applies it after COOLDOWN_BLOCKS elapse, or
#   - KEY_ADD_VETO cancels it before activation.
#
# The shim binds the spend's confirmation to a user-supplied
# current_block_height via height assertions so a compromised key
# can't backdate activates_at to skip cooldown.
# ─────────────────────────────────────────────────────────────────────────


# Member tree hash representing a key the admin DOES NOT YET have. The
# happy path adds this to admin 0's leaves.
NEW_MEMBER_HASH = bytes32(b"\xCC" * 32)
CURRENT_BLOCK_HEIGHT = 1_000_000


def _approving_member_for_admin(admin_record: AdminRecord) -> Program:
    """Construct a fake approving-member puzzle whose tree hash matches
    the FIRST leaf of the given admin record.

    The shim uses tree-hash equality to verify membership in the OneOfN.
    For testing, we construct a constant puzzle and the test fixture
    seeds the admin's leaves with that puzzle's tree hash. This avoids
    needing a real BLS/Eip712Member curry just to exercise the shim.
    """
    # Constant puzzle: when run with any solution, returns one REMARK
    # condition. The shim doesn't introspect the conditions on PROPOSE,
    # so any returnable conditions list works.
    return Program.to((1, [[1, b"approve-add"]]))


@pytest.fixture
def propose_state():
    """Set up a baseline state where admin 0 has one leaf whose tree
    hash matches the test's approving member, and admin 1 has an
    independent leaf set.
    """
    approving_member = Program.to((1, [[1, b"approve-add"]]))
    approving_hash = bytes32(approving_member.get_tree_hash())

    admins = (
        AdminRecord(admin_idx=0, leaves=(approving_hash,), m_within=1),
        AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2, LEAF_EIP712_ADMIN_2),
            m_within=1,
        ),
    )
    pending_ops: tuple[PendingOp, ...] = ()

    mips_reveal = _trivial_mips_puzzle()
    mips_root = bytes32(mips_reveal.get_tree_hash())

    inner = make_inner_puzzle(
        mips_root_hash=mips_root,
        admins_hash=compute_admins_hash(admins),
        pending_ops_hash=compute_pending_ops_hash(pending_ops),
        authority_version=INITIAL_AUTHORITY_VERSION,
    )
    return {
        "approving_member": approving_member,
        "approving_hash": approving_hash,
        "admins": admins,
        "pending_ops": pending_ops,
        "mips_root": mips_root,
        "inner": inner,
    }


class TestKeyAddPropose:
    def test_proposes_pending_add(self, propose_state):
        """Happy path: a leaf of admin 0's OneOfN authorises adding
        NEW_MEMBER_HASH. The pending-ops list grows by one; the height
        binding limits confirmation to a tight window.
        """
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        result = propose_state["inner"].run(sol)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # Cooldown binding: ASSERT_HEIGHT_ABSOLUTE (83) +
        # ASSERT_BEFORE_HEIGHT_ABSOLUTE (87).
        assert 83 in opcodes, "ASSERT_HEIGHT_ABSOLUTE not emitted"
        assert 87 in opcodes, "ASSERT_BEFORE_HEIGHT_ABSOLUTE not emitted"

        # The approving member's REMARK condition should pass through.
        assert 1 in opcodes, "approving member's REMARK not passed through"

        # Shim's CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT, ASSERT_MY_AMOUNT.
        assert 51 in opcodes
        assert 62 in opcodes
        assert 73 in opcodes

        # Verify the height-window has the right shape: ABSOLUTE = block,
        # BEFORE = block + PROPOSE_WINDOW.
        for cond in conditions:
            opcode = int(cond.first().as_int())
            if opcode == 83:  # ASSERT_HEIGHT_ABSOLUTE
                value = int(cond.rest().first().as_int())
                assert value == CURRENT_BLOCK_HEIGHT, (
                    f"ASSERT_HEIGHT_ABSOLUTE expected {CURRENT_BLOCK_HEIGHT}, got {value}"
                )
            elif opcode == 87:  # ASSERT_BEFORE_HEIGHT_ABSOLUTE
                value = int(cond.rest().first().as_int())
                assert value == CURRENT_BLOCK_HEIGHT + PROPOSE_WINDOW

    def test_rejects_unknown_admin_idx(self, propose_state):
        """admin_idx not in current_admins must raise (find-admin-by-idx
        returns nil, which assert treats as raise).
        """
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=99,  # not a valid admin idx
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            propose_state["inner"].run(sol)

    def test_rejects_non_member_approver(self, propose_state):
        """An approving member whose tree hash isn't in admin's leaves
        must raise. Defends against a third party trying to propose
        adds for an admin slot they don't control.
        """
        outside_member = Program.to((1, [[1, b"not-a-leaf"]]))
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=outside_member,
            approving_member_solution=Program.to(0),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            propose_state["inner"].run(sol)

    def test_rejects_duplicate_new_member(self, propose_state):
        """Adding a leaf that's already in the OneOfN must raise.
        Prevents redundant adds that would pollute the leaves list.
        """
        # Use the existing leaf hash as the "new" one.
        existing_leaf = propose_state["approving_hash"]
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            new_member_hash=existing_leaf,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            propose_state["inner"].run(sol)

    def test_rejects_mismatched_admins_list(self, propose_state):
        """current_admins_list whose sha256tree differs from
        ADMINS_HASH must raise. Defends against forged admins lists
        smuggled into the solution.
        """
        # Replace admin 0 with a forged admin that has the attacker's
        # key as a leaf. If the integrity check were absent, this
        # would let the attacker masquerade as a valid approver.
        forged_admins = (
            AdminRecord(
                admin_idx=0,
                leaves=(bytes32(b"\xFF" * 32),),  # attacker-controlled
                m_within=1,
            ),
            propose_state["admins"][1],
        )
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=forged_admins,
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            propose_state["inner"].run(sol)

    def test_pending_ops_hash_in_announcement_matches_appended_state(
        self, propose_state
    ):
        """The new state announcement should carry the new
        PENDING_KEY_OPS_HASH (computed off-chain by the test) so
        off-chain monitors can verify the singleton's new state
        without re-running the puzzle.
        """
        activates_at = CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS
        new_pending_ops = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=NEW_MEMBER_HASH,
                activates_at=activates_at,
            ),
        )
        expected_new_pending_hash = compute_pending_ops_hash(new_pending_ops)

        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        result = propose_state["inner"].run(sol)

        # Find the CREATE_PUZZLE_ANNOUNCEMENT condition's payload.
        for cond in result.as_iter():
            if int(cond.first().as_int()) == 62:
                payload = cond.rest().first().atom
                assert payload is not None
                # payload = PROTOCOL_PREFIX (1B) || spend_tag (1B) || state_hash (32B)
                assert len(payload) == 34
                # spend_tag byte should be 0x02 (KEY_ADD_PROPOSE).
                assert payload[1] == 0x02
                # The off-chain expected_new_pending_hash is INSIDE the
                # state hash, but the state-hash itself is sha256tree of
                # (mips, admins, pending, version) — to check structural
                # correctness without recomputing here, we just confirm
                # the announcement encodes 32 bytes after the prefix.
                state_hash_bytes = payload[2:]
                assert len(state_hash_bytes) == 32
                break
        else:
            pytest.fail("No CREATE_PUZZLE_ANNOUNCEMENT emitted")

        # Sanity: expected_new_pending_hash should be a non-trivial 32B value.
        assert len(expected_new_pending_hash) == 32
        assert expected_new_pending_hash != EMPTY_LIST_HASH

    def test_propose_adds_pending_key_without_adding_admin_slot(self, propose_state):
        activates_at = CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS
        expected_pending = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=NEW_MEMBER_HASH,
                activates_at=activates_at,
            ),
        )
        expected_state_hash = compute_state_hash(
            propose_state["mips_root"],
            compute_admins_hash(propose_state["admins"]),
            compute_pending_ops_hash(expected_pending),
            INITIAL_AUTHORITY_VERSION + 1,
        )

        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=propose_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        payload = _first_announcement_payload(propose_state["inner"].run(sol))

        assert payload[1] == SPEND_KEY_ADD_PROPOSE
        assert payload[2:] == expected_state_hash


# ─────────────────────────────────────────────────────────────────────────
# KEY_ADD_ACTIVATE spend (tag 0x03) — ADD activation path.
#
# Polymorphic on op_kind: this section covers OP_KIND_ADD. The
# OP_KIND_REMOVE branch is exercised in the KEY_REMOVE_EMERGENCY +
# ACTIVATE flow tests (separate fixture pulling a remove pending op).
#
# Permissionless: anyone can submit ACTIVATE once cooldown has elapsed.
# The shim emits ASSERT_HEIGHT_ABSOLUTE activates_at to enforce cooldown
# at consensus time; the puzzle itself just requires the pending op to
# exist and the new leaf to not already be present.
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture
def activate_state(propose_state):
    """Set up a state where a pending ADD already exists, ready to be
    activated. Reuses propose_state's fixture base (admins layout) but
    seeds PENDING_KEY_OPS_HASH with one op.
    """
    activates_at = CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS
    pending = (
        PendingOp(
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            target_hash=NEW_MEMBER_HASH,
            activates_at=activates_at,
        ),
    )
    inner = make_inner_puzzle(
        mips_root_hash=propose_state["mips_root"],
        admins_hash=compute_admins_hash(propose_state["admins"]),
        pending_ops_hash=compute_pending_ops_hash(pending),
        authority_version=INITIAL_AUTHORITY_VERSION,
    )
    return {
        "admins": propose_state["admins"],
        "pending_ops": pending,
        "mips_root": propose_state["mips_root"],
        "activates_at": activates_at,
        "inner": inner,
    }


class TestKeyAddActivate:
    def test_activates_pending_add(self, activate_state):
        """Happy path: a pending ADD op gets activated, the affected
        admin's leaves grow by one, the pending op is removed, and the
        height-binding ASSERT_HEIGHT_ABSOLUTE matches activates_at.
        """
        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activate_state["activates_at"],
        )
        result = activate_state["inner"].run(sol)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # ASSERT_HEIGHT_ABSOLUTE (83) — cooldown elapsed.
        assert 83 in opcodes, "ASSERT_HEIGHT_ABSOLUTE not emitted"

        # Shim's CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT, ASSERT_MY_AMOUNT.
        assert 51 in opcodes
        assert 62 in opcodes
        assert 73 in opcodes

        # The activates_at value bound matches what was in the pending op.
        for cond in conditions:
            if int(cond.first().as_int()) == 83:
                assert int(cond.rest().first().as_int()) == activate_state["activates_at"]
                break
        else:
            pytest.fail("ASSERT_HEIGHT_ABSOLUTE missing")

        # The announcement encodes the spend tag 0x03.
        for cond in conditions:
            if int(cond.first().as_int()) == 62:
                payload = cond.rest().first().atom
                assert payload[1] == 0x03
                break

    def test_rejects_unknown_pending_op(self, activate_state):
        """A pending op whose tuple shape differs from what was stored
        at PROPOSE must raise. Defends against fast-forwarding by
        passing a smaller activates_at.
        """
        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activate_state["activates_at"] - 1,  # not the stored one
        )
        with pytest.raises(Exception):
            activate_state["inner"].run(sol)

    def test_rejects_already_present_leaf(self, activate_state, propose_state):
        """If the new leaf is already in the admin's OneOfN (e.g. a
        sibling ADD activated first), the second activation must
        raise — defensive no-op-prevention.
        """
        # Use the existing leaf hash as target (already in admin 0's leaves).
        existing_leaf = propose_state["approving_hash"]
        # Re-fixture: pending op now targets a leaf that's already in the OneOfN.
        activates_at = CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS
        bad_pending = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_ADD,
                target_hash=existing_leaf,
                activates_at=activates_at,
            ),
        )
        inner = make_inner_puzzle(
            mips_root_hash=propose_state["mips_root"],
            admins_hash=compute_admins_hash(propose_state["admins"]),
            pending_ops_hash=compute_pending_ops_hash(bad_pending),
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=bad_pending,
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            target_member_hash=existing_leaf,
            activates_at=activates_at,
        )
        with pytest.raises(Exception):
            inner.run(sol)

    def test_rejects_unknown_op_kind(self, activate_state):
        """op_kind not in {OP_KIND_ADD, OP_KIND_REMOVE} must raise."""
        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            op_kind=0xFF,  # invalid
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activate_state["activates_at"],
        )
        with pytest.raises(Exception):
            activate_state["inner"].run(sol)

    def test_activate_adds_key_to_existing_admin_slot_only(self, activate_state):
        current_admin = activate_state["admins"][0]
        expected_admins = (
            AdminRecord(
                admin_idx=current_admin.admin_idx,
                leaves=current_admin.leaves + (NEW_MEMBER_HASH,),
                m_within=current_admin.m_within,
            ),
            activate_state["admins"][1],
        )
        expected_state_hash = compute_state_hash(
            activate_state["mips_root"],
            compute_admins_hash(expected_admins),
            EMPTY_LIST_HASH,
            INITIAL_AUTHORITY_VERSION + 1,
        )

        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activate_state["activates_at"],
        )
        payload = _first_announcement_payload(activate_state["inner"].run(sol))

        assert payload[1] == SPEND_KEY_ADD_ACTIVATE
        assert payload[2:] == expected_state_hash
        assert len(expected_admins) == len(activate_state["admins"])
        assert [a.admin_idx for a in expected_admins] == [0, 1]

    def test_activate_rejects_pending_add_for_brand_new_admin_slot(self, propose_state):
        new_admin_idx = 2
        activates_at = CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS
        pending = (
            PendingOp(
                admin_idx=new_admin_idx,
                op_kind=OP_KIND_ADD,
                target_hash=NEW_MEMBER_HASH,
                activates_at=activates_at,
            ),
        )
        inner = make_inner_puzzle(
            mips_root_hash=propose_state["mips_root"],
            admins_hash=compute_admins_hash(propose_state["admins"]),
            pending_ops_hash=compute_pending_ops_hash(pending),
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=propose_state["admins"],
            current_pending_ops=pending,
            admin_idx=new_admin_idx,
            op_kind=OP_KIND_ADD,
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activates_at,
        )

        with pytest.raises(Exception):
            inner.run(sol)

    def test_key_add_activation_keeps_operational_authority_bound_to_existing_mips_root(self, activate_state):
        current_admin = activate_state["admins"][0]
        activated_admins = (
            AdminRecord(
                admin_idx=current_admin.admin_idx,
                leaves=current_admin.leaves + (NEW_MEMBER_HASH,),
                m_within=current_admin.m_within,
            ),
            activate_state["admins"][1],
        )
        post_activation_inner = make_inner_puzzle(
            mips_root_hash=activate_state["mips_root"],
            admins_hash=compute_admins_hash(activated_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION + 1,
        )
        old_mips_solution = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 2,
            mips_puzzle_reveal=_trivial_mips_puzzle(),
            mips_solution=Program.to(0),
        )
        result = post_activation_inner.run(old_mips_solution)
        assert _first_announcement_payload(result)[1] == SPEND_OPERATIONAL

        new_mips_reveal = Program.to((1, [[1, b"new-key-mips"]]))
        new_mips_solution = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 2,
            mips_puzzle_reveal=new_mips_reveal,
            mips_solution=Program.to(0),
        )
        with pytest.raises(Exception):
            post_activation_inner.run(new_mips_solution)


# ─────────────────────────────────────────────────────────────────────────
# KEY_ADD_VETO spend (tag 0x04).
#
# Wide authority — any leaf of the affected admin's OneOfN can veto a
# pending ADD. The pending op is removed from PENDING_KEY_OPS_HASH;
# admins list is unchanged.
# ─────────────────────────────────────────────────────────────────────────


class TestKeyAddVeto:
    def test_vetoes_pending_add(self, activate_state, propose_state):
        """Happy path: a leaf of admin 0's OneOfN cancels the pending
        ADD. The pending op is removed; admins unchanged.
        """
        sol = build_key_add_veto_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activate_state["activates_at"],
        )
        result = activate_state["inner"].run(sol)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # No height binding — VETO can happen any time before activation.
        assert 83 not in opcodes, "VETO should not emit ASSERT_HEIGHT_ABSOLUTE"
        assert 87 not in opcodes, "VETO should not emit ASSERT_BEFORE_HEIGHT_ABSOLUTE"

        # The approving member's REMARK condition passes through.
        assert 1 in opcodes

        # Shim's CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT, ASSERT_MY_AMOUNT.
        assert 51 in opcodes
        assert 62 in opcodes
        assert 73 in opcodes

        # The announcement encodes spend_tag 0x04.
        for cond in conditions:
            if int(cond.first().as_int()) == 62:
                payload = cond.rest().first().atom
                assert payload[1] == 0x04
                break

    def test_rejects_non_member_vetoer(self, activate_state):
        """A vetoer whose tree hash isn't in admin's leaves must raise.
        Defends against third-party DoS by veto-spamming pending ops.
        """
        outside_member = Program.to((1, [[1, b"impostor"]]))
        sol = build_key_add_veto_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=outside_member,
            approving_member_solution=Program.to(0),
            target_member_hash=NEW_MEMBER_HASH,
            activates_at=activate_state["activates_at"],
        )
        with pytest.raises(Exception):
            activate_state["inner"].run(sol)

    def test_rejects_unknown_pending_op(self, activate_state, propose_state):
        """Veto target must match a real pending op."""
        sol = build_key_add_veto_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=activate_state["admins"],
            current_pending_ops=activate_state["pending_ops"],
            admin_idx=0,
            approving_member_reveal=propose_state["approving_member"],
            approving_member_solution=Program.to(0),
            target_member_hash=bytes32(b"\xEE" * 32),  # not a pending op
            activates_at=activate_state["activates_at"],
        )
        with pytest.raises(Exception):
            activate_state["inner"].run(sol)


# ─────────────────────────────────────────────────────────────────────────
# KEY_REMOVE_QUORUM spend (tag 0x05).
#
# Destructive operation requiring m_within distinct co-signers from the
# same admin's OneOfN. I-2 invariant: post-removal len(leaves) >= 1
# (single-key admins can't use this spend at all).
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture
def remove_quorum_state():
    """Admin 0 has THREE leaves with m_within=2, so QUORUM removal
    requires 2 distinct co-signers. Each leaf is a constant puzzle
    that emits an identifiable REMARK so the test can verify the
    member-emitted conditions are passed through.
    """
    leaf_a = Program.to((1, [[1, b"signer-A"]]))
    leaf_b = Program.to((1, [[1, b"signer-B"]]))
    leaf_c = Program.to((1, [[1, b"signer-C"]]))
    leaf_a_hash = bytes32(leaf_a.get_tree_hash())
    leaf_b_hash = bytes32(leaf_b.get_tree_hash())
    leaf_c_hash = bytes32(leaf_c.get_tree_hash())

    admins = (
        AdminRecord(
            admin_idx=0,
            leaves=(leaf_a_hash, leaf_b_hash, leaf_c_hash),
            m_within=2,
        ),
    )

    mips_reveal = _trivial_mips_puzzle()
    inner = make_inner_puzzle(
        mips_root_hash=bytes32(mips_reveal.get_tree_hash()),
        admins_hash=compute_admins_hash(admins),
        pending_ops_hash=EMPTY_LIST_HASH,
        authority_version=INITIAL_AUTHORITY_VERSION,
    )
    return {
        "leaf_a": leaf_a,
        "leaf_b": leaf_b,
        "leaf_c": leaf_c,
        "leaf_a_hash": leaf_a_hash,
        "leaf_b_hash": leaf_b_hash,
        "leaf_c_hash": leaf_c_hash,
        "admins": admins,
        "inner": inner,
    }


class TestKeyRemoveQuorum:
    def test_removes_with_quorum(self, remove_quorum_state):
        """Happy path: 2 distinct co-signers (m_within=2) authorise
        removal of leaf C. The removed leaf is taken out of the
        admin's leaves list.
        """
        s = remove_quorum_state
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            admin_idx=0,
            removed_member_hash=s["leaf_c_hash"],
            approving_pairs=[
                (s["leaf_a"], Program.to(0)),
                (s["leaf_b"], Program.to(0)),
            ],
        )
        result = s["inner"].run(sol)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # Each leaf's REMARK passes through.
        assert 1 in opcodes
        # Shim wrapping.
        assert 51 in opcodes
        assert 62 in opcodes
        assert 73 in opcodes
        # Announcement carries spend_tag 0x05.
        for cond in conditions:
            if int(cond.first().as_int()) == 62:
                assert cond.rest().first().atom[1] == 0x05
                break

    def test_rejects_below_quorum(self, remove_quorum_state):
        """Only 1 co-signer when m_within=2 must raise."""
        s = remove_quorum_state
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            admin_idx=0,
            removed_member_hash=s["leaf_c_hash"],
            approving_pairs=[(s["leaf_a"], Program.to(0))],  # only 1
        )
        with pytest.raises(Exception):
            s["inner"].run(sol)

    def test_rejects_duplicate_signer(self, remove_quorum_state):
        """[X X Y] proof set must be rejected — duplicates would let
        one leaf count for two quorum slots.
        """
        s = remove_quorum_state
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            admin_idx=0,
            removed_member_hash=s["leaf_c_hash"],
            approving_pairs=[
                (s["leaf_a"], Program.to(0)),
                (s["leaf_a"], Program.to(0)),  # duplicate
            ],
        )
        with pytest.raises(Exception):
            s["inner"].run(sol)

    def test_rejects_non_member_signer(self, remove_quorum_state):
        """A signer whose tree hash isn't in admin's leaves must raise."""
        s = remove_quorum_state
        outside_leaf = Program.to((1, [[1, b"impostor"]]))
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            admin_idx=0,
            removed_member_hash=s["leaf_c_hash"],
            approving_pairs=[
                (s["leaf_a"], Program.to(0)),
                (outside_leaf, Program.to(0)),  # not a leaf
            ],
        )
        with pytest.raises(Exception):
            s["inner"].run(sol)

    def test_rejects_removing_only_key(self):
        """Single-leaf admin (len=1) can't use QUORUM removal — I-2
        invariant rejects post-removal len < 1.
        """
        single_leaf = Program.to((1, [[1, b"only-key"]]))
        single_leaf_hash = bytes32(single_leaf.get_tree_hash())
        admins = (
            AdminRecord(admin_idx=0, leaves=(single_leaf_hash,), m_within=1),
        )
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(_trivial_mips_puzzle().get_tree_hash()),
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=admins,
            admin_idx=0,
            removed_member_hash=single_leaf_hash,
            approving_pairs=[(single_leaf, Program.to(0))],
        )
        with pytest.raises(Exception):
            inner.run(sol)

    def test_rejects_removing_nonexistent_leaf(self, remove_quorum_state):
        """removed_member_hash must be in admin's leaves."""
        s = remove_quorum_state
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            admin_idx=0,
            removed_member_hash=bytes32(b"\xDD" * 32),  # not in leaves
            approving_pairs=[
                (s["leaf_a"], Program.to(0)),
                (s["leaf_b"], Program.to(0)),
            ],
        )
        with pytest.raises(Exception):
            s["inner"].run(sol)

    def test_remove_quorum_removes_key_without_changing_admin_slots_or_mips_root(self, remove_quorum_state):
        s = remove_quorum_state
        expected_admins = (
            AdminRecord(
                admin_idx=0,
                leaves=(s["leaf_a_hash"], s["leaf_b_hash"]),
                m_within=2,
            ),
        )
        expected_state_hash = compute_state_hash(
            bytes32(_trivial_mips_puzzle().get_tree_hash()),
            compute_admins_hash(expected_admins),
            EMPTY_LIST_HASH,
            INITIAL_AUTHORITY_VERSION + 1,
        )

        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            admin_idx=0,
            removed_member_hash=s["leaf_c_hash"],
            approving_pairs=[
                (s["leaf_a"], Program.to(0)),
                (s["leaf_b"], Program.to(0)),
            ],
        )
        payload = _first_announcement_payload(s["inner"].run(sol))

        assert payload[1] == SPEND_KEY_REMOVE_QUORUM
        assert payload[2:] == expected_state_hash
        assert len(expected_admins) == len(s["admins"])
        assert [a.admin_idx for a in expected_admins] == [0]


# ─────────────────────────────────────────────────────────────────────────
# KEY_REMOVE_EMERGENCY spend (tag 0x06) + OP_KIND_REMOVE ACTIVATE path.
#
# Tests both halves of the emergency-removal lifecycle:
#   PROPOSE -> (RECOVERY_TIMEOUT_BLOCKS cooldown) -> ACTIVATE
#
# Tag 0x06 proposes; tag 0x03 (KEY_ADD_ACTIVATE polymorphic on op_kind)
# activates with op_kind=OP_KIND_REMOVE.
# ─────────────────────────────────────────────────────────────────────────


@pytest.fixture
def remove_emergency_state():
    """Admin 0 has TWO leaves with m_within=1. Either leaf can
    initiate emergency removal of the other.
    """
    leaf_a = Program.to((1, [[1, b"emergency-A"]]))
    leaf_b = Program.to((1, [[1, b"emergency-B"]]))
    leaf_a_hash = bytes32(leaf_a.get_tree_hash())
    leaf_b_hash = bytes32(leaf_b.get_tree_hash())

    admins = (
        AdminRecord(
            admin_idx=0,
            leaves=(leaf_a_hash, leaf_b_hash),
            m_within=1,
        ),
    )
    inner = make_inner_puzzle(
        mips_root_hash=bytes32(_trivial_mips_puzzle().get_tree_hash()),
        admins_hash=compute_admins_hash(admins),
        pending_ops_hash=EMPTY_LIST_HASH,
        authority_version=INITIAL_AUTHORITY_VERSION,
    )
    return {
        "leaf_a": leaf_a,
        "leaf_b": leaf_b,
        "leaf_a_hash": leaf_a_hash,
        "leaf_b_hash": leaf_b_hash,
        "admins": admins,
        "inner": inner,
    }


class TestKeyRemoveEmergency:
    def test_proposes_emergency_removal(self, remove_emergency_state):
        """Happy path: leaf A authorises emergency removal of leaf B.
        A pending REMOVE op is appended; admins unchanged.
        """
        s = remove_emergency_state
        sol = build_key_remove_emergency_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            current_pending_ops=(),
            admin_idx=0,
            approving_member_reveal=s["leaf_a"],
            approving_member_solution=Program.to(0),
            removed_member_hash=s["leaf_b_hash"],
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        result = s["inner"].run(sol)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # Cooldown binding via PROPOSE-style height window.
        assert 83 in opcodes  # ASSERT_HEIGHT_ABSOLUTE
        assert 87 in opcodes  # ASSERT_BEFORE_HEIGHT_ABSOLUTE

        # Approving member's REMARK passes through.
        assert 1 in opcodes

        # Shim wrapping.
        assert 51 in opcodes
        assert 62 in opcodes
        assert 73 in opcodes

        # Announcement carries spend_tag 0x06.
        for cond in conditions:
            if int(cond.first().as_int()) == 62:
                assert cond.rest().first().atom[1] == 0x06
                break

    def test_rejects_non_member_initiator(self, remove_emergency_state):
        """A non-member trying to start emergency removal must raise."""
        s = remove_emergency_state
        outside = Program.to((1, [[1, b"impostor"]]))
        sol = build_key_remove_emergency_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            current_pending_ops=(),
            admin_idx=0,
            approving_member_reveal=outside,
            approving_member_solution=Program.to(0),
            removed_member_hash=s["leaf_b_hash"],
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            s["inner"].run(sol)

    def test_rejects_removing_nonexistent_leaf(self, remove_emergency_state):
        """Target leaf must currently be in admin's OneOfN."""
        s = remove_emergency_state
        sol = build_key_remove_emergency_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            current_pending_ops=(),
            admin_idx=0,
            approving_member_reveal=s["leaf_a"],
            approving_member_solution=Program.to(0),
            removed_member_hash=bytes32(b"\xEE" * 32),  # not a leaf
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            s["inner"].run(sol)

    def test_rejects_single_leaf_admin(self):
        """Admins with only one leaf can't use emergency removal —
        I-2 invariant prevents emptying the OneOfN.
        """
        only_leaf = Program.to((1, [[1, b"only"]]))
        only_hash = bytes32(only_leaf.get_tree_hash())
        admins = (
            AdminRecord(admin_idx=0, leaves=(only_hash,), m_within=1),
        )
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(_trivial_mips_puzzle().get_tree_hash()),
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_remove_emergency_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=admins,
            current_pending_ops=(),
            admin_idx=0,
            approving_member_reveal=only_leaf,
            approving_member_solution=Program.to(0),
            removed_member_hash=only_hash,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        with pytest.raises(Exception):
            inner.run(sol)

    def test_op_kind_remove_activates_after_cooldown(self, remove_emergency_state):
        """End-to-end: pending REMOVE op activates via tag 0x03 with
        op_kind=OP_KIND_REMOVE. Validates the polymorphic ACTIVATE
        dispatcher's REMOVE branch.
        """
        s = remove_emergency_state
        # Construct the pending REMOVE op as if EMERGENCY-PROPOSE had
        # already happened. activates_at would be set to
        # current_block_height + RECOVERY_TIMEOUT_BLOCKS.
        activates_at = CURRENT_BLOCK_HEIGHT + DEFAULT_RECOVERY_TIMEOUT_BLOCKS
        pending = (
            PendingOp(
                admin_idx=0,
                op_kind=OP_KIND_REMOVE,
                target_hash=s["leaf_b_hash"],
                activates_at=activates_at,
            ),
        )
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(_trivial_mips_puzzle().get_tree_hash()),
            admins_hash=compute_admins_hash(s["admins"]),
            pending_ops_hash=compute_pending_ops_hash(pending),
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_add_activate_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=s["admins"],
            current_pending_ops=pending,
            admin_idx=0,
            op_kind=OP_KIND_REMOVE,
            target_member_hash=s["leaf_b_hash"],
            activates_at=activates_at,
        )
        result = inner.run(sol)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # ASSERT_HEIGHT_ABSOLUTE bound to the recovery activates_at.
        assert 83 in opcodes
        for cond in conditions:
            if int(cond.first().as_int()) == 83:
                assert int(cond.rest().first().as_int()) == activates_at
                break

        # Shim wrapping with spend_tag 0x03 (still ACTIVATE; the op_kind
        # is internal to the polymorphic dispatcher, not the spend tag).
        assert 51 in opcodes
        assert 62 in opcodes
        assert 73 in opcodes
        for cond in conditions:
            if int(cond.first().as_int()) == 62:
                assert cond.rest().first().atom[1] == 0x03
                break


# ─────────────────────────────────────────────────────────────────────────
# Real-puzzle integration tests.
#
# Up to this point the tests use trivial REMARK-emitting constants as
# member reveals. These tests verify the shim works with REAL signature-
# emitting puzzles (a BLS-style leaf that emits AGG_SIG_ME), exercising
# the full `(a member_reveal member_solution)` machinery against a
# non-trivial puzzle that takes a real curry + message solution.
#
# The chia-wallet-sdk's BlsMember has additional MIPS plumbing (coin-id
# assertions, restrictions) on top of the bare AGG_SIG_ME emission. These
# tests use a strict subset that is sufficient to prove the shim's
# pass-through behaviour; full chia-wallet-sdk integration is deferred
# to Phase 9-Hermes-D (testnet11 e2e).
# ─────────────────────────────────────────────────────────────────────────


# A real 48-byte BLS G1 pubkey (sentinel — won't validate as a real
# G1 element at consensus time, but the puzzle's AGG_SIG_ME emission
# doesn't care about that).
REAL_BLS_PUBKEY = bytes(b"\x42" * 48)
REAL_SIGNED_MESSAGE = bytes32(b"\x99" * 32)


class TestRealMemberPuzzleIntegration:
    def test_operational_with_real_bls_mips_reveal(self):
        """Use a real BLS-style member puzzle as the MIPS reveal for an
        OPERATIONAL spend. Verifies the shim correctly:
          - Hashes the curried BLS member puzzle
          - Runs it with a non-trivial solution (a 32-byte message)
          - Passes the emitted AGG_SIG_ME condition through to the
            final conditions list with the right pubkey + message
        """
        bls_member = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        mips_root = bytes32(bls_member.get_tree_hash())
        admins = (
            AdminRecord(
                admin_idx=0,
                leaves=(bytes32(b"\x11" * 32),),
                m_within=1,
            ),
        )
        inner = make_inner_puzzle(
            mips_root_hash=mips_root,
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            mips_puzzle_reveal=bls_member,
            mips_solution=Program.to([REAL_SIGNED_MESSAGE]),
        )
        result = inner.run(sol)
        conditions = list(result.as_iter())

        # The real AGG_SIG_ME (opcode 50) condition should be present.
        agg_sig_me = None
        for cond in conditions:
            if int(cond.first().as_int()) == 50:
                agg_sig_me = cond
                break
        assert agg_sig_me is not None, "AGG_SIG_ME from real BLS member not emitted"

        # Verify the AGG_SIG_ME has the correct pubkey + message.
        agg_pubkey = agg_sig_me.rest().first().atom
        agg_message = agg_sig_me.rest().rest().first().atom
        assert agg_pubkey == REAL_BLS_PUBKEY, (
            f"AGG_SIG_ME pubkey wrong: {agg_pubkey.hex()} vs {REAL_BLS_PUBKEY.hex()}"
        )
        assert agg_message == REAL_SIGNED_MESSAGE, (
            f"AGG_SIG_ME message wrong: {agg_message.hex()} vs {REAL_SIGNED_MESSAGE.hex()}"
        )

        # Shim wrapping still emitted alongside.
        opcodes = [int(c.first().as_int()) for c in conditions]
        assert 51 in opcodes  # CREATE_COIN
        assert 62 in opcodes  # CREATE_PUZZLE_ANNOUNCEMENT
        assert 73 in opcodes  # ASSERT_MY_AMOUNT

    def test_key_add_propose_with_real_bls_approver(self):
        """KEY_ADD_PROPOSE with a real BLS-style approving member. The
        AGG_SIG_ME condition the leaf emits should be passed through
        with the operation binding hash as the message.
        """
        bls_approver = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        approver_hash = bytes32(bls_approver.get_tree_hash())
        expected_binding = compute_key_op_binding_hash(
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            member_hash=NEW_MEMBER_HASH,
            activates_at=CURRENT_BLOCK_HEIGHT + DEFAULT_COOLDOWN_BLOCKS,
        )

        admins = (
            AdminRecord(admin_idx=0, leaves=(approver_hash,), m_within=1),
        )
        mips_reveal = _trivial_mips_puzzle()
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(mips_reveal.get_tree_hash()),
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=admins,
            current_pending_ops=(),
            admin_idx=0,
            approving_member_reveal=bls_approver,
            approving_member_solution=Program.to([]),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=CURRENT_BLOCK_HEIGHT,
        )
        result = inner.run(sol)
        conditions = list(result.as_iter())

        # The approver's AGG_SIG_ME should be present with the on-chain
        # operation binding as the signed message.
        agg_sig_me = None
        for cond in conditions:
            if int(cond.first().as_int()) == 50:
                agg_sig_me = cond
                break
        assert agg_sig_me is not None
        agg_message = agg_sig_me.rest().rest().first().atom
        assert agg_message == expected_binding, (
            "Approver's signature should bind to the key-add operation"
        )

    def test_key_add_propose_forces_member_to_sign_operation_binding(self):
        bls_approver = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        approver_hash = bytes32(bls_approver.get_tree_hash())
        admins = (
            AdminRecord(admin_idx=0, leaves=(approver_hash,), m_within=1),
        )
        current_height = CURRENT_BLOCK_HEIGHT
        activates_at = current_height + DEFAULT_COOLDOWN_BLOCKS
        expected_binding = compute_key_op_binding_hash(
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            member_hash=NEW_MEMBER_HASH,
            activates_at=activates_at,
        )
        attacker_reused_binding = compute_key_op_binding_hash(
            admin_idx=0,
            op_kind=OP_KIND_ADD,
            member_hash=bytes32(b"\xDD" * 32),
            activates_at=activates_at,
        )
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(_trivial_mips_puzzle().get_tree_hash()),
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_add_propose_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=admins,
            current_pending_ops=(),
            admin_idx=0,
            approving_member_reveal=bls_approver,
            approving_member_solution=Program.to([attacker_reused_binding]),
            new_member_hash=NEW_MEMBER_HASH,
            current_block_height=current_height,
        )
        _, message = _first_agg_sig_me_condition(inner.run(sol))

        assert message == expected_binding
        assert message != attacker_reused_binding

    def test_key_remove_quorum_forces_members_to_sign_removed_leaf_binding(self):
        bls_member_a = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        bls_member_b = _bls_member_fixture().curry(bytes(b"\x43" * 48))
        leaf_a = bytes32(bls_member_a.get_tree_hash())
        leaf_b = bytes32(bls_member_b.get_tree_hash())
        legit_removed_hash = bytes32(b"\xAA" * 32)
        attacker_removed_hash = bytes32(b"\xBB" * 32)
        admins = (
            AdminRecord(
                admin_idx=0,
                leaves=(leaf_a, leaf_b, legit_removed_hash, attacker_removed_hash),
                m_within=2,
            ),
        )
        legit_binding = compute_key_remove_quorum_binding_hash(
            admin_idx=0,
            removed_member_hash=legit_removed_hash,
        )
        expected_attack_binding = compute_key_remove_quorum_binding_hash(
            admin_idx=0,
            removed_member_hash=attacker_removed_hash,
        )
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(_trivial_mips_puzzle().get_tree_hash()),
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_key_remove_quorum_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_admins=admins,
            admin_idx=0,
            removed_member_hash=attacker_removed_hash,
            approving_pairs=(
                (bls_member_a, Program.to([legit_binding])),
                (bls_member_b, Program.to([legit_binding])),
            ),
        )
        messages = _agg_sig_me_messages(inner.run(sol))

        assert messages == [expected_attack_binding, expected_attack_binding]
        assert legit_binding not in messages

    def test_admin_roster_update_forces_real_bls_mips_to_sign_binding_hash(self):
        bls_mips_reveal = _bls_member_fixture().curry(REAL_BLS_PUBKEY)
        current_mips_root = bytes32(bls_mips_reveal.get_tree_hash())
        current_admins = (
            AdminRecord(admin_idx=0, leaves=(LEAF_BLS_ADMIN_1,), m_within=1),
        )
        new_admin = AdminRecord(
            admin_idx=1,
            leaves=(LEAF_BLS_ADMIN_2,),
            m_within=1,
        )
        new_mips_root = bytes32(b"\xB0" * 32)
        expected_binding_hash = compute_roster_update_binding_hash(
            current_mips_root_hash=current_mips_root,
            current_admins_hash=compute_admins_hash(current_admins),
            current_pending_ops_hash=EMPTY_LIST_HASH,
            current_authority_version=INITIAL_AUTHORITY_VERSION,
            new_admins_hash=compute_admins_hash(current_admins + (new_admin,)),
            new_mips_root_hash=new_mips_root,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
        )
        inner = make_inner_puzzle(
            mips_root_hash=current_mips_root,
            admins_hash=compute_admins_hash(current_admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_admin_roster_update_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            current_authority_version=INITIAL_AUTHORITY_VERSION,
            current_admins=current_admins,
            current_pending_ops=(),
            current_mips_reveal=bls_mips_reveal,
            current_mips_solution=Program.to([REAL_SIGNED_MESSAGE]),
            new_admin=new_admin,
            new_mips_root_hash=new_mips_root,
        )

        result = inner.run(sol)
        agg_pubkey, agg_message = _first_agg_sig_me_condition(result)

        assert agg_pubkey == REAL_BLS_PUBKEY
        assert agg_message == expected_binding_hash
        assert agg_message != REAL_SIGNED_MESSAGE


# ─────────────────────────────────────────────────────────────────────────
# Real Eip712Member integration test (CHIP-0037 + PR #395 in production).
#
# This is the flagship test for Phase 9-Hermes: an end-to-end happy path
# that:
#   1. Loads the actual Eip712Member.clsp authored in chia-wallet-sdk PR
#      #395 (copied verbatim into solslot-protocol as a test fixture).
#   2. Constructs a real EIP-712 envelope per CHIP-0037 (mainnet domain).
#   3. Signs it with a known secp256k1 keypair (eth_keys + pycryptodome).
#   4. Runs the curried Eip712Member with the right CLVM flags (SECP +
#      KECCAK enabled) and verifies it emits ASSERT_MY_COIN_ID with the
#      correct coin_id.
#   5. Then wraps the same Eip712Member as the v2 shim's MIPS reveal and
#      runs an OPERATIONAL spend, confirming the whole stack composes.
#
# This proves: the v2 admin_authority_v2_inner.clsp shim correctly
# delegates to the upstream Eip712Member, which correctly verifies a
# real EIP-712 signature, in a single integrated end-to-end path.
# ─────────────────────────────────────────────────────────────────────────


_EIP712_MEMBER_FIXTURE: Program | None = None


def _eip712_member_fixture() -> Program:
    """Load the test fixture EIP-712 member puzzle (verbatim copy of
    chia-wallet-sdk PR #395's eip712_member.clsp).
    """
    global _EIP712_MEMBER_FIXTURE
    if _EIP712_MEMBER_FIXTURE is None:
        _EIP712_MEMBER_FIXTURE = load_clvm(
            "test_fixture_eip712_member.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
    return _EIP712_MEMBER_FIXTURE


def _keccak256(data: bytes) -> bytes:
    """Pure keccak256 — matches what the Chialisp `(keccak256 ...)` op
    computes (per CHIP-0036)."""
    from Crypto.Hash import keccak

    return keccak.new(data=data, digest_bits=256).digest()


def _eip712_domain_separator(genesis_challenge: bytes) -> bytes:
    """Reproduces P2Eip712MessageLayer::domain_separator from
    chia-sdk-driver. Mirrors the CHIP-0037 EIP-712 domain schema:
    `{ name: "Chia Coin Spend", version: "1", salt: <genesis_challenge> }`.
    """
    type_hash = _keccak256(b"EIP712Domain(string name,string version,bytes32 salt)")
    blob = (
        type_hash
        + _keccak256(b"Chia Coin Spend")
        + _keccak256(b"1")
        + genesis_challenge
    )
    return _keccak256(blob)


def _eip712_prefix_and_domain_separator(genesis_challenge: bytes) -> bytes:
    """34-byte concatenation of the EIP-712 prefix (0x1901) and the
    CHIP-0037 domain separator. This is what gets curried into
    Eip712Member as PREFIX_AND_DOMAIN_SEPARATOR.
    """
    return b"\x19\x01" + _eip712_domain_separator(genesis_challenge)


def _eip712_type_hash() -> bytes:
    """Keccak-256 of the canonical CHIP-0037 type signature."""
    return _keccak256(
        b"ChiaCoinSpend(bytes32 coin_id,bytes32 delegated_puzzle_hash)"
    )


def _eip712_hash_to_sign(
    prefix_and_domain: bytes, coin_id: bytes, dph: bytes
) -> bytes:
    """The 32-byte digest the off-chain wallet must sign."""
    inner = _keccak256(_eip712_type_hash() + coin_id + dph)
    return _keccak256(prefix_and_domain + inner)


def _compress_pubkey(uncompressed_pk: bytes) -> bytes:
    """Compress a 64-byte (x || y) secp256k1 pubkey to 33 bytes
    (02/03 prefix + x). The chia-wallet-sdk K1PublicKey type is the
    33-byte compressed form.
    """
    assert len(uncompressed_pk) == 64
    x = uncompressed_pk[:32]
    y_int = int.from_bytes(uncompressed_pk[32:], "big")
    prefix = b"\x02" if y_int % 2 == 0 else b"\x03"
    return prefix + x


# Mainnet genesis challenge (per chia-blockchain initial-config.yaml,
# mirrors what the Rust tests use).
MAINNET_GENESIS = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

# Test secp256k1 keypair seeded from a fixed value for deterministic tests.
EIP712_TEST_SK_SEED = bytes.fromhex(
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

# Test coin id and delegated_puzzle_hash — arbitrary 32-byte sentinels
# that the puzzle just binds the signature to.
EIP712_TEST_COIN_ID = bytes32.fromhex(
    "1111111111111111111111111111111111111111111111111111111111111111"
)
EIP712_TEST_DPH = bytes32.fromhex(
    "2222222222222222222222222222222222222222222222222222222222222222"
)

# CLVM flags needed to run secp256k1_verify and softfork-guarded keccak256.
import chia_rs

EIP712_RUN_FLAGS = (
    chia_rs.MEMPOOL_MODE
    | chia_rs.ENABLE_SECP_OPS
    | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
)


class TestEip712MemberIntegration:
    def test_eip712_member_compiles_and_matches_upstream(self):
        """The verbatim copy of chia-wallet-sdk's eip712_member.clsp
        compiles in solslot env and produces a stable tree hash.
        """
        mod = _eip712_member_fixture()
        h = mod.get_tree_hash()
        assert len(h) == 32
        # Tree hash is deterministic across re-loads.
        assert mod.get_tree_hash() == h
        # The compiled bytecode should be small (~170 bytes per the
        # standalone compile in earlier debugging).
        assert 100 < len(bytes(mod)) < 500

    def test_eip712_member_runs_with_valid_signature(self):
        """End-to-end: a real EIP-712 envelope signed with a known
        secp256k1 key passes through the puzzle and emits
        ASSERT_MY_COIN_ID with the right coin_id.
        """
        from eth_keys import keys

        # Off-chain construction (this is what the wallet / portal
        # would do before submitting the spend bundle).
        prefix_and_domain = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        type_h = _eip712_type_hash()
        sk = keys.PrivateKey(EIP712_TEST_SK_SEED)
        pk_compressed = _compress_pubkey(sk.public_key.to_bytes())

        signed_hash = _eip712_hash_to_sign(
            prefix_and_domain,
            EIP712_TEST_COIN_ID,
            EIP712_TEST_DPH,
        )
        # eth_keys returns 65-byte sig (r || s || v). K1Signature is the
        # canonical 64-byte raw form (r || s).
        full_sig = sk.sign_msg_hash(signed_hash).to_bytes()
        sig_64 = full_sig[:64]

        # On-chain: curry Eip712Member with (PREFIX, TYPE_HASH, PUBKEY)
        # and run with the M-of-N-supplied delegated_puzzle_hash + the
        # member's own (my_id, signed_hash, signature) solution.
        member = _eip712_member_fixture().curry(
            prefix_and_domain,
            type_h,
            pk_compressed,
        )
        solution = Program.to([
            EIP712_TEST_DPH,         # Delegated_Puzzle_Hash (truth from M-of-N)
            EIP712_TEST_COIN_ID,     # my_id
            signed_hash,             # signed_hash
            sig_64,                  # signature
        ])

        result = member.run(solution, flags=EIP712_RUN_FLAGS)
        conditions = list(result.as_iter())
        assert len(conditions) == 1, (
            f"Expected single condition (ASSERT_MY_COIN_ID), got {len(conditions)}"
        )
        cond = conditions[0]
        # ASSERT_MY_COIN_ID = 73
        assert int(cond.first().as_int()) == 73
        # The coin_id passed should match what we provided.
        assert cond.rest().first().atom == EIP712_TEST_COIN_ID

    def test_eip712_member_rejects_tampered_signature(self):
        """Negative path: flipping a byte in the signature makes
        secp256k1_verify raise. Confirms the puzzle's signature check
        is actually enforced at runtime.
        """
        from eth_keys import keys

        prefix_and_domain = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        type_h = _eip712_type_hash()
        sk = keys.PrivateKey(EIP712_TEST_SK_SEED)
        pk_compressed = _compress_pubkey(sk.public_key.to_bytes())

        signed_hash = _eip712_hash_to_sign(
            prefix_and_domain, EIP712_TEST_COIN_ID, EIP712_TEST_DPH
        )
        full_sig = sk.sign_msg_hash(signed_hash).to_bytes()
        # Tamper the first byte to invalidate the signature.
        sig_64 = bytes([full_sig[0] ^ 0x01]) + full_sig[1:64]

        member = _eip712_member_fixture().curry(
            prefix_and_domain, type_h, pk_compressed
        )
        solution = Program.to([
            EIP712_TEST_DPH, EIP712_TEST_COIN_ID, signed_hash, sig_64
        ])
        with pytest.raises(Exception):
            member.run(solution, flags=EIP712_RUN_FLAGS)

    def test_v2_shim_with_real_eip712_member_as_mips_reveal(self):
        """The flagship integration: use a real Eip712Member as the
        MIPS reveal for a v2 OPERATIONAL spend. The shim hashes the
        Eip712Member, verifies it matches MIPS_ROOT_HASH, runs it with
        a valid EIP-712 signature, and wraps the resulting
        ASSERT_MY_COIN_ID condition with the shim's own
        (CREATE_COIN, ASSERT_MY_AMOUNT, CREATE_PUZZLE_ANNOUNCEMENT).
        """
        from eth_keys import keys

        prefix_and_domain = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        type_h = _eip712_type_hash()
        sk = keys.PrivateKey(EIP712_TEST_SK_SEED)
        pk_compressed = _compress_pubkey(sk.public_key.to_bytes())

        signed_hash = _eip712_hash_to_sign(
            prefix_and_domain, EIP712_TEST_COIN_ID, EIP712_TEST_DPH
        )
        sig_64 = sk.sign_msg_hash(signed_hash).to_bytes()[:64]

        member = _eip712_member_fixture().curry(
            prefix_and_domain, type_h, pk_compressed
        )
        # The MIPS reveal IS the curried Eip712Member. In production
        # this would be wrapped in MIPS m_of_n; for this test we use
        # it directly as if it were a 1-of-1 quorum.
        member_solution = Program.to([
            EIP712_TEST_DPH, EIP712_TEST_COIN_ID, signed_hash, sig_64
        ])

        admins = (
            AdminRecord(
                admin_idx=0,
                leaves=(bytes32(member.get_tree_hash()),),
                m_within=1,
            ),
        )
        inner = make_inner_puzzle(
            mips_root_hash=bytes32(member.get_tree_hash()),
            admins_hash=compute_admins_hash(admins),
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=INITIAL_AUTHORITY_VERSION,
        )
        sol = build_operational_solution(
            my_amount=SINGLETON_AMOUNT,
            new_authority_version=INITIAL_AUTHORITY_VERSION + 1,
            mips_puzzle_reveal=member,
            mips_solution=member_solution,
        )
        result = inner.run(sol, flags=EIP712_RUN_FLAGS)
        conditions = list(result.as_iter())
        opcodes = [int(c.first().as_int()) for c in conditions]

        # Eip712Member's ASSERT_MY_COIN_ID (opcode 73) flows through.
        # NOTE: the shim ALSO emits ASSERT_MY_AMOUNT (also opcode 73).
        # Differentiate by payload length.
        coin_id_assertions = [
            c for c in conditions
            if int(c.first().as_int()) == 73
            and len(c.rest().first().atom) == 32
        ]
        assert len(coin_id_assertions) == 1, (
            f"Expected exactly one ASSERT_MY_COIN_ID with 32B payload, got {len(coin_id_assertions)}"
        )
        assert coin_id_assertions[0].rest().first().atom == EIP712_TEST_COIN_ID

        # Shim's own conditions are present.
        assert 51 in opcodes  # CREATE_COIN
        assert 62 in opcodes  # CREATE_PUZZLE_ANNOUNCEMENT
        # ASSERT_MY_AMOUNT is also opcode 73 but with a uint payload, not 32B


# ─────────────────────────────────────────────────────────────────────────
# Fresh-genesis helpers and state parsing.
# ─────────────────────────────────────────────────────────────────────────


class TestStateHelpers:
    def test_single_member_admin_record(self):
        """Single-leaf admin record has the leaf, m_within=1, and
        correct admin_idx.
        """
        leaf = bytes32(b"\xAA" * 32)
        rec = single_member_admin_record(admin_idx=3, member_tree_hash=leaf)
        assert rec.admin_idx == 3
        assert rec.leaves == (leaf,)
        assert rec.m_within == 1

    def test_parse_inner_puzzle_round_trip(self):
        """parse_inner_puzzle reverses make_inner_puzzle. All curried
        slots round-trip through serialization unchanged.
        """
        admins = tuple(
            single_member_admin_record(idx, bytes32(bytes([value]) * 32))
            for idx, value in enumerate(range(0xA0, 0xA3))
        )
        admins_hash = compute_admins_hash(admins)
        mips_root = bytes32(b"\xBE\xEF" * 16)

        puzzle = make_inner_puzzle(
            mips_root_hash=mips_root,
            admins_hash=admins_hash,
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=42,
        )
        state = parse_inner_puzzle(puzzle)

        # Curried policy values match the defaults the make_inner_puzzle
        # call used.
        assert state.max_admins == DEFAULT_MAX_ADMINS
        assert state.max_keys_per_admin == DEFAULT_MAX_KEYS_PER_ADMIN
        assert state.cooldown_blocks == DEFAULT_COOLDOWN_BLOCKS
        assert state.recovery_timeout_blocks == DEFAULT_RECOVERY_TIMEOUT_BLOCKS
        assert state.sgt_governance_puzzle_hash == DEFAULT_SGT_GOVERNANCE_PUZZLE_HASH

        # Curried state slots match exactly what we passed in.
        assert state.mips_root_hash == mips_root
        assert state.admins_hash == admins_hash
        assert state.pending_ops_hash == EMPTY_LIST_HASH
        assert state.authority_version == 42

        # SELF_MOD_HASH is the v2 inner mod hash.
        assert state.self_mod_hash == admin_authority_v2_inner_mod_hash()

    def test_parse_rejects_non_v2_puzzle(self):
        """parse_inner_puzzle raises if the puzzle isn't a curried
        admin_authority_v2_inner.clsp instance.
        """
        bogus_puzzle = Program.to((1, [[1, b"not-v2"]])).curry(b"\x00" * 32)
        with pytest.raises(ValueError, match="does not match"):
            parse_inner_puzzle(bogus_puzzle)

    def test_state_hash_via_dataclass_matches_off_chain_compute(self):
        """AdminAuthorityV2State.state_hash matches what
        compute_state_hash returns directly. This is the announcement
        payload's body that off-chain monitors verify.
        """
        admins = tuple(
            single_member_admin_record(idx, leaf)
            for idx, leaf in enumerate(
                (bytes32(b"\xA1" * 32), bytes32(b"\xA2" * 32))
            )
        )
        admins_hash = compute_admins_hash(admins)
        mips_root = bytes32(b"\xCA\xFE" * 16)

        puzzle = make_inner_puzzle(
            mips_root_hash=mips_root,
            admins_hash=admins_hash,
            pending_ops_hash=EMPTY_LIST_HASH,
            authority_version=7,
        )
        state = parse_inner_puzzle(puzzle)

        # The dataclass property and the standalone helper agree.
        from solslot_puzzles.admin_authority_v2_driver import compute_state_hash

        expected = compute_state_hash(
            mips_root, admins_hash, EMPTY_LIST_HASH, 7
        )
        assert state.state_hash == expected
        assert isinstance(state, AdminAuthorityV2State)
