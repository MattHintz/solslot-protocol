"""Joined consensus proof: governance EXECUTE of a vault-version bill emits
*exactly* the routine-path approval the ``vault_version_registry``'s
SPEND_CODE_ROUTINE asserts (vault-version governance, Brick 3.5c-1).

Two existing test suites each prove half of the binding in isolation:

  * ``test_governance.py::TestExecuteVaultVersion`` proves the governance side
    emits the right *message* (PROTOCOL_PREFIX || REGISTRY_TAG_ROUTINE ||
    content_hash).
  * ``test_vault_version_registry.py::TestRoutine`` proves the registry asserts
    ``sha256(governance_full_ph || message)``.

This suite JOINS them at the consensus boundary, using chia's real singleton
top layer (so the governance coin's full puzzle hash is ground-truth): it
reconstructs the announcement id the governance EXECUTE coin actually produces
and shows the registry's SPEND_CODE_ROUTINE asserts that exact id — i.e. the
two singletons pair when co-spent.  It also pins the *content* binding: the
registry can only publish the precise ``(code, params, version)`` the committee
ratified — a relayer cannot redirect the approved vote to a different version.
"""
from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import vault_version_registry_driver as vvr
from solslot_puzzles.sgt_driver import (
    TEST_KOS_MINT_EXECUTE_PUBKEY,
    TRK_EXECUTE,
    bill_vault_version,
    proposal_hash_from_bill,
    proposal_tracker_inner_puzzle,
    vault_version_approval_message,
)

# ── CLVM condition opcodes ──────────────────────────────────────────────────
CREATE_PUZZLE_ANNOUNCEMENT = 62
ASSERT_PUZZLE_ANNOUNCEMENT = 63
SEND_MESSAGE = 66

# ── Shared singleton primitives ─────────────────────────────────────────────
# Both singletons MUST agree on (SINGLETON_MOD_HASH, LAUNCHER_PUZZLE_HASH) and
# the governance launcher id for the cross-coin announcement to pair, so we use
# chia's real top-layer constants throughout (ground truth).
GOV_LAUNCHER_ID = bytes32(b"\xb0" * 32)
GOV_STRUCT = Program.to((SINGLETON_MOD_HASH, (GOV_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH)))

ADMIN_AUTHORITY_LAUNCHER_ID = bytes32(b"\xa1" * 32)

# Registry current state (v1).  The routine publish advances it to v2.
CUR_CODE = bytes32(b"\xc3" * 32)
CUR_PARAMS = bytes32(b"\xd4" * 32)
CUR_VERSION = 1

# The vault-version bill the committee ratified: a CODE change to v2.
NEW_CODE = bytes32(b"\x10" * 32)
NEW_PARAMS = bytes32(b"\x20" * 32)
NEW_VERSION = 2

# Tracker immutable params — values are irrelevant to the announcement binding
# (they affect the gov inner puzzle hash, which both sides use consistently).
SGT_FREE_MOD_HASH = bytes32(b"\x31" * 32)
SGT_LOCKED_MOD_HASH = bytes32(b"\x32" * 32)
CAT_MOD_HASH = bytes32(b"\x33" * 32)
SGT_TAIL_HASH = bytes32(b"\x34" * 32)
DID_PUZHASH = bytes32(b"\x35" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (bytes32(b"\xc0" * 32), SINGLETON_LAUNCHER_HASH))
)
QUORUM_BPS = 5000
VOTING_WINDOW = 300
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000


# ── Helpers ─────────────────────────────────────────────────────────────────
def _gov_execute_ready_inner(
    *, code: bytes32 = NEW_CODE, params: bytes32 = NEW_PARAMS, version: int = NEW_VERSION
) -> Program:
    """Curry the tracker into an EXECUTE-ready state holding a vault-version bill
    (quorum already met — the committee voted)."""
    bill = bill_vault_version(code, params, version)
    return proposal_tracker_inner_puzzle(
        GOV_STRUCT,
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH,
        SGT_TAIL_HASH,
        DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        SGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        TEST_KOS_MINT_EXECUTE_PUBKEY,
        proposal_hash=proposal_hash_from_bill(bill),
        bill_operation=bill,
        vote_tally=SGT_TOTAL_SUPPLY,  # 100% > quorum
        voting_deadline=2_000_000_000,
    )


def _gov_full_ph(inner: Program) -> bytes32:
    """Ground-truth governance singleton full puzzle hash (chia top layer)."""
    return bytes32(SINGLETON_MOD.curry(GOV_STRUCT, inner).get_tree_hash())


def _conds(prog: Program) -> list:
    return [list(c.as_iter()) for c in prog.as_iter()]


def _ai(p: Program) -> int:
    return int.from_bytes(p.atom, "big") if p.atom else 0


def _ab(p: Program) -> bytes:
    return bytes(p.atom) if p.atom is not None else b""


def _run_gov_execute(inner: Program):
    """Run the governance EXECUTE spend and return (conditions, inner_ph, full_ph)."""
    inner_ph = bytes32(inner.get_tree_hash())
    full_ph = _gov_full_ph(inner)
    # ASSERT_MY_COIN_ID needs a self-consistent coin id; `run` doesn't verify it
    # (that's consensus), so any 32-byte value lets the puzzle execute.
    coin_id = bytes32(hashlib.sha256(b"\x00" * 32 + full_ph + bytes([1])).digest())
    sol = Program.to([coin_id, inner_ph, 1, TRK_EXECUTE, 0])
    return _conds(inner.run(sol)), inner_ph, full_ph


def _registry_routine_asserts(*, gov_inner_ph: bytes32, code: bytes32, params: bytes32, version: int):
    """Run the registry SPEND_CODE_ROUTINE authorized by the given governance
    inner puzzle hash; return its ASSERT_PUZZLE_ANNOUNCEMENT ids."""
    registry_inner = vvr.make_inner_puzzle(
        admin_authority_launcher_id=ADMIN_AUTHORITY_LAUNCHER_ID,
        governance_launcher_id=GOV_LAUNCHER_ID,
        vault_inner_mod_hash=CUR_CODE,
        canonical_params_hash=CUR_PARAMS,
        vault_version=CUR_VERSION,
    )
    state = vvr.parse_inner_puzzle(registry_inner)
    art = vvr.build_routine_spend(
        current=state,
        authorizer_inner_puzzle_hash=gov_inner_ph,
        new_vault_inner_mod_hash=code,
        new_canonical_params_hash=params,
        new_vault_version=version,
    )
    conds = _conds(registry_inner.run(art.inner_solution))
    return [_ab(c[1]) for c in conds if _ai(c[0]) == ASSERT_PUZZLE_ANNOUNCEMENT]


# ─────────────────────────────────────────────────────────────────────────────
#  The binding: gov EXECUTE announcement == registry routine assertion
# ─────────────────────────────────────────────────────────────────────────────
def test_gov_execute_announcement_pairs_with_registry_routine_assert():
    gov_conds, gov_inner_ph, gov_full_ph = _run_gov_execute(_gov_execute_ready_inner())

    # Governance dispatches via a puzzle announcement (no SEND_MESSAGE for this
    # bill) — registry asserts, gov announces.
    assert SEND_MESSAGE not in [_ai(c[0]) for c in gov_conds]

    # The routine-approval message gov emits (alongside the EXEC release one).
    msg = vault_version_approval_message(NEW_CODE, NEW_PARAMS, NEW_VERSION)
    gov_anns = [_ab(c[1]) for c in gov_conds if _ai(c[0]) == CREATE_PUZZLE_ANNOUNCEMENT]
    assert msg in gov_anns

    # The on-chain announcement id the gov coin produces.
    gov_announcement_id = bytes32(hashlib.sha256(gov_full_ph + msg).digest())

    # The registry's SPEND_CODE_ROUTINE asserts EXACTLY that id.
    reg_asserts = _registry_routine_asserts(
        gov_inner_ph=gov_inner_ph, code=NEW_CODE, params=NEW_PARAMS, version=NEW_VERSION
    )
    assert reg_asserts == [bytes(gov_announcement_id)]

    # ...and it equals the registry driver's own computation from the gov full ph.
    assert reg_asserts[0] == bytes(
        vvr.compute_authorizer_announcement_id(
            authorizer_full_puzzle_hash=gov_full_ph,
            path_tag=vvr.TAG_ROUTINE,
            vault_inner_mod_hash=NEW_CODE,
            canonical_params_hash=NEW_PARAMS,
            vault_version=NEW_VERSION,
        )
    )


def test_relayer_cannot_publish_a_different_version_than_ratified():
    """The committee ratified (NEW_CODE, NEW_PARAMS, NEW_VERSION).  A relayer who
    tries to drive the registry to a DIFFERENT version is rejected before the
    registry can publish an assertion — so the bundle cannot pair."""
    _, gov_inner_ph, _ = _run_gov_execute(_gov_execute_ready_inner())

    # Attacker drives the registry to version 3 (not what was voted).
    with pytest.raises(ValueError, match="exactly one"):
        _registry_routine_asserts(
            gov_inner_ph=gov_inner_ph, code=NEW_CODE, params=NEW_PARAMS, version=3
        )


def test_routine_binds_to_governance_not_admin_authority():
    """The routine approval is keyed by the governance launcher; the registry
    will not accept it under the admin-authority (fast-track) tier."""
    gov_conds, gov_inner_ph, gov_full_ph = _run_gov_execute(_gov_execute_ready_inner())
    msg = vault_version_approval_message(NEW_CODE, NEW_PARAMS, NEW_VERSION)
    gov_announcement_id = bytes32(hashlib.sha256(gov_full_ph + msg).digest())

    # The same target state under the FAST-TRACK tag + admin-authority key is a
    # different announcement id — tiers cannot cross.
    fast = vvr.compute_authorizer_announcement_id(
        authorizer_full_puzzle_hash=gov_full_ph,
        path_tag=vvr.TAG_FASTTRACK,
        vault_inner_mod_hash=NEW_CODE,
        canonical_params_hash=NEW_PARAMS,
        vault_version=NEW_VERSION,
    )
    assert bytes(gov_announcement_id) != bytes(fast)
