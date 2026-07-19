"""Python driver for admin_authority_v2_inner.clsp (Phase 9-Hermes-C.3).

The v2 admin-authority singleton replaces v1's homegrown BLS allowlist with
a thin shim over CHIP-0043 MIPS. Each admin slot holds a ``OneOfN`` of
personal authentication methods (BLS, EIP-712, passkey, ...); the
protocol-level admin set is an ``MofN`` quorum over those slots.

Design reference:
    research/SOLSLOT_ADMIN_AUTHORITY_V2_DESIGN.md

This module exposes the off-chain construction of state and spends that
mirrors what the on-chain ``admin_authority_v2_inner.clsp`` puzzle expects.
The cross-repo contract is: any tree-hash this driver computes must match
exactly what the on-chain ``sha256tree`` calls produce. Tests in
``tests/test_admin_authority_v2.py`` enforce this end-to-end.

This iteration (C.3 step 1) covers OPERATIONAL spends (tag 0x01). Builders
for the remaining 5 spend tags land in subsequent iterations as their
runtime tests pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia.wallet.puzzles.custody.custody_architecture import MofN, PuzzleWithRestrictions
from chia_puzzles_py import programs as chia_puzzle_programs
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.eip712_helpers import (
    compute_eip712_member_leaf_hash,
    eip712_prefix_and_domain_separator,
    genesis_challenge_for_network,
    make_eip712_member_puzzle,
)

# Standard chia singleton constants pulled in for the launch flow.
SINGLETON_AMOUNT = uint64(1)


# ─────────────────────────────────────────────────────────────────────────
# On-chain constants (mirror the .clsp).
# ─────────────────────────────────────────────────────────────────────────

# Spend tags. Must match defconstants in admin_authority_v2_inner.clsp.
SPEND_OPERATIONAL = 0x01
SPEND_KEY_ADD_PROPOSE = 0x02
SPEND_KEY_ADD_ACTIVATE = 0x03
SPEND_KEY_ADD_VETO = 0x04
SPEND_KEY_REMOVE_QUORUM = 0x05
SPEND_KEY_REMOVE_EMERGENCY = 0x06
SPEND_ADMIN_ROSTER_UPDATE = 0x07

# Op-kind tags inside pending-ops entries.
OP_KIND_ADD = 0x01
OP_KIND_REMOVE = 0x02

# Confirmation window for PROPOSE-style spends. Must match PROPOSE_WINDOW
# in the puzzle. Reflects ~2 minutes at 24-second blocks.
PROPOSE_WINDOW = 8

# Pending-ops list capacity. Must match MAX_PENDING_OPS in the puzzle.
MAX_PENDING_OPS = 8

# sha256tree of the empty list (). Equivalent to the on-chain
# EMPTY_LIST_HASH constant, used as the curried PENDING_KEY_OPS_HASH when
# the singleton has no pending ops.
EMPTY_LIST_HASH: bytes32 = bytes32.fromhex(
    "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
)


# Default protocol-policy values. Operators can override at deployment
# time; these match the design doc's recommended defaults.
DEFAULT_MAX_ADMINS = 25
DEFAULT_MAX_KEYS_PER_ADMIN = 10
DEFAULT_COOLDOWN_BLOCKS = 1024  # ≈ 2 days at 24s blocks
DEFAULT_RECOVERY_TIMEOUT_BLOCKS = 5040  # ≈ 7 days
DEFAULT_SGT_GOVERNANCE_PUZZLE_HASH: bytes32 = bytes32(b"\x00" * 32)


# ─────────────────────────────────────────────────────────────────────────
# Module-level cache of the compiled program.
# ─────────────────────────────────────────────────────────────────────────

_ADMIN_AUTHORITY_V2_INNER_MOD: Program | None = None


def admin_authority_v2_inner_mod() -> Program:
    """Return the compiled (uncurried) admin_authority_v2_inner.clsp Program."""
    global _ADMIN_AUTHORITY_V2_INNER_MOD
    if _ADMIN_AUTHORITY_V2_INNER_MOD is None:
        _ADMIN_AUTHORITY_V2_INNER_MOD = load_puzzle("admin_authority_v2_inner.clsp")
    return _ADMIN_AUTHORITY_V2_INNER_MOD


def admin_authority_v2_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod (used as SELF_MOD_HASH curried arg)."""
    return bytes32(admin_authority_v2_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Typed state.
#
# Admin records are 3-tuples (admin_idx, leaves, m_within). leaves is the
# flat list of member tree hashes (32 bytes each) representing the OneOfN
# of authentication methods this admin can sign with. m_within is the
# within-admin removal quorum (default 1 — single-key admins).
#
# Pending-op entries are 4-tuples (admin_idx, op_kind, target_hash,
# activates_at). They live in a flat list whose sha256tree is curried as
# PENDING_KEY_OPS_HASH.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AdminRecord:
    """One admin slot's state. Maps directly to a Chialisp record."""

    admin_idx: int
    leaves: tuple[bytes32, ...]
    m_within: int

    def to_program(self) -> Program:
        return Program.to([self.admin_idx, list(self.leaves), self.m_within])


@dataclass(frozen=True)
class PendingOp:
    """A pending key-rotation op awaiting activation or veto."""

    admin_idx: int
    op_kind: int  # OP_KIND_ADD | OP_KIND_REMOVE
    target_hash: bytes32
    activates_at: int

    def to_program(self) -> Program:
        return Program.to(
            [self.admin_idx, self.op_kind, self.target_hash, self.activates_at]
        )


@dataclass(frozen=True)
class AdminRosterUpdatePreview:
    new_admins: tuple[AdminRecord, ...]
    new_threshold: int
    new_mips_root_hash: bytes32
    new_admins_hash: bytes32
    new_pending_ops_hash: bytes32
    new_authority_version: int
    new_state_hash: bytes32


@dataclass(frozen=True)
class AdminRosterUpdateSpend:
    preview: AdminRosterUpdatePreview
    solution: Program


@dataclass(frozen=True)
class _ProgramMember:
    """Adapter that lets a canonical Program participate in CHIP-0043."""

    program: Program

    def memo(self, nonce: int) -> Program:
        return Program.to([bytes32(self.program.get_tree_hash())])

    def puzzle(self, nonce: int) -> Program:
        return self.program

    def puzzle_hash(self, nonce: int) -> bytes32:
        return bytes32(self.program.get_tree_hash())


@dataclass(frozen=True)
class GenesisAdminQuorum:
    """Canonical three-slot, two-signature genesis authority."""

    admins: tuple[AdminRecord, AdminRecord, AdminRecord]
    threshold: int
    mips_reveal: Program
    mips_root_hash: bytes32
    admins_hash: bytes32
    compressed_pubkeys: tuple[bytes, bytes, bytes]
    member_puzzle_hashes: tuple[bytes32, bytes32, bytes32]


def build_genesis_eip712_admin_quorum(
    *,
    network: str,
    compressed_pubkeys: Sequence[bytes],
) -> GenesisAdminQuorum:
    """Derive the only admin authority accepted by a fresh V2 ceremony.

    The ceremony never accepts an operator-supplied ``MIPS_ROOT_HASH``.  It
    receives exactly three compressed secp256k1 keys and deterministically
    builds three EIP-712 members plus the CHIP-0043 2-of-3 reveal.
    """
    pubkeys = tuple(bytes(value) for value in compressed_pubkeys)
    if len(pubkeys) != 3:
        raise ValueError("fresh V2 genesis requires exactly three admin public keys")
    if any(len(value) != 33 for value in pubkeys):
        raise ValueError("every genesis admin public key must be 33-byte compressed secp256k1")
    if len(set(pubkeys)) != 3:
        raise ValueError("genesis admin public keys must be distinct")

    prefix = eip712_prefix_and_domain_separator(
        genesis_challenge_for_network(network)
    )
    member_puzzles = tuple(
        make_eip712_member_puzzle(
            secp256k1_pubkey=pubkey,
            prefix_and_domain_separator=prefix,
        )
        for pubkey in pubkeys
    )
    member_hashes = tuple(
        compute_eip712_member_leaf_hash(
            secp256k1_pubkey=pubkey,
            prefix_and_domain_separator=prefix,
        )
        for pubkey in pubkeys
    )
    for member, member_hash in zip(member_puzzles, member_hashes, strict=True):
        if bytes32(member.get_tree_hash()) != member_hash:
            raise ValueError("EIP-712 member reveal does not match its committed hash")

    admins = tuple(
        AdminRecord(admin_idx=index, leaves=(member_hash,), m_within=1)
        for index, member_hash in enumerate(member_hashes)
    )
    threshold = admin_supermajority_threshold(len(admins))
    if threshold != 2:
        raise ValueError("fresh V2 genesis admin threshold must be two")

    quorum = MofN(
        m=threshold,
        members=[
            PuzzleWithRestrictions(
                nonce=index + 1,
                restrictions=[],
                puzzle=_ProgramMember(member),
            )
            for index, member in enumerate(member_puzzles)
        ],
    )
    # Chia's custody driver keeps MofN_MOD as a module-level Program. Program
    # LazyNodes are thread-affine, so calling ``quorum.puzzle`` from an API
    # event-loop thread can panic when the custody module was imported on the
    # process main thread. Rehydrate the canonical bytecode on the caller's
    # thread and curry the exact same threshold/root instead.
    mips_reveal = Program.from_bytes(chia_puzzle_programs.M_OF_N).curry(
        threshold, quorum._merkle_tree.calculate_root()
    )
    return GenesisAdminQuorum(
        admins=admins,  # type: ignore[arg-type]
        threshold=threshold,
        mips_reveal=mips_reveal,
        mips_root_hash=bytes32(mips_reveal.get_tree_hash()),
        admins_hash=compute_admins_hash(admins),
        compressed_pubkeys=pubkeys,  # type: ignore[arg-type]
        member_puzzle_hashes=member_hashes,  # type: ignore[arg-type]
    )


def compute_admins_hash(admins: Sequence[AdminRecord]) -> bytes32:
    """sha256tree of the admins list. Matches on-chain ADMINS_HASH."""
    return bytes32(Program.to([a.to_program() for a in admins]).get_tree_hash())


def compute_pending_ops_hash(pending_ops: Sequence[PendingOp]) -> bytes32:
    """sha256tree of the pending-ops list. Empty list hashes to EMPTY_LIST_HASH."""
    if not pending_ops:
        return EMPTY_LIST_HASH
    return bytes32(
        Program.to([p.to_program() for p in pending_ops]).get_tree_hash()
    )


def compute_state_hash(
    mips_root_hash: bytes32,
    admins_hash: bytes32,
    pending_ops_hash: bytes32,
    authority_version: int,
) -> bytes32:
    """sha256tree of the (state) tuple announced for off-chain monitors.

    Mirrors the on-chain ``state-hash`` defun. Off-chain consumers
    decoding the singleton's puzzle announcement see this exact hash
    after the PROTOCOL_PREFIX + spend_tag bytes.
    """
    return bytes32(
        Program.to(
            [mips_root_hash, admins_hash, pending_ops_hash, authority_version]
        ).get_tree_hash()
    )


def compute_roster_update_binding_hash(
    *,
    current_mips_root_hash: bytes32,
    current_admins_hash: bytes32,
    current_pending_ops_hash: bytes32,
    current_authority_version: int,
    new_admins_hash: bytes32,
    new_mips_root_hash: bytes32,
    new_authority_version: int,
) -> bytes32:
    if len(current_mips_root_hash) != 32:
        raise ValueError("current_mips_root_hash must be 32 bytes")
    if len(current_admins_hash) != 32:
        raise ValueError("current_admins_hash must be 32 bytes")
    if len(current_pending_ops_hash) != 32:
        raise ValueError("current_pending_ops_hash must be 32 bytes")
    if current_authority_version < 0:
        raise ValueError("current_authority_version must be non-negative")
    if len(new_admins_hash) != 32:
        raise ValueError("new_admins_hash must be 32 bytes")
    if len(new_mips_root_hash) != 32:
        raise ValueError("new_mips_root_hash must be 32 bytes")
    if new_authority_version < 0:
        raise ValueError("new_authority_version must be non-negative")
    return bytes32(
        Program.to(
            [
                SPEND_ADMIN_ROSTER_UPDATE,
                current_mips_root_hash,
                current_admins_hash,
                current_pending_ops_hash,
                current_authority_version,
                new_admins_hash,
                new_mips_root_hash,
                new_authority_version,
            ]
        ).get_tree_hash()
    )


def admin_supermajority_threshold(admin_count: int) -> int:
    if admin_count < 1:
        raise ValueError(f"admin_count must be >= 1, got {admin_count}")
    return (2 * admin_count + 2) // 3


def build_admin_slot_add_preview(
    *,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    new_admin: AdminRecord,
    current_mips_root_hash: bytes32,
    new_mips_root_hash: bytes32,
    current_authority_version: int,
    new_authority_version: int,
    max_admins: int = DEFAULT_MAX_ADMINS,
    max_keys_per_admin: int = DEFAULT_MAX_KEYS_PER_ADMIN,
) -> AdminRosterUpdatePreview:
    current_admins_tuple = tuple(current_admins)
    if not current_admins_tuple:
        raise ValueError("current_admins must contain at least one admin")
    if len(current_admins_tuple) >= max_admins:
        raise ValueError(f"admin roster already has max_admins ({max_admins})")
    expected_authority_version = current_authority_version + 1
    if new_authority_version != expected_authority_version:
        raise ValueError(
            "new_authority_version must equal current_authority_version + 1"
        )
    if len(current_mips_root_hash) != 32:
        raise ValueError("current_mips_root_hash must be 32 bytes")
    if len(new_mips_root_hash) != 32:
        raise ValueError("new_mips_root_hash must be 32 bytes")
    if new_mips_root_hash == current_mips_root_hash:
        raise ValueError("new_mips_root_hash must change when adding an admin slot")

    seen_admin_indices: set[int] = set()
    for admin in current_admins_tuple:
        _validate_admin_record(admin, max_keys_per_admin)
        if admin.admin_idx in seen_admin_indices:
            raise ValueError(f"duplicate admin_idx {admin.admin_idx}")
        seen_admin_indices.add(admin.admin_idx)

    _validate_admin_record(new_admin, max_keys_per_admin)
    if new_admin.admin_idx in seen_admin_indices:
        raise ValueError(f"admin_idx {new_admin.admin_idx} already exists")
    expected_admin_idx = max(seen_admin_indices) + 1
    if new_admin.admin_idx != expected_admin_idx:
        raise ValueError(
            f"new admin_idx must be next contiguous slot {expected_admin_idx}, "
            f"got {new_admin.admin_idx}"
        )

    new_admins = current_admins_tuple + (new_admin,)
    new_admins_hash = compute_admins_hash(new_admins)
    new_pending_ops_hash = compute_pending_ops_hash(current_pending_ops)
    new_state_hash = compute_state_hash(
        new_mips_root_hash,
        new_admins_hash,
        new_pending_ops_hash,
        new_authority_version,
    )
    return AdminRosterUpdatePreview(
        new_admins=new_admins,
        new_threshold=admin_supermajority_threshold(len(new_admins)),
        new_mips_root_hash=new_mips_root_hash,
        new_admins_hash=new_admins_hash,
        new_pending_ops_hash=new_pending_ops_hash,
        new_authority_version=new_authority_version,
        new_state_hash=new_state_hash,
    )


def _validate_admin_record(admin: AdminRecord, max_keys_per_admin: int) -> None:
    if admin.admin_idx < 0:
        raise ValueError(f"admin_idx must be non-negative, got {admin.admin_idx}")
    if not admin.leaves:
        raise ValueError(f"admin {admin.admin_idx} must have at least one leaf")
    if len(admin.leaves) > max_keys_per_admin:
        raise ValueError(
            f"admin {admin.admin_idx} has {len(admin.leaves)} leaves, "
            f"max is {max_keys_per_admin}"
        )
    if admin.m_within < 1 or admin.m_within > len(admin.leaves):
        raise ValueError(
            f"admin {admin.admin_idx} m_within must be in [1, {len(admin.leaves)}]"
        )
    seen_leaves: set[bytes32] = set()
    for leaf in admin.leaves:
        if len(leaf) != 32:
            raise ValueError(f"admin {admin.admin_idx} leaf must be 32 bytes")
        if leaf in seen_leaves:
            raise ValueError(f"admin {admin.admin_idx} has duplicate leaf")
        seen_leaves.add(leaf)


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    *,
    mips_root_hash: bytes32,
    admins_hash: bytes32,
    pending_ops_hash: bytes32 = EMPTY_LIST_HASH,
    authority_version: int = 1,
    max_admins: int = DEFAULT_MAX_ADMINS,
    max_keys_per_admin: int = DEFAULT_MAX_KEYS_PER_ADMIN,
    cooldown_blocks: int = DEFAULT_COOLDOWN_BLOCKS,
    recovery_timeout_blocks: int = DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
    sgt_governance_puzzle_hash: bytes32 = DEFAULT_SGT_GOVERNANCE_PUZZLE_HASH,
) -> Program:
    """Curry the v2 inner puzzle for a specific protocol-policy + state.

    Currying order MUST match admin_authority_v2_inner.clsp:

        SELF_MOD_HASH, MAX_ADMINS, MAX_KEYS_PER_ADMIN, COOLDOWN_BLOCKS,
        RECOVERY_TIMEOUT_BLOCKS, SGT_GOVERNANCE_PUZZLE_HASH,
        MIPS_ROOT_HASH, ADMINS_HASH, PENDING_KEY_OPS_HASH,
        AUTHORITY_VERSION
    """
    return admin_authority_v2_inner_mod().curry(
        admin_authority_v2_inner_mod_hash(),
        max_admins,
        max_keys_per_admin,
        cooldown_blocks,
        recovery_timeout_blocks,
        sgt_governance_puzzle_hash,
        mips_root_hash,
        admins_hash,
        pending_ops_hash,
        authority_version,
    )


def make_inner_puzzle_hash(**kwargs) -> bytes32:
    """Tree hash of the curried inner puzzle. Forwards all kwargs."""
    return bytes32(make_inner_puzzle(**kwargs).get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Genesis launch (Phase 9-Hermes-D D-2).
#
# A v2 admin-authority singleton starts life as a single-spend transaction:
#
#   1. The operator's funding coin (at any p2-puzzle that authorises XCH
#      transfer — typically the standard wallet puzzle, BLS-signed) emits
#      ``CREATE_COIN(SINGLETON_LAUNCHER_HASH, 1)``.  This produces the
#      "launcher coin", whose name (= coin id) becomes the singleton's
#      permanent ``launcher_id``.
#   2. The launcher coin spends with solution
#      ``(eve_full_puzzle_hash, 1, ())``, emitting:
#        a. ``CREATE_COIN(eve_full_puzzle_hash, 1)`` → the eve coin.
#        b. ``CREATE_PUZZLE_ANNOUNCEMENT(sha256tree(launcher_solution))``.
#      The launcher coin uses the standard chia launcher puzzle, which
#      is permissionless (no signature needed).
#   3. The eve coin's full puzzle = singleton_top_layer.curry(
#         SINGLETON_STRUCT(launcher_id), v2_inner_puzzle
#      ).  The v2 inner puzzle is what ``make_inner_puzzle`` produces.
#
# These helpers compute the deterministic outputs of step 1+2+3 from
# the operator's intended state.  The portal (Hybrid-C client) calls
# them to construct the spend bundle the operator's chia wallet then
# signs (only the funding coin needs a signature).
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LaunchOutputs:
    """All deterministic coins + announcements produced by a v2 launch.

    Returned by :func:`compute_launch_outputs`. Exposes everything the
    portal / operator tools need to:

    * Build the funding-coin spend (``launcher_coin`` is the CREATE_COIN
      target).
    * Build the launcher-coin spend (``launcher_solution`` is its solution,
      which the standard singleton launcher puzzle will run).
    * Verify post-launch state (``eve_coin``'s lineage parent is
      ``launcher_coin.name()``, and ``eve_full_puzzle_hash`` is what
      future reads of the singleton lineage will see).
    * Cross-check that the launcher-spend announcement matches what
      observers expect (``launcher_announcement_hash``).

    Fields are all immutable + JSON-friendly so they can be cached, logged,
    or surfaced in ``/admin/auth/authority_v2`` snapshots.
    """

    launcher_coin: Coin
    """The launcher coin spawned from the funding coin's CREATE_COIN.

    Its ``.name()`` is the singleton's permanent ``launcher_id``.
    """

    launcher_id: bytes32
    """Convenience accessor for ``launcher_coin.name()``."""

    eve_inner_puzzle_hash: bytes32
    """sha256tree of the curried v2 inner puzzle (what ``make_inner_puzzle_hash`` returns)."""

    eve_full_puzzle_hash: bytes32
    """sha256tree of ``singleton_top_layer.curry(SINGLETON_STRUCT, eve_inner_puzzle)``.

    This is the puzzle hash the eve coin actually lives at.  Subsequent
    OPERATIONAL spends will recurry into a child coin at the same
    inner-puzzle hash (or a new one if the spend mutated state).
    """

    eve_coin: Coin
    """The eve coin: the singleton's first stateful incarnation."""

    launcher_solution: Program
    """The solution program the launcher coin is spent with.

    Layout: ``(eve_full_puzzle_hash eve_amount key_value_list)``.
    The standard chia launcher puzzle hashes this list and emits it
    as ``CREATE_PUZZLE_ANNOUNCEMENT``.
    """

    launcher_announcement_message: bytes32
    """sha256tree of ``launcher_solution`` — the body of the launcher's
    ``CREATE_PUZZLE_ANNOUNCEMENT``.  External observers correlating
    chain state with off-chain expectations match on this value."""

    launcher_announcement_id: bytes32
    """sha256(launcher_id || launcher_announcement_message).

    This is the value that ``ASSERT_PUZZLE_ANNOUNCEMENT`` / external
    observers index by — it ties the announcement to the specific
    launcher coin (preventing announcements from one launch being
    accepted as proof of a different launch).
    """


def _singleton_struct(launcher_id: bytes32) -> Program:
    """Standard chia singleton struct ``(MOD_HASH . (LAUNCHER_ID . LAUNCHER_PH))``.

    Curried into ``singleton_top_layer`` to bind the inner puzzle to a
    specific singleton lineage.  Off-chain readers that walk the lineage
    use this struct to validate every spend.
    """
    return Program.to((SINGLETON_MOD_HASH, (launcher_id, SINGLETON_LAUNCHER_HASH)))


def singleton_full_puzzle_hash(
    launcher_id: bytes32, inner_puzzle_hash: bytes32
) -> bytes32:
    """sha256tree of the singleton wrapper around an inner puzzle.

    Equivalent to ``puzzle_for_singleton(launcher_id, inner).get_tree_hash()``
    where ``inner.get_tree_hash() == inner_puzzle_hash``.  Hand-rolled so
    it's deterministic + cheap (no Program allocation).

    NOTE: ``curry_and_treehash`` takes the tree hashes of the BARE
    arguments — it wraps each one as ``(q . arg)`` internally via
    ``curried_values_tree_hash``.  Passing pre-quoted tree hashes
    double-wraps and produces the wrong result.  ``protocol_deployment.py``
    has the same shape but the bug is masked because its tests
    self-compare; this implementation is verified against
    ``puzzle_for_singleton`` in
    ``tests/test_admin_authority_v2_launch.py``.
    """
    from chia.wallet.util.curry_and_treehash import (
        calculate_hash_of_quoted_mod_hash,
        curry_and_treehash,
    )

    quoted_mod = calculate_hash_of_quoted_mod_hash(SINGLETON_MOD_HASH)
    struct_hash = bytes32(_singleton_struct(launcher_id).get_tree_hash())
    return bytes32(
        curry_and_treehash(
            quoted_mod,
            struct_hash,
            inner_puzzle_hash,
        )
    )


def compute_launch_outputs(
    *,
    parent_coin_id: bytes32,
    eve_inner_puzzle_hash: bytes32,
    eve_amount: int = int(SINGLETON_AMOUNT),
) -> LaunchOutputs:
    """Compute every deterministic output of a v2 admin-authority launch.

    Args:
        parent_coin_id: The funding coin's ``.name()`` (i.e. coin id).
            The launcher coin is uniquely determined by this + the
            standard SINGLETON_LAUNCHER_HASH + amount, so the singleton's
            ``launcher_id`` is locked in once the operator chooses
            which funding coin to spend.
        eve_inner_puzzle_hash: sha256tree of the curried v2 inner
            puzzle (i.e. ``make_inner_puzzle_hash(...)``).  This binds
            the genesis state — admin set, MIPS quorum, version 1, etc.
        eve_amount: Mojos to give the eve coin.  Always 1 for a fresh
            launch (singletons store no value); kept parameterized for
            test flexibility.

    Returns:
        :class:`LaunchOutputs` with every coin + announcement the launch
        produces.  All values are deterministic from the inputs — no
        randomness, no signatures, no chain reads needed.
    """
    import hashlib

    launcher_coin = Coin(
        parent_coin_info=parent_coin_id,
        puzzle_hash=SINGLETON_LAUNCHER_HASH,
        amount=SINGLETON_AMOUNT,
    )
    launcher_id = bytes32(launcher_coin.name())

    eve_full_puzzle_hash = singleton_full_puzzle_hash(
        launcher_id, eve_inner_puzzle_hash
    )

    eve_coin = Coin(
        parent_coin_info=launcher_id,
        puzzle_hash=eve_full_puzzle_hash,
        amount=uint64(eve_amount),
    )

    launcher_solution = Program.to([eve_full_puzzle_hash, eve_amount, []])
    launcher_announcement_message = bytes32(launcher_solution.get_tree_hash())

    # Standard chia announcement-id formula: sha256(coin_id || message).
    # Matches what ASSERT_PUZZLE_ANNOUNCEMENT consumers expect.
    launcher_announcement_id = bytes32(
        hashlib.sha256(launcher_id + launcher_announcement_message).digest()
    )

    return LaunchOutputs(
        launcher_coin=launcher_coin,
        launcher_id=launcher_id,
        eve_inner_puzzle_hash=eve_inner_puzzle_hash,
        eve_full_puzzle_hash=eve_full_puzzle_hash,
        eve_coin=eve_coin,
        launcher_solution=launcher_solution,
        launcher_announcement_message=launcher_announcement_message,
        launcher_announcement_id=launcher_announcement_id,
    )


# ─────────────────────────────────────────────────────────────────────────
# Spend builders.
#
# Each builder returns the SOLUTION program ready to feed into
# ``curried.run(solution)`` (in tests) or to attach to a CoinSpend (in
# production deployments).
# ─────────────────────────────────────────────────────────────────────────


def build_operational_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    mips_puzzle_reveal: Program,
    mips_solution: Program,
) -> Program:
    """Build the solution for an OPERATIONAL spend (tag 0x01).

    The shim runs ``(a mips_puzzle_reveal mips_solution)`` to obtain the
    user-authorised conditions, verifies sha256tree(mips_puzzle_reveal)
    matches the curried MIPS_ROOT_HASH, and wraps them with the shim's
    own self-recurry + announcement conditions.

    Args:
        my_amount: singleton coin amount (must be odd; identity assert).
        new_authority_version: exactly current AUTHORITY_VERSION + 1.
        mips_puzzle_reveal: the MIPS m_of_n tree (or any puzzle whose
            tree-hash matches MIPS_ROOT_HASH). For testing this can be a
            trivial constant puzzle.
        mips_solution: solution that, when run against the reveal,
            produces the conditions the shim wraps. For a constant
            puzzle this is typically nil.

    Returns:
        Program ready for ``curried.run(...)``.
    """
    return Program.to(
        [
            SPEND_OPERATIONAL,
            my_amount,
            new_authority_version,
            [mips_puzzle_reveal, mips_solution],
        ]
    )


def build_admin_roster_update_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_authority_version: int | None = None,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    current_mips_reveal: Program,
    current_mips_solution: Program,
    new_admin: AdminRecord,
    new_mips_root_hash: bytes32,
) -> Program:
    current_admins_tuple = tuple(current_admins)
    current_pending_ops_tuple = tuple(current_pending_ops)
    new_admins_hash = compute_admins_hash(current_admins_tuple + (new_admin,))
    current_mips_root_hash = bytes32(current_mips_reveal.get_tree_hash())
    if current_authority_version is None:
        current_authority_version = new_authority_version - 1
    compute_roster_update_binding_hash(
        current_mips_root_hash=current_mips_root_hash,
        current_admins_hash=compute_admins_hash(current_admins_tuple),
        current_pending_ops_hash=compute_pending_ops_hash(current_pending_ops_tuple),
        current_authority_version=current_authority_version,
        new_admins_hash=new_admins_hash,
        new_mips_root_hash=new_mips_root_hash,
        new_authority_version=new_authority_version,
    )
    return Program.to(
        [
            SPEND_ADMIN_ROSTER_UPDATE,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins_tuple],
                [p.to_program() for p in current_pending_ops_tuple],
                current_mips_reveal,
                current_mips_solution,
                new_admin.to_program(),
                new_mips_root_hash,
            ],
        ]
    )


def build_admin_slot_add_spend(
    *,
    my_amount: int,
    current_authority_version: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    current_mips_reveal: Program,
    current_mips_solution: Program,
    new_admin: AdminRecord,
    new_mips_root_hash: bytes32,
    max_admins: int = DEFAULT_MAX_ADMINS,
    max_keys_per_admin: int = DEFAULT_MAX_KEYS_PER_ADMIN,
) -> AdminRosterUpdateSpend:
    preview = build_admin_slot_add_preview(
        current_admins=current_admins,
        current_pending_ops=current_pending_ops,
        new_admin=new_admin,
        current_mips_root_hash=bytes32(current_mips_reveal.get_tree_hash()),
        new_mips_root_hash=new_mips_root_hash,
        current_authority_version=current_authority_version,
        new_authority_version=new_authority_version,
        max_admins=max_admins,
        max_keys_per_admin=max_keys_per_admin,
    )
    solution = build_admin_roster_update_solution(
        my_amount=my_amount,
        current_authority_version=current_authority_version,
        new_authority_version=preview.new_authority_version,
        current_admins=current_admins,
        current_pending_ops=current_pending_ops,
        current_mips_reveal=current_mips_reveal,
        current_mips_solution=current_mips_solution,
        new_admin=new_admin,
        new_mips_root_hash=preview.new_mips_root_hash,
    )
    return AdminRosterUpdateSpend(preview=preview, solution=solution)


def build_key_add_activate_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    op_kind: int,
    target_member_hash: bytes32,
    activates_at: int,
) -> Program:
    """Build the solution for a KEY_ADD_ACTIVATE spend (tag 0x03).

    Despite the name, this tag activates BOTH ADD and REMOVE pending ops
    (per design doc §5.8 polymorphic ACTIVATE). The op_kind discriminator
    selects which branch of the handler runs:

      OP_KIND_ADD:    appends target_member_hash to the admin's leaves.
      OP_KIND_REMOVE: removes target_member_hash from the admin's leaves.

    Permissionless spend — no signer authority required. The caller proves:
      1. The matching pending op exists in current_pending_ops_list.
      2. ASSERT_HEIGHT_ABSOLUTE activates_at — cooldown has elapsed.

    Args:
        op_kind: OP_KIND_ADD or OP_KIND_REMOVE; must match the pending op
            tuple's stored kind for lookup to succeed.
        target_member_hash: the leaf being added or removed.
        activates_at: cooldown end height; must match what was stored at
            PROPOSE / EMERGENCY time.
    """
    return Program.to(
        [
            SPEND_KEY_ADD_ACTIVATE,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                op_kind,
                target_member_hash,
                activates_at,
            ],
        ]
    )


## ─────────────────────────────────────────────────────────────────────────
## Fresh-genesis construction helpers.
## ─────────────────────────────────────────────────────────────────────────


def single_member_admin_record(
    admin_idx: int,
    member_tree_hash: bytes32,
    m_within: int = 1,
) -> AdminRecord:
    """Build a fresh-genesis AdminRecord with one authentication member."""
    return AdminRecord(
        admin_idx=admin_idx,
        leaves=(member_tree_hash,),
        m_within=m_within,
    )
@dataclass(frozen=True)
class AdminAuthorityV2State:
    """Decoded state of an admin_authority_v2 singleton at a point in time.

    Mirrors the curried [STATE] slots of admin_authority_v2_inner.clsp:
    MIPS_ROOT_HASH, ADMINS_HASH, PENDING_KEY_OPS_HASH, AUTHORITY_VERSION.

    ``admins_revealed`` and ``pending_ops_revealed`` are populated when
    parsing from the full curried puzzle reveal (and the lists provided
    by an off-chain monitor); they're tuple()/() when only the hashes
    are known.
    """

    self_mod_hash: bytes32
    max_admins: int
    max_keys_per_admin: int
    cooldown_blocks: int
    recovery_timeout_blocks: int
    sgt_governance_puzzle_hash: bytes32
    mips_root_hash: bytes32
    admins_hash: bytes32
    pending_ops_hash: bytes32
    authority_version: int
    admins_revealed: tuple[AdminRecord, ...] = ()
    pending_ops_revealed: tuple[PendingOp, ...] = ()

    @property
    def state_hash(self) -> bytes32:
        """sha256tree of the state tuple — what the on-chain announcement
        carries after the PROTOCOL_PREFIX + spend_tag bytes.
        """
        return compute_state_hash(
            self.mips_root_hash,
            self.admins_hash,
            self.pending_ops_hash,
            self.authority_version,
        )


def parse_inner_puzzle(curried_inner_puzzle: Program) -> AdminAuthorityV2State:
    """Decompose a curried v2 inner puzzle back into typed state.

    Strictly validates the uncurried mod hash before returning state —
    otherwise the caller is parsing some other puzzle that happens to
    look like ours.

    Note: this only decodes the curried params (10 slots). The
    revealed admins / pending-ops lists are not part of the curried
    puzzle hash; they're supplied per-spend via solution and the
    state-hash check enforces consistency. Use the dedicated state
    fields ``admins_revealed`` / ``pending_ops_revealed`` if the
    caller has them from off-chain monitoring.

    Raises:
        ValueError: if the puzzle is not an instance of
            ``admin_authority_v2_inner.clsp``.
    """
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != admin_authority_v2_inner_mod_hash():
        raise ValueError(
            f"puzzle mod hash {mod.get_tree_hash().hex()} does not match "
            f"admin_authority_v2_inner.clsp ({admin_authority_v2_inner_mod_hash().hex()})"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 10:
        raise ValueError(
            f"v2 inner puzzle has wrong number of curried args: "
            f"expected 10, got {len(args_list)}"
        )
    return AdminAuthorityV2State(
        self_mod_hash=bytes32(args_list[0].atom),
        max_admins=int(args_list[1].as_int()),
        max_keys_per_admin=int(args_list[2].as_int()),
        cooldown_blocks=int(args_list[3].as_int()),
        recovery_timeout_blocks=int(args_list[4].as_int()),
        sgt_governance_puzzle_hash=bytes32(args_list[5].atom),
        mips_root_hash=bytes32(args_list[6].atom),
        admins_hash=bytes32(args_list[7].atom),
        pending_ops_hash=bytes32(args_list[8].atom),
        authority_version=int(args_list[9].as_int()),
    )


def build_key_remove_emergency_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    approving_member_reveal: Program,
    approving_member_solution: Program,
    removed_member_hash: bytes32,
    current_block_height: int,
) -> Program:
    """Build the solution for a KEY_REMOVE_EMERGENCY spend (tag 0x06).

    Single-leaf authority + long cooldown (RECOVERY_TIMEOUT_BLOCKS).
    Use case: \"I lost my passkey, please remove the passkey eventually.\"
    The long cooldown gives a vigilant compromised-key attacker time
    to be vetoed by other leaves before the removal lands.

    Compared to KEY_REMOVE_QUORUM (which requires m_within co-signers
    but is instant), this trades immediacy for single-key UX. Admins
    with only one leaf cannot use this — I-2 invariant prevents
    emptying the OneOfN.

    State changes:
      - admins_list unchanged at PROPOSE time. Removal happens at
        ACTIVATE time (tag 0x03 with op_kind=OP_KIND_REMOVE).
      - A new pending REMOVE op appended with
        activates_at = current_block_height + RECOVERY_TIMEOUT_BLOCKS.
    """
    return Program.to(
        [
            SPEND_KEY_REMOVE_EMERGENCY,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                approving_member_reveal,
                approving_member_solution,
                removed_member_hash,
                current_block_height,
            ],
        ]
    )


def build_key_remove_quorum_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    admin_idx: int,
    removed_member_hash: bytes32,
    approving_pairs: Sequence[tuple[Program, Program]],
) -> Program:
    """Build the solution for a KEY_REMOVE_QUORUM spend (tag 0x05).

    Removing a leaf is destructive (lockout-risking); this spend
    requires m_within distinct co-signers from the SAME admin's OneOfN.
    A compromised key alone cannot remove other keys (T-KEY-3
    mitigation in design doc threat model).

    Args:
        approving_pairs: list of (member_reveal, member_solution)
            cons-pairs. Must contain at least m_within DISTINCT members
            of the affected admin's leaves; duplicates are rejected by
            the on-chain aggregator.
    """
    # Construct cons-pairs as Programs. Each pair is (reveal . solution),
    # which Program.to((reveal, solution)) builds correctly.
    pairs_program = Program.to(
        [(reveal, solution) for reveal, solution in approving_pairs]
    )
    return Program.to(
        [
            SPEND_KEY_REMOVE_QUORUM,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                admin_idx,
                removed_member_hash,
                pairs_program,
            ],
        ]
    )


def build_key_add_veto_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    approving_member_reveal: Program,
    approving_member_solution: Program,
    target_member_hash: bytes32,
    activates_at: int,
) -> Program:
    """Build the solution for a KEY_ADD_VETO spend (tag 0x04).

    Wide authority — ANY leaf of the affected admin's OneOfN can veto a
    pending ADD. This maximises the chance a legitimate user catches a
    malicious add during cooldown: even if the attacker compromised the
    leaf used at PROPOSE, the user's other leaves can still cancel.

    Args:
        target_member_hash: the leaf whose pending ADD is being cancelled
            (must match what was stored at PROPOSE).
        activates_at: cooldown end height (must match stored pending op).
    """
    return Program.to(
        [
            SPEND_KEY_ADD_VETO,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                approving_member_reveal,
                approving_member_solution,
                target_member_hash,
                activates_at,
            ],
        ]
    )


def build_key_add_propose_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    approving_member_reveal: Program,
    approving_member_solution: Program,
    new_member_hash: bytes32,
    current_block_height: int,
) -> Program:
    """Build the solution for a KEY_ADD_PROPOSE spend (tag 0x02).

    The shim verifies the approving member is in the affected admin's
    OneOfN, runs the member to capture its emitted signature conditions,
    binds the spend's confirmation to ``[current_block_height,
    current_block_height + PROPOSE_WINDOW)`` via height assertions,
    then appends a new pending ADD op with
    ``activates_at = current_block_height + COOLDOWN_BLOCKS``.

    The signature-binding to the rotation intent is the off-chain
    builder's responsibility: the ``approving_member_solution`` should
    be constructed such that the member's signature targets exactly
    ``sha256(admin_idx . OP_KIND_ADD . new_member_hash . activates_at)``.
    For testing the puzzle's structural behaviour (not signature
    cryptography), any solution that produces emittable conditions is
    fine.

    Args:
        my_amount: singleton coin amount.
        new_authority_version: exactly current + 1.
        current_admins: revealed full admins list whose sha256tree must
            match the curried ADMINS_HASH.
        current_pending_ops: revealed full pending-ops list whose
            sha256tree must match the curried PENDING_KEY_OPS_HASH.
        admin_idx: which admin slot is gaining the leaf.
        approving_member_reveal: puzzle reveal of one leaf in admin's
            OneOfN whose tree hash is in that admin's leaves list.
        approving_member_solution: solution to run against the member.
        new_member_hash: 32-byte tree hash of the member to be added.
        current_block_height: user-claimed block height; the puzzle
            binds confirmation to this value via ASSERT_HEIGHT_ABSOLUTE
            + ASSERT_BEFORE_HEIGHT_ABSOLUTE so a malicious caller can't
            choose a stale value to bypass the cooldown.
    """
    return Program.to(
        [
            SPEND_KEY_ADD_PROPOSE,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                approving_member_reveal,
                approving_member_solution,
                new_member_hash,
                current_block_height,
            ],
        ]
    )
