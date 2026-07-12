"""Python driver for admin_authority_inner.clsp (A.2).

The admin-authority singleton is the on-chain replacement for the
``POPULIS_ADMIN_PUBKEY_ALLOWLIST`` env var.  It carries an m-of-n
quorum allowlist of admin BLS pubkeys; rotation requires
``QUORUM_M`` valid signatures from the *current* allowlist, and a
strictly-increasing ``AUTHORITY_VERSION`` (replay protection).

What this module exposes:
  * ``compute_state_hash`` — deterministic hash of (allowlist, m, version)
    that signers commit to.  Mirrors the on-chain ``state-hash`` defun.
  * ``make_inner_puzzle`` / ``make_inner_puzzle_hash`` — construct the
    curried puzzle for a given allowlist state.
  * ``parse_inner_puzzle`` — recover typed state from a puzzle reveal.
  * ``build_rotation_spend`` — build the inner-puzzle solution and
    derive the AGG_SIG_ME message every signer must sign.

Cross-repo contract: the off-chain ``compute_state_hash`` here MUST
exactly equal what the on-chain ``state-hash`` defun produces.  The
test suite enforces this via ``test_state_hash_matches_on_chain``.

The matching API integration lives in
``populis_api/populis_api/admin_authority.py``; that's where the
allowlist verification flow plugs into ``admin_auth.require_admin_jwt``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle


# ── Module-level cache of the compiled program ──────────────────────────
_ADMIN_AUTHORITY_INNER_MOD: Program | None = None


def admin_authority_inner_mod() -> Program:
    """Return the compiled (uncurried) ``admin_authority_inner.clsp`` Program."""
    global _ADMIN_AUTHORITY_INNER_MOD
    if _ADMIN_AUTHORITY_INNER_MOD is None:
        _ADMIN_AUTHORITY_INNER_MOD = load_puzzle("admin_authority_inner.clsp")
    return _ADMIN_AUTHORITY_INNER_MOD


def admin_authority_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod (used as ``SELF_MOD_HASH`` curried arg)."""
    return bytes32(admin_authority_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# State hash — the off-chain ↔ on-chain binding point.
# ─────────────────────────────────────────────────────────────────────────


def compute_state_hash(
    allowlist: Sequence[bytes],
    quorum_m: int,
    authority_version: int,
) -> bytes32:
    """Deterministic hash of the allowlist state tuple.

    MUST match the on-chain Chialisp ``state-hash`` defun in
    ``admin_authority_inner.clsp``.  Each signer's AGG_SIG_ME signature
    commits to this hash, so divergence between off-chain and on-chain
    representation would silently invalidate every rotation signature.

    Args:
        allowlist: ordered list of admin BLS G1 pubkeys (48 bytes each).
            Order matters — ``signer_indices`` in a rotation spend
            references positions in this list.
        quorum_m: minimum signatures required (1..len(allowlist)).
        authority_version: monotonic uint, replay-attack guard.

    Returns:
        bytes32 sha256-tree hash of ``(allowlist quorum_m authority_version)``.
    """
    state_program = Program.to(
        [
            list(allowlist),
            quorum_m,
            authority_version,
        ]
    )
    return bytes32(state_program.get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    allowlist: Sequence[bytes],
    quorum_m: int,
    authority_version: int,
) -> Program:
    """Curry the inner puzzle for a specific authority state.

    Currying order MUST match ``admin_authority_inner.clsp``:

        SELF_MOD_HASH, ALLOWLIST, QUORUM_M, AUTHORITY_VERSION

    Args:
        allowlist: see :func:`compute_state_hash`.
        quorum_m: see :func:`compute_state_hash`.
        authority_version: see :func:`compute_state_hash`.

    Returns:
        Curried Program ready to be wrapped by the singleton top layer.
    """
    if quorum_m < 1 or quorum_m > len(allowlist):
        raise ValueError(
            f"quorum_m must be in [1, {len(allowlist)}], got {quorum_m}"
        )
    for i, pk in enumerate(allowlist):
        if len(pk) != 48:
            raise ValueError(
                f"allowlist[{i}] must be 48-byte BLS G1 pubkey, got {len(pk)} bytes"
            )
    # POP-CANON-017 preflight: reject duplicate pubkeys before the on-chain
    # `has-no-duplicates` guard would refuse the spend.  Fails fast and gives
    # a friendlier error (the on-chain failure is just a generic CLVM raise).
    seen: set[bytes] = set()
    for i, pk in enumerate(allowlist):
        if bytes(pk) in seen:
            raise ValueError(
                f"allowlist contains duplicate pubkey at index {i}: "
                f"{bytes(pk).hex()[:16]}… "
                f"— a duplicate would dilute the effective quorum below "
                f"the cardinality you appear to be committing to."
            )
        seen.add(bytes(pk))
    return admin_authority_inner_mod().curry(
        admin_authority_inner_mod_hash(),
        list(allowlist),
        quorum_m,
        authority_version,
    )


def make_inner_puzzle_hash(
    allowlist: Sequence[bytes],
    quorum_m: int,
    authority_version: int,
) -> bytes32:
    """Tree hash of the curried inner puzzle."""
    return bytes32(
        make_inner_puzzle(
            allowlist=allowlist,
            quorum_m=quorum_m,
            authority_version=authority_version,
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# State parsing — recover typed state from an on-chain puzzle reveal.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AdminAuthorityState:
    """Decoded state of an admin-authority singleton."""

    self_mod_hash: bytes32
    allowlist: tuple[bytes, ...]
    quorum_m: int
    authority_version: int

    @property
    def state_hash(self) -> bytes32:
        return compute_state_hash(
            allowlist=self.allowlist,
            quorum_m=self.quorum_m,
            authority_version=self.authority_version,
        )

    def has_member(self, pubkey: bytes) -> bool:
        return bytes(pubkey) in self.allowlist


def parse_inner_puzzle(curried_inner_puzzle: Program) -> AdminAuthorityState:
    """Decompose a curried inner puzzle back into typed state.

    Strictly validates the uncurried mod hash before returning state —
    otherwise the caller is parsing some other puzzle that happens to
    look like ours.

    Raises:
        ValueError: if the puzzle is not an instance of
            ``admin_authority_inner.clsp`` or if any field has the wrong
            type / length.
    """
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != admin_authority_inner_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate admin_authority_inner.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{admin_authority_inner_mod_hash().hex()}"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 4:
        raise ValueError(
            f"admin_authority_inner expects 4 curried args, got {len(args_list)}"
        )
    self_mod_hash = bytes32(args_list[0].as_atom())
    allowlist_program = args_list[1]
    quorum_m = int(args_list[2].as_int())
    authority_version = int(args_list[3].as_int())

    allowlist: list[bytes] = []
    for pk_program in allowlist_program.as_iter():
        atom = pk_program.as_atom()
        if atom is None:
            raise ValueError("allowlist entry is not an atom (BLS G1 pubkey expected)")
        if len(atom) != 48:
            raise ValueError(
                f"allowlist entry has wrong length: {len(atom)} (expected 48)"
            )
        allowlist.append(bytes(atom))

    if quorum_m < 1 or quorum_m > len(allowlist):
        raise ValueError(
            f"quorum_m={quorum_m} out of range [1, {len(allowlist)}]"
        )

    return AdminAuthorityState(
        self_mod_hash=self_mod_hash,
        allowlist=tuple(allowlist),
        quorum_m=quorum_m,
        authority_version=authority_version,
    )


# ─────────────────────────────────────────────────────────────────────────
# Rotation spend.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RotationSpendArtifacts:
    """Bundle of artifacts an operator needs to drive a rotation spend."""

    inner_solution: Program
    """Solution to feed into the curried inner puzzle."""

    new_inner_puzzle_hash: bytes32
    """Tree hash of the next-state inner puzzle (CREATE_COIN destination)."""

    agg_sig_me_message: bytes32
    """Pre-AGG_SIG_ME message that EVERY signer must sign.

    The on-chain puzzle emits ``AGG_SIG_ME pubkey_at_index <message>``
    for each entry in ``signer_indices``; signers all commit to the
    same message (the new state hash), so reviewers can independently
    verify what was authorised.
    """

    new_state_hash: bytes32
    """Public state hash for the new state — what the API will see in
    the ``CREATE_PUZZLE_ANNOUNCEMENT`` after the spend confirms."""


def build_rotation_spend(
    *,
    current: AdminAuthorityState,
    new_allowlist: Sequence[bytes],
    new_quorum_m: int,
    new_authority_version: int,
    signer_indices: Sequence[int],
    my_amount: int,
) -> RotationSpendArtifacts:
    """Construct the inner-puzzle solution + signing message for a rotation.

    Pre-flight checks (replicated from the on-chain assertions so the
    caller fails fast in Python rather than getting an opaque CLVM
    panic at spend time):

        * ``new_authority_version > current.authority_version``
        * ``1 ≤ new_quorum_m ≤ len(new_allowlist)``
        * ``len(signer_indices) ≥ current.quorum_m``
        * ``signer_indices`` is sorted strictly ascending (no dupes)
        * each index < ``len(current.allowlist)``
        * ``my_amount`` is odd (singleton convention)

    Args:
        current: pre-rotation state, as returned by
            :func:`parse_inner_puzzle`.
        new_allowlist: replacement list of admin pubkeys.
        new_quorum_m: replacement quorum threshold.
        new_authority_version: must strictly exceed
            ``current.authority_version``.
        signer_indices: indices into ``current.allowlist`` for the
            signers participating in this rotation.  Length must be
            ≥ ``current.quorum_m``.
        my_amount: singleton coin amount (odd integer).

    Returns:
        :class:`RotationSpendArtifacts` with the inner solution, the
        next-state puzzle hash, the AGG_SIG_ME message every signer
        must sign, and the public state hash.

    Raises:
        ValueError: on any pre-flight check failure.
    """
    if new_authority_version <= current.authority_version:
        raise ValueError(
            "new_authority_version must strictly exceed current "
            f"(got new={new_authority_version} current="
            f"{current.authority_version})"
        )
    if new_quorum_m < 1 or new_quorum_m > len(new_allowlist):
        raise ValueError(
            f"new_quorum_m must be in [1, {len(new_allowlist)}], "
            f"got {new_quorum_m}"
        )
    for i, pk in enumerate(new_allowlist):
        if len(pk) != 48:
            raise ValueError(
                f"new_allowlist[{i}] must be 48-byte BLS G1 pubkey, "
                f"got {len(pk)} bytes"
            )
    # POP-CANON-017 preflight (matches `has-no-duplicates` on-chain guard).
    seen: set[bytes] = set()
    for i, pk in enumerate(new_allowlist):
        if bytes(pk) in seen:
            raise ValueError(
                f"new_allowlist contains duplicate pubkey at index {i}: "
                f"{bytes(pk).hex()[:16]}… "
                f"— a duplicate would dilute the effective quorum below "
                f"the cardinality you appear to be committing to."
            )
        seen.add(bytes(pk))

    if len(signer_indices) < current.quorum_m:
        raise ValueError(
            f"need ≥ {current.quorum_m} signers, got {len(signer_indices)}"
        )
    last = -1
    for idx in signer_indices:
        if idx <= last:
            raise ValueError(
                "signer_indices must be sorted strictly ascending (no dupes)"
            )
        if idx < 0 or idx >= len(current.allowlist):
            raise ValueError(
                f"signer index {idx} out of range "
                f"[0, {len(current.allowlist) - 1}]"
            )
        last = idx

    if my_amount % 2 == 0:
        raise ValueError(
            f"singleton amount must be odd (got {my_amount})"
        )

    new_state_hash = compute_state_hash(
        allowlist=new_allowlist,
        quorum_m=new_quorum_m,
        authority_version=new_authority_version,
    )
    new_inner_puzzle_hash = make_inner_puzzle_hash(
        allowlist=new_allowlist,
        quorum_m=new_quorum_m,
        authority_version=new_authority_version,
    )

    inner_solution = Program.to(
        [
            my_amount,
            list(new_allowlist),
            new_quorum_m,
            new_authority_version,
            list(signer_indices),
        ]
    )

    return RotationSpendArtifacts(
        inner_solution=inner_solution,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        # Each signer's AGG_SIG_ME signs the new state hash directly
        # (per the puzzle's ``state-hash`` defun).
        agg_sig_me_message=new_state_hash,
        new_state_hash=new_state_hash,
    )


__all__ = [
    "AdminAuthorityState",
    "RotationSpendArtifacts",
    "admin_authority_inner_mod",
    "admin_authority_inner_mod_hash",
    "build_rotation_spend",
    "compute_state_hash",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "parse_inner_puzzle",
]
