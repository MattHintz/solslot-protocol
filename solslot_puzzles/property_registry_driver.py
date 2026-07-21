"""Python driver for property_registry_inner.clsp (A.4).

The property-registry singleton is a uniqueness-enforced on-chain log of
canonicalised property identifiers.  The mint-publish/proposal flow consumes
the registry registration co-spend and announcement assertion in the same
bundle, so the local ``MintProposalStore`` uniqueness check is only a UI/cache
ergonomic gate rather than the mint-path authority.

Current A4 scope:
  * Append-only log; replay protection via monotonic version (which
    doubles as the registered-count).
  * Consensus uniqueness via ``REGISTERED_IDS_ROOT`` plus a full-set
    non-membership witness.  Each registration proves the supplied
    current id list hashes to the curried root, has count
    ``REGISTRY_VERSION``, and does not contain the new property id.
  * Governance-gated registrations (single AGG_SIG_ME from GOV_PUBKEY).
  * Off-chain consumers index the announcements to build a full
    registered-property set.

Future compression:
  * Replace the full-set witness with a sparse/sorted Merkle proof once
    registration volume needs sublinear witness size.  The state-root
    invariant and consensus uniqueness semantics should stay the same.

What this module exposes:
  * ``canonicalise_property_id`` — the on-chain ↔ off-chain canonical
    form contract; mirrors ``MintProposalStore.create``.
  * ``compute_signing_message`` — what GOV_PUBKEY's AGG_SIG_ME binds.
  * ``make_inner_puzzle`` / ``make_inner_puzzle_hash``.
  * ``parse_inner_puzzle`` — recover typed state.
  * ``build_registration_spend`` — solution + signing message.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle


_PROPERTY_REGISTRY_INNER_MOD: Program | None = None


def property_registry_inner_mod() -> Program:
    """Return the compiled (uncurried) ``property_registry_inner.clsp`` Program."""
    global _PROPERTY_REGISTRY_INNER_MOD
    if _PROPERTY_REGISTRY_INNER_MOD is None:
        _PROPERTY_REGISTRY_INNER_MOD = load_puzzle("property_registry_inner.clsp")
    return _PROPERTY_REGISTRY_INNER_MOD


def property_registry_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod (used as ``SELF_MOD_HASH`` curried arg)."""
    return bytes32(property_registry_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Canonicalisation — the off-chain ↔ on-chain form contract.
# ─────────────────────────────────────────────────────────────────────────


def canonicalise_property_id(human_id: str) -> bytes32:
    """Convert a human-typed property identifier into the canonical
    on-chain form.

    Pipeline:

        human_id  ──strip()──►  ──upper()──►  utf8 encode  ──sha256──►  bytes32

    The strip-and-upper canonicalisation matches the off-chain
    ``MintProposalStore.create`` (V1-CANON-014 fix) so the same human
    string always maps to the same bytes32 regardless of casing or
    surrounding whitespace.

    The sha256 step is what makes the result a fixed-length bytes32
    suitable for use as the ``property_id_canon`` puzzle parameter and
    the announcement message body.

    Args:
        human_id: The user-typed property identifier string.

    Returns:
        Deterministic bytes32 derived from the canonicalised human id.
    """
    canon = human_id.strip().upper()
    if not canon:
        raise ValueError("property_id must be non-empty after stripping whitespace")
    return bytes32(hashlib.sha256(canon.encode("utf-8")).digest())


def _as_property_id_atom(value: bytes | bytes32, field_name: str) -> bytes32:
    b = bytes(value)
    if len(b) != 32:
        raise ValueError(f"{field_name} must be 32 bytes, got {len(b)}")
    return bytes32(b)


def normalise_registered_ids(
    registered_ids: Sequence[bytes | bytes32],
) -> list[bytes32]:
    """Return ``registered_ids`` as validated bytes32 atoms."""
    return [
        _as_property_id_atom(pid, f"registered_ids[{i}]")
        for i, pid in enumerate(registered_ids)
    ]


def registered_ids_root(registered_ids: Sequence[bytes | bytes32]) -> bytes32:
    """Return ``sha256tree(registered_ids)`` for the registry state root.

    The newest id is expected at index 0.  The puzzle does not require a sorted
    order; it commits to the exact historical list and checks non-membership by
    scanning the supplied witness.
    """
    ids = normalise_registered_ids(registered_ids)
    return bytes32(Program.to(ids).get_tree_hash())


EMPTY_REGISTERED_IDS_ROOT = registered_ids_root([])


# ─────────────────────────────────────────────────────────────────────────
# Signing message.
# ─────────────────────────────────────────────────────────────────────────


def compute_signing_message(
    property_id_canon: bytes32,
    registered_ids_root: bytes32,
    new_registered_ids_root: bytes32,
    new_registry_version: int,
) -> bytes32:
    """The message GOV_PUBKEY's AGG_SIG_ME binds to.

    Mirrors the on-chain ``signing-message`` defun in
    ``property_registry_inner.clsp``.  Binding to the current root and computed
    new root means a stolen signature from one registration cannot be replayed
    against a different property set or version slot.
    """
    _as_property_id_atom(property_id_canon, "property_id_canon")
    _as_property_id_atom(registered_ids_root, "registered_ids_root")
    _as_property_id_atom(new_registered_ids_root, "new_registered_ids_root")
    msg_program = Program.to(
        [
            property_id_canon,
            registered_ids_root,
            new_registered_ids_root,
            new_registry_version,
        ]
    )
    return bytes32(msg_program.get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    gov_pubkey: bytes,
    registry_version: int,
    registered_ids_root: bytes32 = EMPTY_REGISTERED_IDS_ROOT,
) -> Program:
    """Curry the inner puzzle for a specific registry state.

    Currying order MUST match ``property_registry_inner.clsp``:

        SELF_MOD_HASH, GOV_PUBKEY, REGISTERED_IDS_ROOT, REGISTRY_VERSION
    """
    if len(gov_pubkey) != 48:
        raise ValueError(
            f"gov_pubkey must be 48 bytes (BLS G1), got {len(gov_pubkey)}"
        )
    if len(registered_ids_root) != 32:
        raise ValueError(
            f"registered_ids_root must be 32 bytes, got {len(registered_ids_root)}"
        )
    if registry_version < 0:
        raise ValueError(
            f"registry_version must be ≥ 0, got {registry_version}"
        )
    return property_registry_inner_mod().curry(
        property_registry_inner_mod_hash(),
        gov_pubkey,
        registered_ids_root,
        registry_version,
    )


def make_inner_puzzle_hash(
    gov_pubkey: bytes,
    registry_version: int,
    registered_ids_root: bytes32 = EMPTY_REGISTERED_IDS_ROOT,
) -> bytes32:
    """Tree hash of the curried inner puzzle."""
    return bytes32(
        make_inner_puzzle(
            gov_pubkey=gov_pubkey,
            registry_version=registry_version,
            registered_ids_root=registered_ids_root,
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# State parsing.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PropertyRegistryState:
    """Decoded state of a property-registry singleton."""

    self_mod_hash: bytes32
    gov_pubkey: bytes
    registered_ids_root: bytes32
    registry_version: int


def parse_inner_puzzle(curried_inner_puzzle: Program) -> PropertyRegistryState:
    """Decompose a curried inner puzzle back into typed state."""
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != property_registry_inner_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate property_registry_inner.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{property_registry_inner_mod_hash().hex()}"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 4:
        raise ValueError(
            f"property_registry_inner expects 4 curried args, got {len(args_list)}"
        )
    self_mod_hash = bytes32(args_list[0].as_atom())
    gov_pubkey = bytes(args_list[1].as_atom())
    root = bytes32(args_list[2].as_atom())
    registry_version = int(args_list[3].as_int())
    if len(gov_pubkey) != 48:
        raise ValueError(
            f"gov_pubkey must be 48 bytes (BLS G1), got {len(gov_pubkey)}"
        )
    return PropertyRegistryState(
        self_mod_hash=self_mod_hash,
        gov_pubkey=gov_pubkey,
        registered_ids_root=root,
        registry_version=registry_version,
    )


# ─────────────────────────────────────────────────────────────────────────
# Registration spend.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RegistrationSpendArtifacts:
    """Bundle of artifacts an operator needs to drive a registration spend."""

    inner_solution: Program
    new_inner_puzzle_hash: bytes32
    new_registered_ids_root: bytes32
    agg_sig_me_message: bytes32
    """What GOV_PUBKEY signs (the result of :func:`compute_signing_message`)."""
    announcement_message: bytes
    """Full announcement body — ``PROTOCOL_PREFIX (0x53) || property_id_canon``.

    Other coins ASSERT_PUZZLE_ANNOUNCEMENT this exact bytes value to
    confirm a property registration on-chain.
    """

    announcement_id: bytes32
    """Puzzle-announcement id for the current registry full puzzle hash.

    Equals ``sha256(registry_full_puzzle_hash || announcement_message)`` and is
    the value a co-spent mint-publish/proposal coin asserts with
    ``ASSERT_PUZZLE_ANNOUNCEMENT``.
    """


def build_registration_spend(
    *,
    current: PropertyRegistryState,
    property_id_canon: bytes32,
    my_amount: int,
    registered_ids: Sequence[bytes | bytes32] | None = None,
) -> RegistrationSpendArtifacts:
    """Construct the inner-puzzle solution + signing message.

    The puzzle on-chain enforces ``new_registry_version == REGISTRY_VERSION + 1``;
    we replicate that here so callers fail fast in Python.

    Args:
        current: pre-registration state (from :func:`parse_inner_puzzle`).
        property_id_canon: bytes32 produced by :func:`canonicalise_property_id`.
        my_amount: singleton coin amount (must be odd).
        registered_ids: full current registered-id witness.  Newest id first.

    Returns:
        :class:`RegistrationSpendArtifacts`.
    """
    property_id_canon = _as_property_id_atom(property_id_canon, "property_id_canon")
    if my_amount % 2 == 0:
        raise ValueError(
            f"singleton amount must be odd (got {my_amount})"
        )
    witness = normalise_registered_ids(registered_ids or [])
    witness_root = registered_ids_root(witness)
    if witness_root != current.registered_ids_root:
        raise ValueError(
            "registered_ids witness root does not match current state "
            f"(got {witness_root.hex()}, expected {current.registered_ids_root.hex()})"
        )
    if len(witness) != current.registry_version:
        raise ValueError(
            "registered_ids witness count does not match current registry_version "
            f"(got {len(witness)}, expected {current.registry_version})"
        )
    if property_id_canon in witness:
        raise ValueError("property_id_canon is already registered")

    new_registry_version = current.registry_version + 1
    new_registered_ids = [property_id_canon, *witness]
    new_registered_ids_root = registered_ids_root(new_registered_ids)
    agg_sig_me_message = compute_signing_message(
        property_id_canon=property_id_canon,
        registered_ids_root=current.registered_ids_root,
        new_registered_ids_root=new_registered_ids_root,
        new_registry_version=new_registry_version,
    )
    new_inner_puzzle_hash = make_inner_puzzle_hash(
        gov_pubkey=current.gov_pubkey,
        registered_ids_root=new_registered_ids_root,
        registry_version=new_registry_version,
    )
    inner_solution = Program.to(
        [
            my_amount,
            property_id_canon,
            witness,
            new_registry_version,
        ]
    )
    # PROTOCOL_PREFIX is 0x53 (matches utility_macros.clib).
    announcement_message = b"\x53" + bytes(property_id_canon)
    return RegistrationSpendArtifacts(
        inner_solution=inner_solution,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        new_registered_ids_root=new_registered_ids_root,
        agg_sig_me_message=agg_sig_me_message,
        announcement_message=announcement_message,
        # Inner-only callers do not know the current singleton full puzzle hash,
        # so the id is filled with the impossible zero value.  Full singleton
        # callers should use ``build_registration_coin_spend`` below.
        announcement_id=bytes32(b"\x00" * 32),
    )


def registration_announcement_message(property_id_canon: bytes | bytes32) -> bytes:
    """Return the registry announcement body for ``property_id_canon``.

    Shape is ``PROTOCOL_PREFIX || property_id_canon`` where
    ``PROTOCOL_PREFIX`` is ``0x53``.
    """
    property_id_canon = _as_property_id_atom(
        property_id_canon, "property_id_canon"
    )
    return b"\x53" + bytes(property_id_canon)


def registration_announcement_id(
    registry_full_puzzle_hash: bytes | bytes32,
    property_id_canon: bytes | bytes32,
) -> bytes32:
    """Return the ASSERT_PUZZLE_ANNOUNCEMENT id for a registry registration.

    Chia puzzle announcements are keyed by the announcing coin's puzzle hash,
    not its coin id:

        ``sha256(registry_full_puzzle_hash || (0x53 || property_id_canon))``

    This is the consensus bridge between the property-registry singleton spend
    and the mint-publish/proposal spend that consumes that registration.
    """
    registry_full_puzzle_hash = _as_property_id_atom(
        registry_full_puzzle_hash, "registry_full_puzzle_hash"
    )
    return bytes32(
        hashlib.sha256(
            bytes(registry_full_puzzle_hash)
            + registration_announcement_message(property_id_canon)
        ).digest()
    )


@dataclass(frozen=True)
class RegistrationCoinSpendArtifacts:
    """Full singleton spend for registering one property id."""

    coin_spend: CoinSpend
    inner: RegistrationSpendArtifacts
    registry_full_puzzle_hash: bytes32
    announcement_id: bytes32
    """Value a co-spent mint-publish/proposal coin must assert."""


def build_registration_coin_spend(
    *,
    registry_coin: Coin,
    registry_inner_puzzle: Program,
    registry_launcher_id: bytes32,
    lineage_proof: LineageProof,
    property_id_canon: bytes32,
    registered_ids: Sequence[bytes | bytes32] | None = None,
) -> RegistrationCoinSpendArtifacts:
    """Build the full singleton CoinSpend for a property registration.

    This wraps :func:`build_registration_spend` in chia's singleton top layer
    so callers can co-spend it with mint publish and assert the exact
    registration announcement id.
    """
    if len(registry_launcher_id) != 32:
        raise ValueError(
            f"registry_launcher_id must be 32 bytes, got {len(registry_launcher_id)}"
        )
    current = parse_inner_puzzle(registry_inner_puzzle)
    registry_full_puzzle = puzzle_for_singleton(
        registry_launcher_id, registry_inner_puzzle
    )
    registry_full_puzzle_hash = bytes32(registry_full_puzzle.get_tree_hash())
    if registry_coin.puzzle_hash != registry_full_puzzle_hash:
        raise ValueError(
            "registry coin puzzle hash does not match supplied inner puzzle "
            f"(coin={registry_coin.puzzle_hash.hex()}, "
            f"computed={registry_full_puzzle_hash.hex()})"
        )
    inner = build_registration_spend(
        current=current,
        property_id_canon=property_id_canon,
        my_amount=int(registry_coin.amount),
        registered_ids=registered_ids,
    )
    announcement_id = registration_announcement_id(
        registry_full_puzzle_hash, property_id_canon
    )
    inner = RegistrationSpendArtifacts(
        inner_solution=inner.inner_solution,
        new_inner_puzzle_hash=inner.new_inner_puzzle_hash,
        new_registered_ids_root=inner.new_registered_ids_root,
        agg_sig_me_message=inner.agg_sig_me_message,
        announcement_message=inner.announcement_message,
        announcement_id=announcement_id,
    )
    full_solution = solution_for_singleton(
        lineage_proof, uint64(registry_coin.amount), inner.inner_solution
    )
    return RegistrationCoinSpendArtifacts(
        coin_spend=make_spend(registry_coin, registry_full_puzzle, full_solution),
        inner=inner,
        registry_full_puzzle_hash=registry_full_puzzle_hash,
        announcement_id=announcement_id,
    )


__all__ = [
    "PropertyRegistryState",
    "RegistrationCoinSpendArtifacts",
    "RegistrationSpendArtifacts",
    "EMPTY_REGISTERED_IDS_ROOT",
    "build_registration_coin_spend",
    "build_registration_spend",
    "canonicalise_property_id",
    "compute_signing_message",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "normalise_registered_ids",
    "parse_inner_puzzle",
    "property_registry_inner_mod",
    "property_registry_inner_mod_hash",
    "registration_announcement_id",
    "registration_announcement_message",
    "registered_ids_root",
]
