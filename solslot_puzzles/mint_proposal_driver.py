"""Python driver for mint_proposal_inner.clsp (A.1) — DEPRECATED.

.. deprecated:: Phase 9-Hermes-D

    This V1 driver is superseded by
    :mod:`solslot_puzzles.mint_proposal_v2_driver`, which targets the
    MIPS-pluggable :file:`mint_proposal_inner_v2.clsp`.  V2 replaces
    V1's hard-coded BLS ``OWNER_PUBKEY`` / ``GOV_PUBKEY`` with
    CHIP-0043 member tree hashes so a single deployment can mix BLS,
    Eip712Member (EVM), passkey, etc. member types.

    State-machine semantics (DRAFT → APPROVED / CANCELLED) are
    identical between V1 and V2; only the auth surface differs.

    All new mint-proposal work — including Phase 4 publish flow,
    Phase 5 execute flow, and the future APPROVED → EXECUTED cross-
    coin coordination link with ``governance_singleton_inner.clsp``
    — uses V2 exclusively.

    V1 remains in :data:`solslot_puzzles.PUZZLE_FILENAMES` to avoid a
    frozen-checksum bump in this brick; a future "V1 mint-proposal
    retirement" brick will remove it atomically with a checksum
    refreeze.

    Importing this module emits a :class:`DeprecationWarning`.

Each Populis mint proposal is a per-proposal singleton coin whose
state evolves through the puzzle's state machine.  The launcher_id is
the proposal id; the singleton's lineage IS the audit log.

V1 scope (matches the puzzle):

    DRAFT  ──gov-sig──▶  APPROVED
       │
       │ owner-sig
       ▼
    CANCELLED

What this module exposes:
  * State + transition constants matching the .clsp file.
  * ``compute_proposal_data_hash`` — the off-chain canonical hash that
    the API publishes alongside the launcher id; mirrors the puzzle's
    PROPOSAL_DATA_HASH curry so anyone can re-verify "the proposal at
    launcher_id X has fields {property, par, royalty, quorum} = …" by
    walking the launcher coin's spend bundle.
  * ``compute_signing_message`` — what each transition's AGG_SIG_ME binds.
  * ``compute_transition_message`` — the off-chain announcement payload.
  * ``make_inner_puzzle`` / ``make_inner_puzzle_hash``.
  * ``parse_inner_puzzle`` — decompose a curried inner puzzle into typed state.
  * ``build_approve_spend`` / ``build_cancel_spend``.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle

warnings.warn(
    "solslot_puzzles.mint_proposal_driver (V1) is deprecated; use "
    "solslot_puzzles.mint_proposal_v2_driver instead. See the module "
    "docstring for migration notes.",
    DeprecationWarning,
    stacklevel=2,
)


# ─── Constants (kept in lock-step with mint_proposal_inner.clsp) ──────────

STATE_DRAFT = 1
STATE_APPROVED = 2
STATE_CANCELLED = 3
STATE_NAMES = {
    STATE_DRAFT: "DRAFT",
    STATE_APPROVED: "APPROVED",
    STATE_CANCELLED: "CANCELLED",
}

TRANSITION_APPROVE = 0x61  # 'a'
TRANSITION_CANCEL = 0x63  # 'c'


_MINT_PROPOSAL_INNER_MOD: Program | None = None


def mint_proposal_inner_mod() -> Program:
    """Return the compiled (uncurried) ``mint_proposal_inner.clsp`` Program."""
    global _MINT_PROPOSAL_INNER_MOD
    if _MINT_PROPOSAL_INNER_MOD is None:
        _MINT_PROPOSAL_INNER_MOD = load_puzzle("mint_proposal_inner.clsp")
    return _MINT_PROPOSAL_INNER_MOD


def mint_proposal_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried mod (curried into proposals as ``SELF_MOD_HASH``)."""
    return bytes32(mint_proposal_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Proposal data hash — the off-chain ↔ on-chain content commitment.
# ─────────────────────────────────────────────────────────────────────────


def compute_proposal_data_hash(
    *,
    property_id_canon: bytes32,
    par_value_mojos: int,
    royalty_bps: int,
    quorum_threshold: int,
) -> bytes32:
    """Deterministic 32-byte commitment over a proposal's immutable fields.

    Mirrors the curried ``PROPOSAL_DATA_HASH`` slot.  The puzzle treats
    this as opaque bytes — it never needs to inspect the underlying
    fields — but binds it into the curried state so:

      * Two proposals with the same launcher pubkey but different fields
        yield different inner puzzle hashes; their on-chain coins are
        unrelated.
      * Anyone walking the launcher coin's spend bundle (which reveals
        the curried args) can re-verify "this proposal claims fields F"
        against the published off-chain data without trusting the API.

    The hash construction is sha256tree over the values in declaration
    order — the exact Python expression below is the canonical form;
    do not change it without bumping every existing on-chain singleton.

    Args:
        property_id_canon: bytes32 produced by
            ``property_registry_driver.canonicalise_property_id``.
        par_value_mojos: par value in mojos (uint64).
        royalty_bps: royalty in basis points (0–10000 inclusive, but
            range is enforced off-chain — the puzzle treats it as opaque).
        quorum_threshold: PGT vote-quorum threshold for execution.

    Returns:
        Deterministic bytes32 commitment.
    """
    if len(property_id_canon) != 32:
        raise ValueError(
            f"property_id_canon must be 32 bytes, got {len(property_id_canon)}"
        )
    if par_value_mojos < 0:
        raise ValueError(f"par_value_mojos must be ≥ 0, got {par_value_mojos}")
    if royalty_bps < 0:
        raise ValueError(f"royalty_bps must be ≥ 0, got {royalty_bps}")
    if quorum_threshold < 0:
        raise ValueError(
            f"quorum_threshold must be ≥ 0, got {quorum_threshold}"
        )
    program = Program.to(
        [property_id_canon, par_value_mojos, royalty_bps, quorum_threshold]
    )
    return bytes32(program.get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Signing & announcement messages.
# ─────────────────────────────────────────────────────────────────────────


def compute_signing_message(transition_case: int, new_state_version: int) -> bytes32:
    """The message a transition's AGG_SIG_ME binds.

    Mirrors the puzzle's ``signing-message`` defun.  Binding to BOTH
    the transition case AND the new version slot prevents replay of a
    stolen signature against a different transition or version.
    """
    return bytes32(
        Program.to([transition_case, new_state_version]).get_tree_hash()
    )


def compute_transition_message(
    transition_case: int,
    new_state: int,
    new_state_version: int,
) -> bytes32:
    """The body of the CREATE_PUZZLE_ANNOUNCEMENT message (without prefix).

    Mirrors the puzzle's ``transition-message`` defun.  Off-chain
    consumers (the API indexer) use this value, prefixed with the
    PROTOCOL_PREFIX byte (0x50), to identify and update cached state.
    """
    return bytes32(
        Program.to([transition_case, new_state, new_state_version]).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    *,
    owner_pubkey: bytes,
    gov_pubkey: bytes,
    proposal_data_hash: bytes32,
    proposal_state: int,
    state_version: int,
) -> Program:
    """Curry the inner puzzle for a specific proposal state.

    Currying order MUST match ``mint_proposal_inner.clsp``:

        SELF_MOD_HASH, OWNER_PUBKEY, GOV_PUBKEY, PROPOSAL_DATA_HASH,
        PROPOSAL_STATE, STATE_VERSION
    """
    if len(owner_pubkey) != 48:
        raise ValueError(
            f"owner_pubkey must be 48 bytes (BLS G1), got {len(owner_pubkey)}"
        )
    if len(gov_pubkey) != 48:
        raise ValueError(
            f"gov_pubkey must be 48 bytes (BLS G1), got {len(gov_pubkey)}"
        )
    if len(proposal_data_hash) != 32:
        raise ValueError(
            f"proposal_data_hash must be 32 bytes, got {len(proposal_data_hash)}"
        )
    if proposal_state not in STATE_NAMES:
        raise ValueError(
            f"proposal_state must be one of {sorted(STATE_NAMES)}, got {proposal_state}"
        )
    if state_version < 0:
        raise ValueError(
            f"state_version must be ≥ 0, got {state_version}"
        )
    return mint_proposal_inner_mod().curry(
        mint_proposal_inner_mod_hash(),
        owner_pubkey,
        gov_pubkey,
        proposal_data_hash,
        proposal_state,
        state_version,
    )


def make_inner_puzzle_hash(
    *,
    owner_pubkey: bytes,
    gov_pubkey: bytes,
    proposal_data_hash: bytes32,
    proposal_state: int,
    state_version: int,
) -> bytes32:
    """Tree hash of the curried inner puzzle."""
    return bytes32(
        make_inner_puzzle(
            owner_pubkey=owner_pubkey,
            gov_pubkey=gov_pubkey,
            proposal_data_hash=proposal_data_hash,
            proposal_state=proposal_state,
            state_version=state_version,
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# State parsing.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MintProposalState:
    """Decoded curried state of a mint-proposal singleton."""

    self_mod_hash: bytes32
    owner_pubkey: bytes
    gov_pubkey: bytes
    proposal_data_hash: bytes32
    proposal_state: int
    state_version: int

    @property
    def state_name(self) -> str:
        return STATE_NAMES.get(self.proposal_state, f"UNKNOWN({self.proposal_state})")

    @property
    def is_draft(self) -> bool:
        return self.proposal_state == STATE_DRAFT

    @property
    def is_approved(self) -> bool:
        return self.proposal_state == STATE_APPROVED

    @property
    def is_cancelled(self) -> bool:
        return self.proposal_state == STATE_CANCELLED

    @property
    def is_terminal(self) -> bool:
        """True if no further V1 transitions are possible from this state."""
        return self.proposal_state in (STATE_APPROVED, STATE_CANCELLED)


def parse_inner_puzzle(curried_inner_puzzle: Program) -> MintProposalState:
    """Decompose a curried inner puzzle back into typed state."""
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != mint_proposal_inner_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate mint_proposal_inner.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{mint_proposal_inner_mod_hash().hex()}"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 6:
        raise ValueError(
            f"mint_proposal_inner expects 6 curried args, got {len(args_list)}"
        )
    self_mod_hash = bytes32(args_list[0].as_atom())
    owner_pubkey = bytes(args_list[1].as_atom())
    gov_pubkey = bytes(args_list[2].as_atom())
    proposal_data_hash = bytes32(args_list[3].as_atom())
    proposal_state = int(args_list[4].as_int())
    state_version = int(args_list[5].as_int())
    if len(owner_pubkey) != 48:
        raise ValueError(
            f"owner_pubkey must be 48 bytes (BLS G1), got {len(owner_pubkey)}"
        )
    if len(gov_pubkey) != 48:
        raise ValueError(
            f"gov_pubkey must be 48 bytes (BLS G1), got {len(gov_pubkey)}"
        )
    if proposal_state not in STATE_NAMES:
        raise ValueError(
            f"unknown proposal_state {proposal_state} (valid: {sorted(STATE_NAMES)})"
        )
    return MintProposalState(
        self_mod_hash=self_mod_hash,
        owner_pubkey=owner_pubkey,
        gov_pubkey=gov_pubkey,
        proposal_data_hash=proposal_data_hash,
        proposal_state=proposal_state,
        state_version=state_version,
    )


# ─────────────────────────────────────────────────────────────────────────
# Transition spends.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TransitionSpendArtifacts:
    """Bundle of artifacts an operator needs to drive a transition spend."""

    inner_solution: Program
    new_inner_puzzle_hash: bytes32
    """Puzzle hash of the post-transition singleton inner puzzle."""
    new_state: int
    """The proposal_state value the singleton transitions INTO."""
    agg_sig_me_message: bytes32
    """What the per-transition signer (gov for APPROVE, owner for CANCEL) signs."""
    transition_announcement_message: bytes
    """Full announcement body — ``PROTOCOL_PREFIX (0x50) || transition_msg``.

    Off-chain indexers ASSERT or scan for this exact bytes value to
    update cached state.
    """


def _build_transition(
    *,
    current: MintProposalState,
    transition_case: int,
    new_state: int,
    new_state_version: int,
    my_amount: int,
) -> TransitionSpendArtifacts:
    """Shared transition-spend builder."""
    if not current.is_draft:
        raise ValueError(
            f"V1 only allows transitions from DRAFT, current state is "
            f"{current.state_name}"
        )
    if new_state_version <= current.state_version:
        raise ValueError(
            f"new_state_version must be > current.state_version "
            f"({new_state_version} <= {current.state_version})"
        )
    if my_amount % 2 == 0:
        raise ValueError(
            f"singleton amount must be odd (got {my_amount})"
        )

    new_inner_puzzle_hash = make_inner_puzzle_hash(
        owner_pubkey=current.owner_pubkey,
        gov_pubkey=current.gov_pubkey,
        proposal_data_hash=current.proposal_data_hash,
        proposal_state=new_state,
        state_version=new_state_version,
    )
    agg_sig_me_message = compute_signing_message(
        transition_case=transition_case,
        new_state_version=new_state_version,
    )
    inner_solution = Program.to(
        [my_amount, transition_case, new_state_version]
    )
    transition_msg = compute_transition_message(
        transition_case=transition_case,
        new_state=new_state,
        new_state_version=new_state_version,
    )
    transition_announcement_message = b"\x50" + bytes(transition_msg)
    return TransitionSpendArtifacts(
        inner_solution=inner_solution,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        new_state=new_state,
        agg_sig_me_message=agg_sig_me_message,
        transition_announcement_message=transition_announcement_message,
    )


def build_approve_spend(
    *,
    current: MintProposalState,
    new_state_version: int,
    my_amount: int,
) -> TransitionSpendArtifacts:
    """Build a DRAFT → APPROVED spend.  Signed by GOV_PUBKEY."""
    return _build_transition(
        current=current,
        transition_case=TRANSITION_APPROVE,
        new_state=STATE_APPROVED,
        new_state_version=new_state_version,
        my_amount=my_amount,
    )


def build_cancel_spend(
    *,
    current: MintProposalState,
    new_state_version: int,
    my_amount: int,
) -> TransitionSpendArtifacts:
    """Build a DRAFT → CANCELLED spend.  Signed by OWNER_PUBKEY."""
    return _build_transition(
        current=current,
        transition_case=TRANSITION_CANCEL,
        new_state=STATE_CANCELLED,
        new_state_version=new_state_version,
        my_amount=my_amount,
    )


__all__ = [
    "STATE_APPROVED",
    "STATE_CANCELLED",
    "STATE_DRAFT",
    "STATE_NAMES",
    "TRANSITION_APPROVE",
    "TRANSITION_CANCEL",
    "MintProposalState",
    "TransitionSpendArtifacts",
    "build_approve_spend",
    "build_cancel_spend",
    "compute_proposal_data_hash",
    "compute_signing_message",
    "compute_transition_message",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "mint_proposal_inner_mod",
    "mint_proposal_inner_mod_hash",
    "parse_inner_puzzle",
]
