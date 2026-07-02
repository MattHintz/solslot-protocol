"""Python driver for mint_proposal_inner_v2.clsp (A.1 v2).

Phase 9-Hermes-D refactor of ``mint_proposal_driver`` for the
MIPS-pluggable mint-proposal puzzle.  V1 hard-coded BLS pubkeys for
owner / gov; V2 takes **CHIP-0043 member tree hashes** so owner and
gov can be any member type (BLS, Eip712Member / EVM, passkey, …).

State machine semantics are unchanged from V1:

    DRAFT  ──gov-member──▶ APPROVED
       │
       │ owner-member
       ▼
    CANCELLED

What this module exposes:

  * State + transition constants matching the .clsp file.
  * ``compute_proposal_data_hash`` \u2014 the off-chain canonical hash that
    pins the proposal's immutable fields, including Pool Economic V2
    collection and deed-share metadata.
  * ``compute_binding_hash`` \u2014 the 32-byte value the curve-specific
    member verifier signs over.  Binds the signature to the specific
    transition_case + new_state_version + PROPOSAL_DATA_HASH so a
    signature collected for one transition cannot be replayed against
    another transition, version, or proposal.  This is the value off-
    chain drivers feed into the member's signing call (e.g.
    ``Delegated_Puzzle_Hash`` for Eip712Member).
  * ``compute_transition_message`` \u2014 wire-compatible with V1; what
    off-chain monitors decode from the puzzle's announcement.
  * ``make_inner_puzzle`` / ``make_inner_puzzle_hash`` \u2014 curry the
    inner with member tree hashes instead of pubkeys.
  * ``parse_inner_puzzle`` \u2014 decompose curried state for chain readers.
  * ``build_approve_spend`` / ``build_cancel_spend`` \u2014 transition
    spend artifacts including the inner solution shape (with
    member_puzzle_reveal + member_solution_remainder slots).
"""
from __future__ import annotations

from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from populis_puzzles import load_puzzle


# \u2500\u2500\u2500 Constants (kept in lock-step with mint_proposal_inner_v2.clsp) \u2500\u2500\u2500\u2500\u2500\u2500\u2500

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


_MINT_PROPOSAL_INNER_V2_MOD: Program | None = None


def mint_proposal_inner_v2_mod() -> Program:
    """Return the compiled (uncurried) ``mint_proposal_inner_v2.clsp`` Program."""
    global _MINT_PROPOSAL_INNER_V2_MOD
    if _MINT_PROPOSAL_INNER_V2_MOD is None:
        _MINT_PROPOSAL_INNER_V2_MOD = load_puzzle("mint_proposal_inner_v2.clsp")
    return _MINT_PROPOSAL_INNER_V2_MOD


def mint_proposal_inner_v2_mod_hash() -> bytes32:
    """Tree hash of the uncurried mod (curried into proposals as ``SELF_MOD_HASH``).

    Pinned value (validated by ``test_mint_proposal_v2.py``):
        0x1d3838f04de2d8b864c0b96f7f14d7fc8ec6bd39940806e2fa4087b520138517
    """
    return bytes32(mint_proposal_inner_v2_mod().get_tree_hash())


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Proposal data hash \u2014 Pool Economic V2 immutable mint terms.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


def compute_proposal_data_hash(
    *,
    property_id_canon: bytes32,
    collection_id_canon: bytes32,
    share_ppm: int,
    par_value_mojos: int,
    royalty_bps: int,
    quorum_threshold: int,
) -> bytes32:
    """Deterministic 32-byte commitment over a proposal's immutable fields.

    The V2 tuple is:
      (property_id_canon, collection_id_canon, share_ppm,
       par_value_mojos, royalty_bps, quorum_threshold)
    """
    if len(property_id_canon) != 32:
        raise ValueError(
            f"property_id_canon must be 32 bytes, got {len(property_id_canon)}"
        )
    if len(collection_id_canon) != 32:
        raise ValueError(
            f"collection_id_canon must be 32 bytes, got {len(collection_id_canon)}"
        )
    if share_ppm <= 0 or share_ppm > 1_000_000:
        raise ValueError(f"share_ppm must be in 1..1_000_000, got {share_ppm}")
    if par_value_mojos < 0:
        raise ValueError(f"par_value_mojos must be \u2265 0, got {par_value_mojos}")
    if royalty_bps < 0:
        raise ValueError(f"royalty_bps must be \u2265 0, got {royalty_bps}")
    if quorum_threshold < 0:
        raise ValueError(
            f"quorum_threshold must be \u2265 0, got {quorum_threshold}"
        )
    program = Program.to(
        [
            property_id_canon,
            collection_id_canon,
            share_ppm,
            par_value_mojos,
            royalty_bps,
            quorum_threshold,
        ]
    )
    return bytes32(program.get_tree_hash())


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Binding hash \u2014 the value the member's signature commits to.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


def compute_binding_hash(
    *,
    transition_case: int,
    new_state_version: int,
    proposal_data_hash: bytes32,
) -> bytes32:
    """The 32-byte value the curve-specific member verifier signs over.

    Mirrors the puzzle's ``binding-hash`` defun.  Binds the signature to:

      * ``transition_case`` \u2014 replay across cases (APPROVE/CANCEL) blocked.
      * ``new_state_version`` \u2014 replay across versions blocked.
      * ``proposal_data_hash`` \u2014 replay across proposals blocked.

    For Eip712Member this value is the ``Delegated_Puzzle_Hash`` slot
    in the member's solution.  For BlsMember (or any member that emits
    ``AGG_SIG_ME``) this is the message body the signature targets.

    The puzzle's V2 binding adds ``proposal_data_hash`` over V1's
    (case + version) so two copy-paste-shaped sibling proposals can't
    share signatures.
    """
    if transition_case not in (TRANSITION_APPROVE, TRANSITION_CANCEL):
        raise ValueError(
            f"transition_case must be 0x61 (APPROVE) or 0x63 (CANCEL), "
            f"got {hex(transition_case)}"
        )
    if new_state_version < 0:
        raise ValueError(
            f"new_state_version must be \u2265 0, got {new_state_version}"
        )
    if len(proposal_data_hash) != 32:
        raise ValueError(
            f"proposal_data_hash must be 32 bytes, got {len(proposal_data_hash)}"
        )
    return bytes32(
        Program.to(
            [transition_case, new_state_version, proposal_data_hash]
        ).get_tree_hash()
    )


def compute_transition_message(
    *,
    transition_case: int,
    new_state: int,
    new_state_version: int,
) -> bytes32:
    """The body of the CREATE_PUZZLE_ANNOUNCEMENT message (without prefix).

    Wire-compatible with V1's ``compute_transition_message`` \u2014 off-
    chain consumers (the API indexer) read this exact value (prefixed
    with the PROTOCOL_PREFIX byte 0x50) to update cached state.
    """
    return bytes32(
        Program.to(
            [transition_case, new_state, new_state_version]
        ).get_tree_hash()
    )


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Inner puzzle construction.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


def make_inner_puzzle(
    *,
    owner_member_hash: bytes32,
    gov_member_hash: bytes32,
    proposal_data_hash: bytes32,
    proposal_state: int,
    state_version: int,
) -> Program:
    """Curry the V2 inner puzzle for a specific proposal state.

    Currying order MUST match ``mint_proposal_inner_v2.clsp``:

        SELF_MOD_HASH, OWNER_MEMBER_HASH, GOV_MEMBER_HASH,
        PROPOSAL_DATA_HASH, PROPOSAL_STATE, STATE_VERSION

    Note the rename from V1: ``OWNER_PUBKEY`` (48-byte BLS) /
    ``GOV_PUBKEY`` (48-byte BLS) \u2192 ``OWNER_MEMBER_HASH`` (32-byte
    sha256tree) / ``GOV_MEMBER_HASH`` (32-byte sha256tree).  Member
    hashes commit to a CHIP-0043 member puzzle (Eip712Member,
    BlsMember, …); the curve-specific size + signature checks live
    inside that member, not in the proposal puzzle.
    """
    if len(owner_member_hash) != 32:
        raise ValueError(
            f"owner_member_hash must be 32 bytes, got {len(owner_member_hash)}"
        )
    if len(gov_member_hash) != 32:
        raise ValueError(
            f"gov_member_hash must be 32 bytes, got {len(gov_member_hash)}"
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
            f"state_version must be \u2265 0, got {state_version}"
        )
    return mint_proposal_inner_v2_mod().curry(
        mint_proposal_inner_v2_mod_hash(),
        owner_member_hash,
        gov_member_hash,
        proposal_data_hash,
        proposal_state,
        state_version,
    )


def make_inner_puzzle_hash(
    *,
    owner_member_hash: bytes32,
    gov_member_hash: bytes32,
    proposal_data_hash: bytes32,
    proposal_state: int,
    state_version: int,
) -> bytes32:
    """Tree hash of the curried V2 inner puzzle."""
    return bytes32(
        make_inner_puzzle(
            owner_member_hash=owner_member_hash,
            gov_member_hash=gov_member_hash,
            proposal_data_hash=proposal_data_hash,
            proposal_state=proposal_state,
            state_version=state_version,
        ).get_tree_hash()
    )


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# State parsing.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


@dataclass(frozen=True)
class MintProposalV2State:
    """Decoded curried state of a V2 mint-proposal singleton."""

    self_mod_hash: bytes32
    owner_member_hash: bytes32
    gov_member_hash: bytes32
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
        """True if no further V1-shaped transitions are possible from this state."""
        return self.proposal_state in (STATE_APPROVED, STATE_CANCELLED)


def parse_inner_puzzle(curried_inner_puzzle: Program) -> MintProposalV2State:
    """Decompose a curried V2 inner puzzle back into typed state."""
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != mint_proposal_inner_v2_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate mint_proposal_inner_v2.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{mint_proposal_inner_v2_mod_hash().hex()}"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 6:
        raise ValueError(
            f"mint_proposal_inner_v2 expects 6 curried args, got {len(args_list)}"
        )
    self_mod_hash = bytes32(args_list[0].as_atom())
    owner_member_hash = bytes32(args_list[1].as_atom())
    gov_member_hash = bytes32(args_list[2].as_atom())
    proposal_data_hash = bytes32(args_list[3].as_atom())
    proposal_state = int(args_list[4].as_int())
    state_version = int(args_list[5].as_int())
    if proposal_state not in STATE_NAMES:
        raise ValueError(
            f"unknown proposal_state {proposal_state} (valid: {sorted(STATE_NAMES)})"
        )
    return MintProposalV2State(
        self_mod_hash=self_mod_hash,
        owner_member_hash=owner_member_hash,
        gov_member_hash=gov_member_hash,
        proposal_data_hash=proposal_data_hash,
        proposal_state=proposal_state,
        state_version=state_version,
    )


# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Transition spends.
# \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500


@dataclass(frozen=True)
class TransitionSpendArtifacts:
    """Bundle of artifacts an operator needs to drive a V2 transition spend.

    The inner solution slot ``member_solution_remainder`` is the
    operator's responsibility \u2014 it depends on the curve-specific
    member's solution shape (e.g., ``(my_id signed_hash signature)``
    for Eip712Member, ``(my_id signature)`` for BlsMember).  See the
    member puzzle docs for the expected layout.
    """

    inner_solution_template: Program
    """Partial inner solution: ``(my_amount transition_case new_state_version)``.

    The operator must extend it with ``(member_puzzle_reveal
    member_solution_remainder)`` once the member's signing call has
    produced the appropriate solution tail.
    """

    new_inner_puzzle_hash: bytes32
    """Puzzle hash of the post-transition singleton inner puzzle."""

    new_state: int
    """The proposal_state value the singleton transitions INTO."""

    binding_hash: bytes32
    """The 32-byte value the member's signature commits to.

    Drivers feed this into the curve-specific signing call (e.g. the
    ``delegated_puzzle_hash`` parameter of the Eip712Member envelope).
    """

    transition_announcement_message: bytes
    """Full announcement body \u2014 ``PROTOCOL_PREFIX (0x50) || transition_msg``.

    Off-chain indexers ASSERT or scan for this exact bytes value to
    update cached state.
    """


def _build_transition(
    *,
    current: MintProposalV2State,
    transition_case: int,
    new_state: int,
    new_state_version: int,
    my_amount: int,
) -> TransitionSpendArtifacts:
    """Shared transition-spend builder."""
    if not current.is_draft:
        raise ValueError(
            f"V1 transitions require state DRAFT, current state is "
            f"{current.state_name}"
        )
    if new_state_version <= current.state_version:
        raise ValueError(
            f"new_state_version must be > current.state_version "
            f"({new_state_version} <= {current.state_version})"
        )
    if my_amount % 2 == 0:
        raise ValueError(f"singleton amount must be odd (got {my_amount})")

    new_inner_puzzle_hash = make_inner_puzzle_hash(
        owner_member_hash=current.owner_member_hash,
        gov_member_hash=current.gov_member_hash,
        proposal_data_hash=current.proposal_data_hash,
        proposal_state=new_state,
        state_version=new_state_version,
    )
    binding_hash = compute_binding_hash(
        transition_case=transition_case,
        new_state_version=new_state_version,
        proposal_data_hash=current.proposal_data_hash,
    )
    inner_solution_template = Program.to(
        [my_amount, transition_case, new_state_version]
    )
    transition_msg = compute_transition_message(
        transition_case=transition_case,
        new_state=new_state,
        new_state_version=new_state_version,
    )
    transition_announcement_message = b"\x50" + bytes(transition_msg)
    return TransitionSpendArtifacts(
        inner_solution_template=inner_solution_template,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        new_state=new_state,
        binding_hash=binding_hash,
        transition_announcement_message=transition_announcement_message,
    )


def build_approve_spend(
    *,
    current: MintProposalV2State,
    new_state_version: int,
    my_amount: int,
) -> TransitionSpendArtifacts:
    """Build a DRAFT \u2192 APPROVED spend.  Authorised by the gov member."""
    return _build_transition(
        current=current,
        transition_case=TRANSITION_APPROVE,
        new_state=STATE_APPROVED,
        new_state_version=new_state_version,
        my_amount=my_amount,
    )


def build_cancel_spend(
    *,
    current: MintProposalV2State,
    new_state_version: int,
    my_amount: int,
) -> TransitionSpendArtifacts:
    """Build a DRAFT \u2192 CANCELLED spend.  Authorised by the owner member."""
    return _build_transition(
        current=current,
        transition_case=TRANSITION_CANCEL,
        new_state=STATE_CANCELLED,
        new_state_version=new_state_version,
        my_amount=my_amount,
    )


def assemble_inner_solution(
    *,
    artifacts: TransitionSpendArtifacts,
    member_puzzle_reveal: Program,
    member_solution_remainder: Program,
) -> Program:
    """Glue the inner-solution template to a curve-specific member solution.

    Convenience helper so callers don't have to remember the exact
    slot order.  The puzzle expects the full inner solution to be:

        (my_amount transition_case new_state_version
         member_puzzle_reveal member_solution_remainder)

    The first three slots come from the artifacts; the latter two are
    operator-supplied based on which member type they're using.
    """
    template_args = list(artifacts.inner_solution_template.as_iter())
    return Program.to(
        [
            *(int(a.as_int()) if a.as_atom() else a for a in template_args),
            member_puzzle_reveal,
            member_solution_remainder,
        ]
    )


__all__ = [
    "STATE_APPROVED",
    "STATE_CANCELLED",
    "STATE_DRAFT",
    "STATE_NAMES",
    "TRANSITION_APPROVE",
    "TRANSITION_CANCEL",
    "MintProposalV2State",
    "TransitionSpendArtifacts",
    "assemble_inner_solution",
    "build_approve_spend",
    "build_cancel_spend",
    "compute_binding_hash",
    "compute_proposal_data_hash",
    "compute_transition_message",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "mint_proposal_inner_v2_mod",
    "mint_proposal_inner_v2_mod_hash",
    "parse_inner_puzzle",
]
