"""Python driver helpers for the Solslot Governance Token (SGT).

SGT is a CAT2 token with a fixed-supply genesis-by-coin-id TAIL.  Every SGT
coin carries the solslot governance machinery as its CAT inner puzzle:

  - sgt_free_inner.clsp wraps SGT in TRANSFER / LOCK modes (free state).
  - sgt_locked_inner.clsp wraps SGT in RELEASE_DEADLINE / RELEASE_EXEC modes
    (locked state, committed to a specific proposal).

This module exposes:

  - sgt_tail_puzzle / sgt_tail_hash         — TAIL construction
  - sgt_free_inner_puzzle / sgt_free_inner_hash
  - sgt_locked_inner_puzzle / sgt_locked_inner_hash
  - make_cat_truths                         — synthetic Truths for unit tests
  - PROPOSAL_TRACKER_STRUCT helper          — singleton struct factory
"""
from __future__ import annotations

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs import CoinSpend
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle


# ── Module-level caches of the compiled programs ─────────────────────────────
_SGT_TAIL_MOD: Program | None = None
_SGT_FREE_INNER_MOD: Program | None = None
_SGT_LOCKED_INNER_MOD: Program | None = None
_TRACKER_MOD: Program | None = None
_TRACKER_V2_MOD: Program | None = None


def proposal_tracker_mod() -> Program:
    """Return the compiled (uncurried) governance_singleton_inner.clsp Program.

    This is the v2 governance puzzle ("proposal tracker") with SGT-backed
    voting.  It replaces the legacy raw-vote_weight puzzle (CRITICAL-3 audit fix).
    """
    global _TRACKER_MOD
    if _TRACKER_MOD is None:
        _TRACKER_MOD = load_puzzle("governance_singleton_inner.clsp")
    return _TRACKER_MOD


def proposal_tracker_v2_mod() -> Program:
    """Return the RC22 tracker with typed statutes bill dispatch."""
    global _TRACKER_V2_MOD
    if _TRACKER_V2_MOD is None:
        _TRACKER_V2_MOD = load_puzzle("governance_singleton_inner_v2.clsp")
    return _TRACKER_V2_MOD


def sgt_tail_mod() -> Program:
    """Return the compiled (uncurried) sgt_tail.clsp Program."""
    global _SGT_TAIL_MOD
    if _SGT_TAIL_MOD is None:
        _SGT_TAIL_MOD = load_puzzle("sgt_tail.clsp")
    return _SGT_TAIL_MOD


def sgt_free_inner_mod() -> Program:
    """Return the compiled (uncurried) sgt_free_inner.clsp Program."""
    global _SGT_FREE_INNER_MOD
    if _SGT_FREE_INNER_MOD is None:
        _SGT_FREE_INNER_MOD = load_puzzle("sgt_free_inner.clsp")
    return _SGT_FREE_INNER_MOD


def sgt_locked_inner_mod() -> Program:
    """Return the compiled (uncurried) sgt_locked_inner.clsp Program."""
    global _SGT_LOCKED_INNER_MOD
    if _SGT_LOCKED_INNER_MOD is None:
        _SGT_LOCKED_INNER_MOD = load_puzzle("sgt_locked_inner.clsp")
    return _SGT_LOCKED_INNER_MOD


# ── SGT spend-case constants (must match the .clsp `defconstant`s) ───────────
SGT_TRANSFER = 1
SGT_LOCK = 2

SGT_RELEASE_DEADLINE = 1
SGT_RELEASE_EXEC = 2

# Proposal tracker spend cases
TRK_PROPOSE = 1
TRK_VOTE = 2
TRK_EXECUTE = 3
TRK_EXPIRE = 4

# Bill operation tags (single ASCII bytes)
BILL_MINT = b"M"           # 0x4d
BILL_FREEZE = b"F"         # 0x46
BILL_SETTLE = b"S"         # 0x53
BILL_REDEMPTION = b"D"     # 0x44 — fund permanent wUSDC.b deed offers
BILL_VAULT_VERSION = b"V"  # 0x56 — ratify a vault_version_registry code change
BILL_PARAMETER = b"P"
BILL_COLLECTION = b"N"
BILL_ORACLE = b"O"
BILL_ROUTE = b"R"
BILL_PAUSE = b"U"
REDEMPTION_FUND_TAG = b"RDF1"

# Solslot announcement namespace prefix (utility_macros.clib PROTOCOL_PREFIX).
PROTOCOL_PREFIX = bytes.fromhex("53")  # "S"

# vault_version_registry_inner.clsp routine-path approval tag ("RT").  The
# governance tracker's EXECUTE of a VAULT_VERSION bill emits a puzzle
# announcement with message PROTOCOL_PREFIX || REGISTRY_TAG_ROUTINE ||
# content_hash, which the registry's SPEND_CODE_ROUTINE asserts.  MUST equal
# both governance_singleton_inner.clsp `REGISTRY_TAG_ROUTINE` and
# vault_version_registry_inner.clsp `TAG_ROUTINE`.
REGISTRY_TAG_ROUTINE = bytes.fromhex("5254")  # "RT"

# Dedicated MINT execution co-signer namespace. This public test vector is
# deliberately exported for deterministic fixtures only; deployment plans must
# provide their own nonzero co-signer public key.
KOS_MINT_EXECUTE_TAG = bytes.fromhex("4b4f534d")  # "KOSM"
ADMIN_PROPOSAL_TAG = bytes.fromhex("474f5650")  # "GOVP"
TEST_KOS_MINT_EXECUTE_PUBKEY = bytes.fromhex(
    "ac5669419e8eb7d00814692207ddf331e45835ee441260f6309fd564e7e92a60"
    "555e5be793654a9b5f949c7f74de8174"
)


# ── Singleton-struct construction ────────────────────────────────────────────
SINGLETON_LAUNCHER_HASH = bytes32.fromhex(
    "eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9"
)


def make_proposal_tracker_struct(
    singleton_mod_hash: bytes32,
    tracker_launcher_id: bytes32,
    launcher_puzzle_hash: bytes32 = SINGLETON_LAUNCHER_HASH,
) -> Program:
    """Build the PROPOSAL_TRACKER_STRUCT used by the SGT inner puzzles.

    Layout: (SINGLETON_MOD_HASH (TRACKER_LAUNCHER_ID . LAUNCHER_PUZZLE_HASH)).
    Same shape as Chia's standard SINGLETON_STRUCT.
    """
    return Program.to((singleton_mod_hash, (tracker_launcher_id, launcher_puzzle_hash)))


def sgt_tail_puzzle(genesis_coin_id: bytes32) -> Program:
    """Return the SGT TAIL curried with the given genesis coin id.

    Args:
        genesis_coin_id: bytes32 coin id of the unique XCH coin that bootstraps
            SGT into circulation at protocol launch.

    Returns:
        Curried TAIL Program.  Its tree hash is the value used as TOKEN_TAIL_HASH
        in any contract that curries the SGT tail (e.g. governance, vote escrow).
    """
    if not isinstance(genesis_coin_id, bytes) or len(genesis_coin_id) != 32:
        raise ValueError("genesis_coin_id must be 32 bytes")
    return sgt_tail_mod().curry(genesis_coin_id)


def sgt_tail_hash(genesis_coin_id: bytes32) -> bytes32:
    """Return the puzzle tree hash of the curried SGT TAIL."""
    return sgt_tail_puzzle(genesis_coin_id).get_tree_hash()


# ── SGT free-state inner puzzle ──────────────────────────────────────────────
def sgt_free_inner_puzzle(
    locked_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
) -> Program:
    """Curry sgt_free_inner.clsp for a specific SGT owner.

    Args:
        locked_mod_hash: tree hash of the (uncurried) sgt_locked_inner module
            — needed for re-curry computations on LOCK transitions.
        proposal_tracker_struct: singleton struct of the proposal tracker.
        inner_puzzle_hash: the owner's user puzzle hash (e.g. p2_delegated).

    Returns:
        A curried sgt_free_inner Program.  Wrap it in CAT2(SGT_TAIL_HASH, ...)
        to get the on-chain puzzle.
    """
    mod = sgt_free_inner_mod()
    mod_hash = mod.get_tree_hash()
    return mod.curry(
        mod_hash,
        locked_mod_hash,
        proposal_tracker_struct,
        inner_puzzle_hash,
    )


def sgt_free_inner_hash(
    locked_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
) -> bytes32:
    """Tree hash of the curried sgt_free_inner.  Used to derive CAT puzzle hash."""
    return sgt_free_inner_puzzle(
        locked_mod_hash, proposal_tracker_struct, inner_puzzle_hash
    ).get_tree_hash()


# ── SGT locked-state inner puzzle ────────────────────────────────────────────
def sgt_locked_inner_puzzle(
    free_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
    lock_proposal_hash: bytes32,
    lock_deadline: int,
) -> Program:
    """Curry sgt_locked_inner.clsp for a specific locked SGT coin."""
    mod = sgt_locked_inner_mod()
    mod_hash = mod.get_tree_hash()
    return mod.curry(
        mod_hash,
        free_mod_hash,
        proposal_tracker_struct,
        inner_puzzle_hash,
        lock_proposal_hash,
        lock_deadline,
    )


def sgt_locked_inner_hash(
    free_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
    lock_proposal_hash: bytes32,
    lock_deadline: int,
) -> bytes32:
    return sgt_locked_inner_puzzle(
        free_mod_hash,
        proposal_tracker_struct,
        inner_puzzle_hash,
        lock_proposal_hash,
        lock_deadline,
    ).get_tree_hash()


# ── Proposal tracker singleton inner puzzle ──────────────────────────────────
def proposal_tracker_inner_puzzle(
    singleton_struct: Program,
    sgt_free_mod_hash: bytes32,
    sgt_locked_mod_hash: bytes32,
    cat_mod_hash: bytes32,
    sgt_tail_hash: bytes32,
    protocol_did_puzhash: bytes32,
    pool_singleton_struct: Program,
    quorum_bps: int,
    voting_window_seconds: int,
    sgt_total_supply: int,
    min_proposal_stake: int,
    kos_mint_execute_pubkey: bytes,
    proposal_hash: int = 0,
    bill_operation: int = 0,
    vote_tally: int = 0,
    voting_deadline: int = 0,
) -> Program:
    """Curry the proposal tracker singleton inner puzzle.

    All immutable params come first, followed by the four state fields
    (proposal_hash, bill_operation, vote_tally, voting_deadline).  When idle,
    the four state fields are 0; when an active proposal exists, they hold
    the proposal hash, the bill tuple, the accumulated SGT mojos, and the
    voting deadline (absolute seconds).

    `min_proposal_stake` is the minimum first-vote SGT mojos required to
    open a new proposal (anti-spam; the locked SGT is returned on EXEC or
    EXPIRE so this is a stake-deposit, not a fee).  Suggested testnet
    default: 10_000 (= 1% of 1M SGT total supply).
    """
    if len(kos_mint_execute_pubkey) != 48:
        raise ValueError("kos_mint_execute_pubkey must be 48 bytes")
    mod = proposal_tracker_mod()
    mod_hash = mod.get_tree_hash()
    return mod.curry(
        mod_hash,
        singleton_struct,
        sgt_free_mod_hash,
        sgt_locked_mod_hash,
        cat_mod_hash,
        sgt_tail_hash,
        protocol_did_puzhash,
        pool_singleton_struct,
        quorum_bps,
        voting_window_seconds,
        sgt_total_supply,
        min_proposal_stake,
        kos_mint_execute_pubkey,
        proposal_hash,
        bill_operation,
        vote_tally,
        voting_deadline,
    )


def proposal_tracker_inner_hash(*args, **kwargs) -> bytes32:
    return proposal_tracker_inner_puzzle(*args, **kwargs).get_tree_hash()


def proposal_tracker_v2_inner_puzzle(
    singleton_struct: Program,
    sgt_free_mod_hash: bytes32,
    sgt_locked_mod_hash: bytes32,
    cat_mod_hash: bytes32,
    sgt_tail_hash: bytes32,
    protocol_did_puzhash: bytes32,
    pool_singleton_struct: Program,
    admin_authority_struct: Program,
    quorum_bps: int,
    voting_window_seconds: int,
    sgt_total_supply: int,
    min_proposal_stake: int,
    kos_mint_execute_pubkey: bytes,
    proposal_hash: int | bytes32 = 0,
    bill_operation: int | Program = 0,
    vote_tally: int = 0,
    voting_deadline: int = 0,
) -> Program:
    """Curry the RC22 tracker while preserving the RC20 tracker API."""
    if len(kos_mint_execute_pubkey) != 48:
        raise ValueError("kos_mint_execute_pubkey must be 48 bytes")
    mod = proposal_tracker_v2_mod()
    return mod.curry(
        mod.get_tree_hash(),
        singleton_struct,
        sgt_free_mod_hash,
        sgt_locked_mod_hash,
        cat_mod_hash,
        sgt_tail_hash,
        protocol_did_puzhash,
        pool_singleton_struct,
        admin_authority_struct,
        quorum_bps,
        voting_window_seconds,
        sgt_total_supply,
        min_proposal_stake,
        kos_mint_execute_pubkey,
        proposal_hash,
        bill_operation,
        vote_tally,
        voting_deadline,
    )


def proposal_tracker_v2_inner_hash(*args, **kwargs) -> bytes32:
    return proposal_tracker_v2_inner_puzzle(*args, **kwargs).get_tree_hash()


def kos_mint_execute_message(
    *,
    governance_singleton_struct: Program,
    governance_coin_id: bytes32,
    proposal_hash: bytes32,
) -> bytes:
    """Return the exact visible MINT co-signer condition message.

    The governance puzzle emits this only for a MINT execution.  It commits to
    the immutable governance singleton structure, the live singleton coin, and
    the approved proposal hash.  Consensus appends AGG_SIG_ME additional data
    when forming the BLS signing message.
    """
    governance_coin_id = _require_b32(governance_coin_id, "governance_coin_id")
    proposal_hash = _require_b32(proposal_hash, "proposal_hash")
    struct_hash = bytes32(governance_singleton_struct.get_tree_hash())
    return (
        PROTOCOL_PREFIX
        + KOS_MINT_EXECUTE_TAG
        + bytes(Program.to([struct_hash, governance_coin_id, proposal_hash]).get_tree_hash())
    )


def kos_mint_execute_signing_message(
    *,
    governance_singleton_struct: Program,
    governance_coin_id: bytes32,
    proposal_hash: bytes32,
    agg_sig_me_additional_data: bytes,
) -> bytes:
    """Return the full testnet/mainnet-specific AGG_SIG_ME BLS message."""
    if len(agg_sig_me_additional_data) != 32:
        raise ValueError("agg_sig_me_additional_data must be 32 bytes")
    return kos_mint_execute_message(
        governance_singleton_struct=governance_singleton_struct,
        governance_coin_id=governance_coin_id,
        proposal_hash=proposal_hash,
    ) + bytes(governance_coin_id) + bytes(agg_sig_me_additional_data)


# ── Bill operation builders ──────────────────────────────────────────────────
def _require_b32(value: bytes | bytes32, name: str) -> bytes32:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    return bytes32(raw)


def bill_mint(
    deed_full_puzzle_hash: bytes32,
    property_id_canon: bytes32,
    property_registry_puzzle_hash: bytes32,
) -> Program:
    """MINT bill: approve spawning a deed and bind its property registry context.

    Layout: ``(M deed_full_puzzle_hash property_id_canon
    property_registry_puzzle_hash)``.  ``governance_singleton_inner.clsp`` still
    dispatches MINT by reading the first payload slot as ``deed_full_puzzle_hash``;
    the two extra slots are part of ``sha256tree(bill)`` so voters and the API
    bind the proposal to the A4 property-registry record that the portal used.

    All three values are mandatory.  A shorter legacy bill cannot satisfy the
    registry announcement asserted by the governance puzzle and is rejected
    before a spend is built.
    """
    deed_full_puzzle_hash = _require_b32(deed_full_puzzle_hash, "deed_full_puzzle_hash")
    property_id_canon = _require_b32(
        property_id_canon, "property_id_canon"
    )
    property_registry_puzzle_hash = _require_b32(
        property_registry_puzzle_hash,
        "property_registry_puzzle_hash",
    )
    return Program.to(
        (
            BILL_MINT,
            (
                deed_full_puzzle_hash,
                (property_id_canon, (property_registry_puzzle_hash, 0)),
            ),
        )
    )


def bill_freeze(new_pool_status: int) -> Program:
    """FREEZE bill: governance toggles pool status (0 = FROZEN, 1 = ACTIVE)."""
    return Program.to((BILL_FREEZE, (new_pool_status, 0)))


def deed_releases_hash(deed_releases) -> bytes32:
    """Return ``sha256tree(deed_releases)`` for governance settlement binding."""
    return bytes32(Program.to(deed_releases).get_tree_hash())


def bill_settle(
    splitxch_root: bytes32,
    total_amount: int,
    num_deeds: int,
    deed_releases_hash: bytes32,
) -> Program:
    """SETTLE bill: governance approves a specific batch settlement release set."""
    if len(deed_releases_hash) != 32:
        raise ValueError("deed_releases_hash must be 32 bytes")
    return Program.to(
        (
            BILL_SETTLE,
            (splitxch_root, (total_amount, (num_deeds, (deed_releases_hash, 0)))),
        )
    )


def bill_funded_redemption(
    *,
    collection_id: bytes32,
    settlement_id: bytes32,
    payment_asset_id: bytes32,
    total_payment_amount: int,
    deed_count: int,
    allocations_root: bytes32,
) -> Program:
    """Approve exact funding for permanent per-deed redemption offers."""
    for label, value in (
        ("collection_id", collection_id),
        ("settlement_id", settlement_id),
        ("payment_asset_id", payment_asset_id),
        ("allocations_root", allocations_root),
    ):
        _require_b32(value, label)
    if not 0 < total_payment_amount < 2**64:
        raise ValueError("total_payment_amount must be a positive uint64")
    if not 0 < deed_count < 2**64:
        raise ValueError("deed_count must be a positive uint64")
    return Program.to(
        [
            BILL_REDEMPTION,
            collection_id,
            settlement_id,
            payment_asset_id,
            total_payment_amount,
            deed_count,
            allocations_root,
        ]
    )


def funded_redemption_message_hash(
    *,
    collection_id: bytes32,
    settlement_id: bytes32,
    payment_asset_id: bytes32,
    total_payment_amount: int,
    deed_count: int,
    allocations_root: bytes32,
) -> bytes32:
    """Message paired by the governed non-withdrawable redemption treasury."""
    bill = bill_funded_redemption(
        collection_id=collection_id,
        settlement_id=settlement_id,
        payment_asset_id=payment_asset_id,
        total_payment_amount=total_payment_amount,
        deed_count=deed_count,
        allocations_root=allocations_root,
    )
    values = list(bill.as_iter())
    return bytes32(
        Program.to([REDEMPTION_FUND_TAG, *values[1:]]).get_tree_hash()
    )


def bill_vault_version(
    new_vault_inner_mod_hash: bytes32,
    new_canonical_params_hash: bytes32,
    new_vault_version: int,
) -> Program:
    """VAULT_VERSION bill: SGT quorum ratifies a vault-version registry CODE change.

    The bill carries the next registry state ``(code, params, version)`` so the
    proposal hash (``sha256tree(bill)``) binds it at PROPOSE time and the
    tracker's EXECUTE can reconstruct the registry's content hash.  On EXECUTE,
    ``dispatch_bill`` emits ``CREATE_PUZZLE_ANNOUNCEMENT`` with message
    :func:`vault_version_approval_message`, which the
    ``vault_version_registry_inner.clsp`` SPEND_CODE_ROUTINE asserts.

    Layout ``(V . (code . (params . (version . 0))))`` so the puzzle's
    ``(f (r bill_op))`` / ``(f (r (r bill_op)))`` / ``(f (r (r (r bill_op))))``
    pick ``code`` / ``params`` / ``version`` respectively.
    """
    for name, value in (
        ("new_vault_inner_mod_hash", new_vault_inner_mod_hash),
        ("new_canonical_params_hash", new_canonical_params_hash),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes, got {len(value)}")
    return Program.to(
        (
            BILL_VAULT_VERSION,
            (new_vault_inner_mod_hash, (new_canonical_params_hash, (new_vault_version, 0))),
        )
    )


def vault_version_content_hash(
    new_vault_inner_mod_hash: bytes32,
    new_canonical_params_hash: bytes32,
    new_vault_version: int,
) -> bytes32:
    """``sha256tree([code, params, version])`` — the registry's content hash.

    MUST equal ``vault_version_registry_driver.compute_content_hash`` and the
    on-chain ``(sha256tree (list ...))`` the governance dispatch emits.
    """
    return bytes32(
        Program.to(
            [new_vault_inner_mod_hash, new_canonical_params_hash, new_vault_version]
        ).get_tree_hash()
    )


def vault_version_approval_message(
    new_vault_inner_mod_hash: bytes32,
    new_canonical_params_hash: bytes32,
    new_vault_version: int,
) -> bytes:
    """The CREATE_PUZZLE_ANNOUNCEMENT message governance EXECUTE emits.

    ``PROTOCOL_PREFIX || REGISTRY_TAG_ROUTINE || content_hash`` — byte-identical
    to ``vault_version_registry_driver.compute_approval_message(path_tag=TAG_ROUTINE)``
    so the registry's ASSERT_PUZZLE_ANNOUNCEMENT (keyed by the governance coin's
    full puzzle hash) pairs with it.
    """
    return (
        PROTOCOL_PREFIX
        + REGISTRY_TAG_ROUTINE
        + bytes(
            vault_version_content_hash(
                new_vault_inner_mod_hash, new_canonical_params_hash, new_vault_version
            )
        )
    )


def proposal_hash_from_bill(bill: Program) -> bytes32:
    """The proposal hash is sha256tree of the bill operation."""
    return bytes32(bill.get_tree_hash())


def admin_governance_proposal_message(proposal_hash: bytes32) -> bytes:
    """Announcement body emitted by the co-spent admin-authority operation."""
    proposal_hash = _require_b32(proposal_hash, "proposal_hash")
    return PROTOCOL_PREFIX + ADMIN_PROPOSAL_TAG + bytes(proposal_hash)


# ── Tracker EXECUTE coin spend (singleton-wrapped) ──────────────────────────
def build_tracker_execute_coin_spend(
    *,
    tracker_coin: Coin,
    tracker_inner_puzzle: Program,
    tracker_launcher_id: bytes32,
    lineage_proof: LineageProof,
) -> CoinSpend:
    """Singleton-wrapped EXECUTE spend for the governance proposal tracker.

    ``tracker_inner_puzzle`` must already be curried into its OPEN/executable
    state — an active proposal whose ``VOTE_TALLY`` meets quorum and whose
    ``VOTING_DEADLINE`` has passed (``ASSERT_SECONDS_ABSOLUTE`` is emitted, so
    the spending block's timestamp must be at or after the deadline).  EXECUTE
    dispatches the curried bill and resets the tracker to IDLE:

      * MINT/FREEZE/SETTLE  -> emits the bill's ``SEND_MESSAGE`` to DID/pool.
      * VAULT_VERSION       -> emits the routine-path ``CREATE_PUZZLE_ANNOUNCEMENT``
        the co-spent ``vault_version_registry`` SPEND_CODE_ROUTINE asserts
        (see :func:`vault_version_approval_message`).

    Generic across bill types.  The inner solution layout matches
    ``governance_singleton_inner.clsp``'s dispatcher:
    ``(my_id my_inner_puzzlehash my_amount TRK_EXECUTE ())``.  EXECUTE takes no
    extra params, so the trailing element is ``()``.
    """
    inner_solution = Program.to(
        [
            tracker_coin.name(),
            tracker_inner_puzzle.get_tree_hash(),
            tracker_coin.amount,
            TRK_EXECUTE,
            0,
        ]
    )
    full_puzzle = puzzle_for_singleton(tracker_launcher_id, tracker_inner_puzzle)
    full_solution = solution_for_singleton(
        lineage_proof, uint64(tracker_coin.amount), inner_solution
    )
    return make_spend(tracker_coin, full_puzzle, full_solution)


# ── Tracker VOTE coin spend (singleton-wrapped) ─────────────────────────────
def build_tracker_vote_coin_spend(
    *,
    tracker_coin: Coin,
    tracker_inner_puzzle: Program,
    tracker_launcher_id: bytes32,
    lineage_proof: LineageProof,
    voter_inner_puzzle_hash: bytes32,
    additional_vote_amount: int,
) -> CoinSpend:
    """Singleton-wrapped VOTE spend for the governance proposal tracker.

    ``tracker_inner_puzzle`` must already be curried into its OPEN state — an
    active proposal whose ``PROPOSAL_HASH``, ``BILL_OPERATION``, ``VOTE_TALLY``,
    and ``VOTING_DEADLINE`` are non-zero.  VOTE increases ``VOTE_TALLY`` by
    ``additional_vote_amount`` and recreates the tracker singleton in its new
    OPEN state.  The spend asserts the SGT lock announcement for
    ``(voter_inner_puzzle_hash, PROPOSAL_HASH, additional_vote_amount,
    VOTING_DEADLINE)``, so the co-spent SGT free coin MUST emit that exact
    announcement (see :func:`build_sgt_lock_coin_spend`).

    The inner solution shape mirrors ``governance_singleton_inner.clsp``'s
    dispatcher: ``(my_id my_inner_puzzlehash my_amount TRK_VOTE
    (voter_inner_puzhash additional_vote_amount))``.

    The two amount values (``additional_vote_amount`` here and the SGT lock
    ``my_amount``) MUST match — the on-chain announcement-id pairing enforces
    this.

    Args:
        tracker_coin: The current tracker singleton coin in OPEN state.
        tracker_inner_puzzle: The OPEN-state curried tracker inner puzzle.
        tracker_launcher_id: The tracker singleton's launcher id.
        lineage_proof: The lineage proof of ``tracker_coin``'s parent.
        voter_inner_puzzle_hash: The voter's inner puzzle hash — MUST match
            the SGT free coin's owner curry (so the LOCK announcement is
            produced by that user's SGT coin and not somebody else's).
        additional_vote_amount: The SGT mojos being locked to add weight to
            the proposal.  MUST be > 0 and MUST equal the co-spent SGT free
            coin's amount (LOCK is a full-coin operation).

    Returns:
        A ``CoinSpend`` ready to bundle with the matching SGT lock spend and
        push through the mempool.
    """
    if len(voter_inner_puzzle_hash) != 32:
        raise ValueError("voter_inner_puzzle_hash must be 32 bytes")
    if additional_vote_amount <= 0:
        raise ValueError("additional_vote_amount must be > 0")
    inner_solution = Program.to(
        [
            tracker_coin.name(),
            tracker_inner_puzzle.get_tree_hash(),
            tracker_coin.amount,
            TRK_VOTE,
            [voter_inner_puzzle_hash, additional_vote_amount],
        ]
    )
    full_puzzle = puzzle_for_singleton(tracker_launcher_id, tracker_inner_puzzle)
    full_solution = solution_for_singleton(
        lineage_proof, uint64(tracker_coin.amount), inner_solution
    )
    return make_spend(tracker_coin, full_puzzle, full_solution)


# ── SGT LOCK coin spend (CAT2-wrapped sgt_free_inner) ────────────────────────
def build_sgt_lock_coin_spend(
    *,
    sgt_coin: Coin,
    voter_inner_puzzle: Program,
    voter_inner_solution: Program,
    proposal_tracker_struct: Program,
    sgt_tail_hash: bytes32,
    lineage_proof: LineageProof,
    proposal_hash: bytes32,
    deadline: int,
) -> CoinSpend:
    """CAT2-wrapped sgt_free_inner LOCK CoinSpend.

    Builds the on-chain spend of a free SGT coin owned by ``voter_inner_puzzle``
    that locks ``sgt_coin.amount`` SGT mojos to ``proposal_hash`` until
    ``deadline`` (absolute seconds).  The spend emits the LOCK announcement
    the governance tracker's PROPOSE/VOTE handler asserts.

    The voter's ``voter_inner_puzzle`` retains full authority over what the
    LOCK destination looks like — the only constraint is that running it on
    ``voter_inner_solution`` must yield a single ``CREATE_COIN`` whose
    puzzle hash equals the canonical ``sgt_locked_inner`` puzhash for
    ``(proposal_tracker_struct, voter_inner_puzzle_hash, proposal_hash,
    deadline)`` and whose amount equals ``sgt_coin.amount``.  Any other
    inner conditions (e.g. ``AGG_SIG_ME`` for the wallet's signature) pass
    through unchanged.

    LOCK is a full-coin operation: ``extra_delta = 0`` so the CAT2
    conservation invariant holds without melting supply.  Callers that want
    to lock less than their full SGT coin must split it first via a
    TRANSFER spend.

    Args:
        sgt_coin: The free SGT coin to lock.  Its puzzle hash MUST equal
            ``cat_sgt_free_puzzle_hash(...)`` with the same
            ``proposal_tracker_struct``, ``sgt_tail_hash``, and
            ``voter_inner_puzzle.get_tree_hash()``.
        voter_inner_puzzle: The reveal of the SGT owner's inner puzzle
            (e.g. ``p2_delegated_puzzle_or_hidden_puzzle``).  Its tree hash
            MUST equal the ``INNER_PUZZLE_HASH`` curried into the SGT free
            inner that produced ``sgt_coin``.
        voter_inner_solution: The owner's signed inner solution.  It must
            yield exactly one ``CREATE_COIN`` to the canonical locked
            puzhash with ``amount == sgt_coin.amount``.
        proposal_tracker_struct: Singleton struct of the governance tracker
            (same one curried into the SGT inner mods).
        sgt_tail_hash: Tree hash of the curried SGT TAIL (CAT2's
            ``limitations_program_hash``).
        lineage_proof: Lineage proof of the SGT coin's parent (so the CAT2
            outer can verify the lineage chain back to the issuance).
        proposal_hash: 32-byte ``sha256tree(bill_operation)`` of the open
            proposal we're voting on.
        deadline: Absolute seconds (uint64) of the proposal's voting
            deadline.  The LOCK spend asserts
            ``ASSERT_BEFORE_SECONDS_ABSOLUTE deadline``, so the locking
            block's timestamp must be strictly less than ``deadline``.

    Returns:
        A single ``CoinSpend`` (the CAT2-wrapped SGT free coin spend).  The
        caller bundles this with the matching tracker PROPOSE/VOTE spend
        and any lineage-providing parent spends, then asks the wallet to
        sign for the inner ``AGG_SIG_ME`` conditions and pushes the bundle.
    """
    if len(proposal_hash) != 32:
        raise ValueError("proposal_hash must be 32 bytes")
    if not isinstance(deadline, int) or deadline < 0 or deadline > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("deadline must be a uint64")

    sgt_locked_mod_h = bytes32(sgt_locked_inner_mod().get_tree_hash())
    voter_inner_ph = bytes32(voter_inner_puzzle.get_tree_hash())
    free_inner = sgt_free_inner_puzzle(
        sgt_locked_mod_h, proposal_tracker_struct, voter_inner_ph
    )

    # sgt_free_inner solution shape:
    #   (spend_case inner_puzzle inner_solution case_args)
    # case_args for LOCK: (proposal_hash deadline my_amount)
    free_inner_solution = Program.to(
        [
            SGT_LOCK,
            voter_inner_puzzle,
            voter_inner_solution,
            [proposal_hash, deadline, sgt_coin.amount],
        ]
    )

    spendable = SpendableCAT(
        coin=sgt_coin,
        limitations_program_hash=sgt_tail_hash,
        inner_puzzle=free_inner,
        inner_solution=free_inner_solution,
        lineage_proof=lineage_proof,
        extra_delta=0,
    )
    bundle = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [spendable])
    if len(bundle.coin_spends) != 1:
        raise RuntimeError(
            f"unsigned_spend_bundle_for_spendable_cats returned "
            f"{len(bundle.coin_spends)} spends, expected 1"
        )
    return bundle.coin_spends[0]


# ── CAT-wrapped SGT helpers (for tests / drivers building announcements) ─────
def cat_sgt_free_puzzle_hash(
    singleton_struct: Program,
    sgt_free_mod_hash: bytes32,
    sgt_locked_mod_hash: bytes32,
    cat_mod_hash: bytes32,
    sgt_tail_hash: bytes32,
    voter_inner_puzzle_hash: bytes32,
) -> bytes32:
    """Compute the on-chain puzzle hash of a CAT-wrapped SGT free coin owned
    by the given voter.  This is the announcement sender id used by the
    proposal tracker when asserting LOCK announcements.

    Mirrors the CLVM `curry_hashes` chain in governance_singleton_inner's
    `cat_sgt_free_puzhash` helper:

        curry_hashes(CAT_MOD_HASH,
            sha256(1, CAT_MOD_HASH),
            sha256(1, SGT_TAIL_HASH),
            curry_hashes(SGT_FREE_MOD_HASH,
                sha256(1, SGT_FREE_MOD_HASH),
                sha256(1, SGT_LOCKED_MOD_HASH),
                sha256tree(SINGLETON_STRUCT),
                sha256(1, voter_inner_puzhash)))

    Note that the puzzle uses raw `(sha256 1 X)` (not `tree_hash((q . X))`)
    for atom params, so we replicate that pattern here using the simple
    `curry_hashes` algorithm, NOT chia's standard `curry_and_treehash`
    which assumes `(q . X)` form.
    """
    import hashlib

    def sha256_pre(b: bytes) -> bytes32:
        """sha256(0x01 || X) — matches `(sha256 1 X)` in chialisp."""
        return bytes32(hashlib.sha256(b"\x01" + b).digest())

    def sha256tree(prog: Program) -> bytes32:
        """Compute tree hash of any Program (atom or pair)."""
        return bytes32(prog.get_tree_hash())

    def curry_hashes(mod_hash: bytes32, *param_hashes: bytes32) -> bytes32:
        """Replicates curry.clib's curry_hashes function exactly.

        tree_hash_of_apply(mod_hash, environment_hash) where
        environment_hash = calculate_hash_of_curried_parameters(params).
        """
        # constants from curry.clib's `constant_tree`:
        sha256_one = bytes32.fromhex(
            "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
        )
        sha256_one_one = bytes32.fromhex(
            "9dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2"
        )
        # `(concat 2 (sha256 1 #a))` — used as prefix for `tree_hash_of_apply`
        two_sha256_one_a_kw = bytes.fromhex(
            "02a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222"
        )
        # `(concat 2 (sha256 1 #c))` — prefix for `update_hash_for_parameter_hash`
        two_sha256_one_c_kw = bytes.fromhex(
            "02a8d5dd63fba471ebcb1f3e8f7c1e1879b7152a6e7298a91ce119a63400ade7c5"
        )

        def hash_expression_F(a1: bytes, a2: bytes) -> bytes:
            # tree_hash of `((q . a1) a2)` given a1, a2 are the param values
            return hashlib.sha256(
                b"\x02"
                + hashlib.sha256(b"\x02" + sha256_one_one + a1).digest()
                + hashlib.sha256(b"\x02" + a2 + sha256_one).digest()
            ).digest()

        # Build environment hash recursively from right.
        env_hash = sha256_one_one  # tree_hash of `1` (the env)
        for ph in reversed(param_hashes):
            env_hash = hashlib.sha256(
                two_sha256_one_c_kw + hash_expression_F(ph, env_hash)
            ).digest()

        # Final apply: `(a (q . mod_hash) env)`
        return bytes32(
            hashlib.sha256(two_sha256_one_a_kw + hash_expression_F(mod_hash, env_hash)).digest()
        )

    # Inner: curry(SGT_FREE_MOD, SGT_FREE_MOD_HASH, SGT_LOCKED_MOD_HASH,
    #              SINGLETON_STRUCT, voter_inner_puzhash)
    sgt_free_h = curry_hashes(
        sgt_free_mod_hash,
        sha256_pre(sgt_free_mod_hash),
        sha256_pre(sgt_locked_mod_hash),
        sha256tree(singleton_struct),
        sha256_pre(voter_inner_puzzle_hash),
    )

    # Outer: curry(CAT_MOD, CAT_MOD_HASH, TAIL_HASH, INNER_HASH)
    return curry_hashes(
        cat_mod_hash,
        sha256_pre(cat_mod_hash),
        sha256_pre(sgt_tail_hash),
        sgt_free_h,
    )


# ── CAT2 Truths construction (testing helper) ────────────────────────────────
def make_cat_truths(
    inner_puzzle_hash: bytes32,
    cat_mod_hash: bytes32,
    cat_mod_hash_hash: bytes32,
    tail_hash: bytes32,
    my_id: bytes32,
    my_parent_info: bytes32,
    my_full_puzzle_hash: bytes32,
    my_amount: int,
) -> Program:
    """Build a synthetic CAT2 Truths struct for unit-testing TAIL puzzles.

    Layout (verbatim from cat_truths.clib comment):
      ((Inner_puzzle_hash . (MOD_hash . (MOD_hash_hash . TAIL_hash)))
       . (my_id . (my_parent_info my_full_puzhash my_amount)))

    cat_struct used here mirrors the 3-element layout assumed by the accessors
    (`cat_mod_hash_truth`, `cat_mod_hash_hash_truth`, `cat_tail_program_hash_truth`).
    """
    cat_struct = (cat_mod_hash, (cat_mod_hash_hash, tail_hash))
    coin_info = (my_parent_info, (my_full_puzzle_hash, (my_amount, 0)))
    truths = ((inner_puzzle_hash, cat_struct), (my_id, coin_info))
    return Program.to(truths)
