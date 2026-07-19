"""Python driver for protocol_config_inner.clsp (A.3).

The protocol-config singleton publishes Solslot runtime configuration
on-chain.  Off-chain consumers (the API at ``/protocol``, the EIP-712
registration envelope, the frontend) bind to its deterministic
``content_hash`` instead of trusting environment variables.

This module is the single source of truth for:

  * Computing the content hash that the EIP-712 envelope's
    ``protocolConfigHash`` field commits to.
  * Constructing the curried inner puzzle for launching or updating
    the singleton.
  * Parsing an on-chain singleton's puzzle reveal back into a typed
    ``ProtocolConfigState`` dataclass.
  * Building the update-spend solution + AGG_SIG_ME message that
    governance signs.

The matching test ``tests/test_protocol_config.py`` round-trips every
function and asserts that the off-chain content hash exactly equals
the on-chain ``content-hash`` Chialisp function (no possibility of
divergence).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle


# ── Module-level cache of the compiled program ──────────────────────────
_PROTOCOL_CONFIG_INNER_MOD: Program | None = None


def protocol_config_inner_mod() -> Program:
    """Return the compiled (uncurried) ``protocol_config_inner.clsp`` Program."""
    global _PROTOCOL_CONFIG_INNER_MOD
    if _PROTOCOL_CONFIG_INNER_MOD is None:
        _PROTOCOL_CONFIG_INNER_MOD = load_puzzle("protocol_config_inner.clsp")
    return _PROTOCOL_CONFIG_INNER_MOD


def protocol_config_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod.

    Used both as the ``SELF_MOD_HASH`` curried arg (so the puzzle can
    self-recurry on update) and to verify on-chain puzzle reveals
    actually instantiate this module.
    """
    return bytes32(protocol_config_inner_mod().get_tree_hash())


# ── Network IDs ──────────────────────────────────────────────────────────
#
# We use Chia's AGG_SIG_ME genesis_challenge as the network discriminator
# because it's the same constant the rest of the protocol already binds
# signatures against.  Hardcoded values pulled from
# ``chia.consensus.default_constants`` (also documented in
# ``solslot_api/solslot_api/faucet.py:AGG_SIG_ME_DATA``).

NETWORK_ID_MAINNET: Final[bytes32] = bytes32.fromhex(
    "ccd5bb71183532bff220ba46c268991a00000000000000000000000000000000"
)
NETWORK_ID_TESTNET11: Final[bytes32] = bytes32.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
)


# ─────────────────────────────────────────────────────────────────────────
# Content hash — the off-chain ↔ on-chain binding point.
# ─────────────────────────────────────────────────────────────────────────


def compute_content_hash(
    pool_launcher_id: bytes32,
    gov_tracker_launcher_id: bytes32,
    network_id: bytes32,
    config_version: int,
) -> bytes32:
    """Deterministic hash of the protocol-config state tuple.

    MUST match the on-chain Chialisp ``content-hash`` defun in
    ``protocol_config_inner.clsp``.  The test suite enforces this via
    ``test_content_hash_matches_driver``: any divergence between the two
    representations would silently break the EIP-712 binding.

    Args:
        pool_launcher_id: 32-byte launcher coin id of the protocol pool
            singleton.
        gov_tracker_launcher_id: 32-byte launcher coin id of the
            governance tracker singleton.
        network_id: 32-byte network discriminator (use
            :data:`NETWORK_ID_MAINNET` or :data:`NETWORK_ID_TESTNET11`).
        config_version: monotonically increasing integer; replay-attack
            guard, asserted by the puzzle to strictly increase on every
            update spend.

    Returns:
        bytes32 sha256-tree hash of ``(pool gov_tracker network version)``.
    """
    state_program = Program.to(
        [
            pool_launcher_id,
            gov_tracker_launcher_id,
            network_id,
            config_version,
        ]
    )
    return bytes32(state_program.get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    gov_pubkey: bytes,
    pool_launcher_id: bytes32,
    gov_tracker_launcher_id: bytes32,
    network_id: bytes32,
    config_version: int,
) -> Program:
    """Curry the inner puzzle for a specific protocol-config state.

    Currying order MUST match ``protocol_config_inner.clsp``:

        SELF_MOD_HASH, GOV_PUBKEY, POOL_LAUNCHER_ID,
        GOV_TRACKER_LAUNCHER_ID, NETWORK_ID, CONFIG_VERSION

    The SELF_MOD_HASH curried arg lets the puzzle self-recurry on update
    spends (Chialisp can't introspect its own tree hash without a hand-
    fed parameter).

    Args:
        gov_pubkey: 48-byte BLS G1 pubkey of the protocol governance
            authority — the only key whose AGG_SIG_ME signature can
            authorise an update spend.
        pool_launcher_id: see :func:`compute_content_hash`.
        gov_tracker_launcher_id: see :func:`compute_content_hash`.
        network_id: see :func:`compute_content_hash`.
        config_version: see :func:`compute_content_hash`.

    Returns:
        Curried Program ready to be wrapped by the singleton top layer.
    """
    return protocol_config_inner_mod().curry(
        protocol_config_inner_mod_hash(),
        gov_pubkey,
        pool_launcher_id,
        gov_tracker_launcher_id,
        network_id,
        config_version,
    )


def make_inner_puzzle_hash(
    gov_pubkey: bytes,
    pool_launcher_id: bytes32,
    gov_tracker_launcher_id: bytes32,
    network_id: bytes32,
    config_version: int,
) -> bytes32:
    """Tree hash of the curried inner puzzle.

    Convenience wrapper around :func:`make_inner_puzzle`; useful when
    constructing the next-state ``CREATE_COIN`` destination during an
    update spend without rebuilding the full puzzle tree.
    """
    return bytes32(
        make_inner_puzzle(
            gov_pubkey=gov_pubkey,
            pool_launcher_id=pool_launcher_id,
            gov_tracker_launcher_id=gov_tracker_launcher_id,
            network_id=network_id,
            config_version=config_version,
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# State parsing — recover typed state from an on-chain puzzle reveal.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProtocolConfigState:
    """Decoded state of a protocol-config singleton.

    Mirrors the curried args of ``protocol_config_inner.clsp``.  The API
    indexer constructs one of these by calling :func:`parse_inner_puzzle`
    on each puzzle reveal it pulls from coinset.org.
    """

    self_mod_hash: bytes32
    gov_pubkey: bytes
    pool_launcher_id: bytes32
    gov_tracker_launcher_id: bytes32
    network_id: bytes32
    config_version: int

    @property
    def content_hash(self) -> bytes32:
        """Recompute the content hash for this state."""
        return compute_content_hash(
            pool_launcher_id=self.pool_launcher_id,
            gov_tracker_launcher_id=self.gov_tracker_launcher_id,
            network_id=self.network_id,
            config_version=self.config_version,
        )


def parse_inner_puzzle(curried_inner_puzzle: Program) -> ProtocolConfigState:
    """Decompose a curried inner puzzle back into typed state.

    The chia ``Program.uncurry()`` returns ``(uncurried_mod, args)`` where
    ``args`` is a Program list of the curried arguments in declaration
    order.  We strictly validate that the uncurried mod hashes back to
    our known module hash before returning state — otherwise the caller
    is parsing some other puzzle that happens to look like ours.

    Raises:
        ValueError: if the puzzle is not an instance of
            ``protocol_config_inner.clsp``, or if any field has the wrong
            length / type.
    """
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != protocol_config_inner_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate protocol_config_inner.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{protocol_config_inner_mod_hash().hex()}"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 6:
        raise ValueError(
            f"protocol_config_inner expects 6 curried args, got {len(args_list)}"
        )
    self_mod_hash = bytes32(args_list[0].as_atom())
    gov_pubkey = bytes(args_list[1].as_atom())
    pool_launcher_id = bytes32(args_list[2].as_atom())
    gov_tracker_launcher_id = bytes32(args_list[3].as_atom())
    network_id = bytes32(args_list[4].as_atom())
    config_version = int(args_list[5].as_int())
    if len(gov_pubkey) != 48:
        raise ValueError(f"GOV_PUBKEY must be 48 bytes (BLS G1), got {len(gov_pubkey)}")
    return ProtocolConfigState(
        self_mod_hash=self_mod_hash,
        gov_pubkey=gov_pubkey,
        pool_launcher_id=pool_launcher_id,
        gov_tracker_launcher_id=gov_tracker_launcher_id,
        network_id=network_id,
        config_version=config_version,
    )


# ─────────────────────────────────────────────────────────────────────────
# Update spend — solution construction + signing message derivation.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class UpdateSpendArtifacts:
    """Bundle of artifacts an operator needs to drive an update spend.

    The driver intentionally stops short of building a full SpendBundle
    (which requires AGG_SIG_ME additional data, parent-coin lookup, and
    the singleton wrapper).  That assembly lives in the API's
    ``protocol_config_writer.py`` (or in operator scripts), which has
    the chia network primitives wired up.
    """

    inner_solution: Program
    """Solution to feed into the curried inner puzzle."""

    new_inner_puzzle_hash: bytes32
    """Tree hash of the next-state inner puzzle (CREATE_COIN destination)."""

    agg_sig_me_message: bytes32
    """Pre-AGG_SIG_ME message that governance must sign.

    This is the ``content-hash(new_state)`` value emitted directly by
    the on-chain ``AGG_SIG_ME GOV_PUBKEY <msg>`` condition.  The caller
    appends the AGG_SIG_ME additional data + coin id and signs with
    ``AugSchemeMPL.sign``.
    """

    new_content_hash: bytes32
    """Public ``content_hash`` of the new state — what the API will
    expose on ``/protocol`` after the spend confirms."""


def build_update_spend(
    *,
    current: ProtocolConfigState,
    new_pool_launcher_id: bytes32,
    new_gov_tracker_launcher_id: bytes32,
    new_network_id: bytes32,
    new_config_version: int,
    my_amount: int,
) -> UpdateSpendArtifacts:
    """Construct the inner-puzzle solution + signing message for an update.

    The puzzle on-chain enforces ``new_config_version == current.version + 1``;
    we replicate that check here so callers fail fast in Python rather
    than getting an opaque CLVM ``(x)`` panic at spend time.

    Args:
        current: the pre-update state, as returned by
            :func:`parse_inner_puzzle`.
        new_pool_launcher_id: replacement pool launcher.  Pass the same
            value as ``current`` if you only want to bump other fields.
        new_gov_tracker_launcher_id: replacement governance tracker.
        new_network_id: replacement network id (typically only changes
            during a testnet → mainnet migration).
        new_config_version: must be exactly ``current.config_version + 1``.
        my_amount: singleton coin amount (must be odd; singleton
            convention).

    Returns:
        :class:`UpdateSpendArtifacts` containing everything needed to
        finalise the spend: the inner solution, the next-state puzzle
        hash, the AGG_SIG_ME message, and the public content_hash.

    Raises:
        ValueError: on non-exact version bump or invalid lengths.
    """
    expected_config_version = current.config_version + 1
    if new_config_version != expected_config_version:
        raise ValueError(
            "new_config_version must advance exactly one step "
            f"(got new={new_config_version} expected={expected_config_version})"
        )
    if my_amount % 2 == 0:
        raise ValueError(
            f"singleton amount must be odd (got {my_amount}); singletons "
            "use odd amounts to distinguish from regular coin lineage"
        )
    for name, value in (
        ("new_pool_launcher_id", new_pool_launcher_id),
        ("new_gov_tracker_launcher_id", new_gov_tracker_launcher_id),
        ("new_network_id", new_network_id),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes, got {len(value)}")

    new_content_hash = compute_content_hash(
        pool_launcher_id=new_pool_launcher_id,
        gov_tracker_launcher_id=new_gov_tracker_launcher_id,
        network_id=new_network_id,
        config_version=new_config_version,
    )

    new_inner_puzzle_hash = make_inner_puzzle_hash(
        gov_pubkey=current.gov_pubkey,
        pool_launcher_id=new_pool_launcher_id,
        gov_tracker_launcher_id=new_gov_tracker_launcher_id,
        network_id=new_network_id,
        config_version=new_config_version,
    )

    inner_solution = Program.to(
        [
            my_amount,
            new_pool_launcher_id,
            new_gov_tracker_launcher_id,
            new_network_id,
            new_config_version,
        ]
    )

    return UpdateSpendArtifacts(
        inner_solution=inner_solution,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        # Per the puzzle: AGG_SIG_ME signs the content_hash of the NEW
        # state directly.  This is intentional — anyone reviewing the
        # chain can independently recompute what was signed.
        agg_sig_me_message=new_content_hash,
        new_content_hash=new_content_hash,
    )


__all__ = [
    "NETWORK_ID_MAINNET",
    "NETWORK_ID_TESTNET11",
    "ProtocolConfigState",
    "UpdateSpendArtifacts",
    "build_update_spend",
    "compute_content_hash",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "parse_inner_puzzle",
    "protocol_config_inner_mod",
    "protocol_config_inner_mod_hash",
]
