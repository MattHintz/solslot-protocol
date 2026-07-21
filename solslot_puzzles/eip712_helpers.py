"""CHIP-0037 EIP-712 helpers for off-chain admin tooling.

These reproduce the constants + hash construction logic from
``chia-wallet-sdk``'s ``P2Eip712MessageLayer`` (Rust) so off-chain
clients (the Solslot API, the launch wizard) can:

  * Compute the 34-byte ``PREFIX_AND_DOMAIN_SEPARATOR`` curried into
    ``Eip712Member`` (depends on the chain's genesis challenge).
  * Compute the constant CHIP-0037 ``TYPE_HASH`` for
    ``ChiaCoinSpend(bytes32 coin_id, bytes32 delegated_puzzle_hash)``.
  * Compute the 32-byte digest a wallet must sign for a given
    ``(coin_id, delegated_puzzle_hash)`` pair.
  * Compute the tree hash of an ``Eip712Member`` curried with a
    specific operator's secp256k1 public key — this is the "leaf hash"
    that lives in an admin record's ``leaves`` tuple and gets folded
    into the on-chain ``ADMINS_HASH``.

Why these live in ``solslot_puzzles`` rather than at API or portal
level: the leaf hash is an on-chain commitment, so the canonical
computation must come from the same place that knows the puzzle
bytecode.  The API + portal both depend on this module so they
cannot drift from each other or from the chain.

The matching Rust source is:
``chia-wallet-sdk/crates/chia-sdk-driver/src/layers/p2_eip712_message_layer.rs``
(``compute_hash_to_sign``, ``domain_separator``,
``prefix_and_domain_separator``, ``type_hash``).

Tests pinning this module to the Rust implementation live in
``solslot-protocol/tests/test_admin_authority_v2.py::TestEip712MemberIntegration``.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32


# ──────────────────────────────────────────────────────────────────────
# Genesis challenges for the Chia networks we support.
#
# The EIP-712 domain separator binds to the Chia genesis challenge so
# signatures cannot be replayed across networks.  Operators select the
# right value based on SOLSLOT_NETWORK env.
# ──────────────────────────────────────────────────────────────────────

MAINNET_GENESIS_CHALLENGE: bytes32 = bytes32.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

TESTNET11_GENESIS_CHALLENGE: bytes32 = bytes32.fromhex(
    "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
)


def genesis_challenge_for_network(network: str) -> bytes32:
    """Map a Solslot network name to the corresponding genesis challenge.

    Raises ValueError for unsupported networks so misconfigured
    deployments fail loud rather than silently using the wrong
    challenge (which would invalidate every EIP-712 signature).
    """
    if network == "mainnet":
        return MAINNET_GENESIS_CHALLENGE
    if network == "testnet11":
        return TESTNET11_GENESIS_CHALLENGE
    raise ValueError(
        f"Unsupported network {network!r}; expected 'mainnet' or 'testnet11'"
    )


# ──────────────────────────────────────────────────────────────────────
# Hashing primitives
# ──────────────────────────────────────────────────────────────────────


def keccak256(data: bytes) -> bytes:
    """Pure keccak256 — matches what the Chialisp ``(keccak256 ...)``
    op computes (per CHIP-0036)."""
    from Crypto.Hash import keccak

    return keccak.new(data=data, digest_bits=256).digest()


def eip712_type_hash() -> bytes32:
    """The canonical CHIP-0037 type hash.

    Constant across networks and operators; bound to the wire format
    of ``ChiaCoinSpend(bytes32 coin_id, bytes32 delegated_puzzle_hash)``.
    """
    return bytes32(
        keccak256(b"ChiaCoinSpend(bytes32 coin_id,bytes32 delegated_puzzle_hash)")
    )


def eip712_domain_separator(genesis_challenge: bytes) -> bytes32:
    """Reproduces ``P2Eip712MessageLayer::domain_separator``.

    Schema: ``{ name: "Chia Coin Spend", version: "1",
    salt: <genesis_challenge> }``.  The salt binds the signature to a
    specific Chia network so a mainnet admin's signature can never be
    replayed against a testnet11 vault and vice versa.
    """
    type_hash = keccak256(
        b"EIP712Domain(string name,string version,bytes32 salt)"
    )
    blob = (
        type_hash
        + keccak256(b"Chia Coin Spend")
        + keccak256(b"1")
        + bytes(genesis_challenge)
    )
    return bytes32(keccak256(blob))


def eip712_prefix_and_domain_separator(genesis_challenge: bytes) -> bytes:
    """The 34-byte value curried into ``Eip712Member``.

    Bytes 0-1: ``0x1901`` (EIP-712 prefix).
    Bytes 2-33: keccak256 of the domain separator components.

    This is what each leaf in an admin record commits to via curry.
    """
    return b"\x19\x01" + bytes(eip712_domain_separator(genesis_challenge))


def eip712_hash_to_sign(
    prefix_and_domain: bytes,
    coin_id: bytes,
    delegated_puzzle_hash: bytes,
) -> bytes32:
    """The 32-byte digest the wallet must sign.

    Used by both off-chain spend construction (sign here, paste sig
    into the spend solution) and signature verification (recover
    pubkey from sig + this hash, compare against the curried key).
    """
    inner = keccak256(
        bytes(eip712_type_hash()) + coin_id + delegated_puzzle_hash
    )
    return bytes32(keccak256(prefix_and_domain + inner))


# ──────────────────────────────────────────────────────────────────────
# Eip712Member leaf-hash computation
# ──────────────────────────────────────────────────────────────────────


_EIP712_MEMBER_PUZZLE_CACHE: Optional[Program] = None
_EIP712_MEMBER_PUZZLE_BYTES_CACHE: Optional[bytes] = None


def _eip712_member_puzzle() -> Program:
    """Load + cache the ``eip712_member.clsp`` puzzle program.

    Sourced from ``solslot_puzzles.test_fixture_eip712_member.clsp``
    which is a verbatim copy of the upstream chia-wallet-sdk PR #395
    puzzle (see solslot-protocol's test suite for the cross-check that
    asserts byte-for-byte equality with the upstream).

    A future refactor will move this fixture out of "test_fixture_*"
    naming once the upstream PR lands and we can vendor the canonical
    bytecode at a stable path.
    """
    global _EIP712_MEMBER_PUZZLE_CACHE, _EIP712_MEMBER_PUZZLE_BYTES_CACHE
    if _EIP712_MEMBER_PUZZLE_CACHE is None:
        # Lazy import to avoid touching clvm tooling at module load
        # time; matches the test fixture's loading pattern.
        from chia.wallet.puzzles.load_clvm import load_clvm

        _EIP712_MEMBER_PUZZLE_CACHE = load_clvm(
            "test_fixture_eip712_member.clsp",
            package_or_requirement="solslot_puzzles",
            recompile=True,
        )
        _EIP712_MEMBER_PUZZLE_BYTES_CACHE = bytes(_EIP712_MEMBER_PUZZLE_CACHE)
    return _EIP712_MEMBER_PUZZLE_CACHE


def _eip712_member_puzzle_bytes() -> bytes:
    """Return serialized module bytes safe to deserialize on any thread."""
    global _EIP712_MEMBER_PUZZLE_BYTES_CACHE
    if _EIP712_MEMBER_PUZZLE_BYTES_CACHE is None:
        _eip712_member_puzzle()
    assert _EIP712_MEMBER_PUZZLE_BYTES_CACHE is not None
    return _EIP712_MEMBER_PUZZLE_BYTES_CACHE


def _atom_treehash(atom: bytes) -> bytes32:
    """sha256tree of an atom — equivalent to ``Program.to(atom).get_tree_hash()``
    but pure bytes-in-bytes-out so it doesn't create a LazyNode (which
    breaks under cross-thread access in pyo3).

    Per CLVM tree-hash semantics: sha256(b"\\x01" || atom).
    """
    return bytes32(hashlib.sha256(b"\x01" + atom).digest())


def _quoted_mod_hash(mod_hash: bytes32) -> bytes32:
    """sha256tree of ``(q . mod_hash)`` where ``mod_hash`` is *already*
    a tree hash — i.e., ``sha256(0x02 || sha256(0x01 || 0x01) || mod_hash)``.

    Mirrors ``chia.wallet.util.curry_and_treehash.calculate_hash_of_
    quoted_mod_hash`` byte-for-byte but in pure bytes so it sidesteps
    LazyNode threading hazards under ``pyo3``/anyio worker pools.

    The Q_KW (``0x01``) is treated as an atom (so its tree hash is
    ``sha256(0x01 || 0x01)``).  The ``mod_hash`` is **not** re-hashed:
    in CLVM curry, the second element of ``(q . mod_hash)`` is the
    program tree itself, whose tree hash is ``mod_hash`` by definition.
    Earlier revisions of this helper double-hashed (``sha256(0x01 ||
    mod_hash)``) which produced a hash that diverged from
    ``Program.curry().get_tree_hash()`` and from the chia-wallet-sdk
    Rust ``Eip712Member::curry_tree_hash`` — admin records produced
    with that variant would fail the on-chain ``(= (sha256tree
    approving_member_reveal) <leaf>)`` check at spend time.
    """
    one_one = hashlib.sha256(b"\x01\x01").digest()
    return bytes32(hashlib.sha256(b"\x02" + one_one + bytes(mod_hash)).digest())


# Module-level cache for the Eip712Member mod hash.  Computed once on
# first use; subsequent compute_eip712_member_leaf_hash calls reuse it.
# This is the only piece of the puzzle that needs Program.get_tree_hash
# (one-shot at module load), all per-call work is pure-bytes curry maths.
_EIP712_MEMBER_MOD_HASH_CACHE: Optional[bytes32] = None


def _eip712_member_mod_hash() -> bytes32:
    """Tree hash of the (uncurried) ``eip712_member.clsp`` puzzle.

    Computed once + cached so per-request curry computations are pure
    bytes work (no LazyNode allocation).  See ``_atom_treehash`` for
    why this matters for FastAPI / anyio-thread safety.
    """
    global _EIP712_MEMBER_MOD_HASH_CACHE
    if _EIP712_MEMBER_MOD_HASH_CACHE is None:
        _EIP712_MEMBER_MOD_HASH_CACHE = bytes32(
            _eip712_member_puzzle().get_tree_hash()
        )
    return _EIP712_MEMBER_MOD_HASH_CACHE


def compute_eip712_member_leaf_hash(
    *,
    secp256k1_pubkey: bytes,
    prefix_and_domain_separator: bytes,
    type_hash: bytes32 = None,
) -> bytes32:
    """Compute the tree hash of an ``Eip712Member`` curried with the
    given operator pubkey.

    This is the value that lives in an admin record's ``leaves`` tuple
    and gets folded into the on-chain ``ADMINS_HASH``.  Callers (the
    Solslot API at boot time, the launch wizard at admin-records-
    generation time) use this to verify their off-chain admin records
    JSON binds correctly to the on-chain singleton state.

    Args:
        secp256k1_pubkey: 33-byte compressed secp256k1 public key.
        prefix_and_domain_separator: 34-byte ``0x1901 || domain_sep``.
            Use :func:`eip712_prefix_and_domain_separator` to derive
            from a network's genesis challenge.
        type_hash: 32-byte CHIP-0037 type hash.  Defaults to the
            canonical ``ChiaCoinSpend(...)`` type via
            :func:`eip712_type_hash` when None.

    Returns:
        The 32-byte tree hash of the curried Eip712Member puzzle.

    Raises:
        ValueError: if the pubkey isn't 33 bytes, the prefix isn't 34
            bytes, or doesn't start with 0x1901.
    """
    if len(secp256k1_pubkey) != 33:
        raise ValueError(
            f"secp256k1_pubkey must be 33 bytes (compressed), got "
            f"{len(secp256k1_pubkey)}"
        )
    if len(prefix_and_domain_separator) != 34:
        raise ValueError(
            f"prefix_and_domain_separator must be 34 bytes, got "
            f"{len(prefix_and_domain_separator)}"
        )
    if prefix_and_domain_separator[:2] != b"\x19\x01":
        raise ValueError(
            f"prefix_and_domain_separator must start with 0x1901 (EIP-712 "
            f"prefix), got 0x{prefix_and_domain_separator[:2].hex()}"
        )
    th = type_hash if type_hash is not None else eip712_type_hash()
    if len(th) != 32:
        raise ValueError(f"type_hash must be 32 bytes, got {len(th)}")

    # Curry order matches the Rust struct field order in
    # chia-sdk-types/src/puzzles/mips/members/eip712_member.rs:
    #   prefix_and_domain_separator, type_hash, public_key.
    #
    # We use pure-bytes curry-and-treehash math (rather than
    # ``Program.curry().get_tree_hash()``) to avoid creating a
    # per-call LazyNode that would panic under cross-thread access
    # when this helper is invoked from FastAPI's anyio worker pool.
    # The math mirrors ``chia.wallet.util.curry_and_treehash`` but
    # operates on raw 32-byte hashes throughout.
    quoted_mod_hash = _quoted_mod_hash(_eip712_member_mod_hash())
    args_tree_hashes = [
        _atom_treehash(bytes(prefix_and_domain_separator)),
        _atom_treehash(bytes(th)),
        _atom_treehash(bytes(secp256k1_pubkey)),
    ]

    # curry_and_treehash recursive formula (mirrors
    # ``chia.wallet.util.curry_and_treehash`` byte-for-byte):
    #
    #   curry(mod, args) = (a (q . mod) curried_values(args))
    #
    # whose tree hash is:
    #   pair(A_KW_TH, pair(quoted_mod_th, pair(curried_values_th, NIL_TH)))
    #
    # where:
    #   curried_values_th([])       = ONE_TREEHASH = shatree_atom(0x01) =
    #                                 sha256(0x01 || 0x01)
    #     (the trailing "1" atom in the curry env: ``(c (q . a) 1)``)
    #   curried_values_th([a, ...]) =
    #       pair(C_KW_TH, pair(pair(Q_KW_TH, a),
    #                          pair(curried_values_th([...]), NIL_TH)))
    #   NIL_TREEHASH = shatree_atom(b"") = sha256(0x01)
    #     (the empty-list / nil sentinel)
    #
    # Note: NIL_TREEHASH and ONE_TREEHASH are **different values** —
    # earlier revisions of this helper conflated them (used NIL where
    # ONE was needed for the curried-values base case), producing leaf
    # hashes that diverged from chia's reference and the chia-wallet-sdk
    # Rust ``Eip712Member::curry_tree_hash`` and would fail on-chain at
    # spend time.
    #
    # Constants from chia-blockchain ``curry_and_treehash``:
    A_KW = 2  # opcode for `apply` (run a curried function)
    C_KW = 4  # opcode for `cons` (build the args list lazily)
    Q_KW = 1  # opcode for `quote` (so atom args aren't re-evaluated)
    a_kw_th = _atom_treehash(bytes([A_KW]))
    c_kw_th = _atom_treehash(bytes([C_KW]))
    q_kw_th = _atom_treehash(bytes([Q_KW]))
    one_treehash = _atom_treehash(b"\x01")  # sha256(0x01 || 0x01) — curry-args base case
    nil_treehash = _atom_treehash(b"")  # sha256(0x01) — empty-list sentinel

    def _pair_th(left: bytes, right: bytes) -> bytes32:
        return bytes32(hashlib.sha256(b"\x02" + left + right).digest())

    def _curried_values_th(args: list[bytes32]) -> bytes32:
        if not args:
            return one_treehash
        head, *tail = args
        # pair(Q_KW, a)
        quoted_arg = _pair_th(q_kw_th, head)
        # pair(curried_values_th([...]), NIL)
        rest_then_nil = _pair_th(_curried_values_th(tail), nil_treehash)
        # pair(C_KW, pair(quoted_arg, rest_then_nil))
        return _pair_th(c_kw_th, _pair_th(quoted_arg, rest_then_nil))

    cv_th = _curried_values_th(args_tree_hashes)
    cv_then_nil = _pair_th(cv_th, nil_treehash)
    quoted_then_cv_then_nil = _pair_th(quoted_mod_hash, cv_then_nil)
    return _pair_th(a_kw_th, quoted_then_cv_then_nil)


def make_eip712_member_puzzle(
    *,
    secp256k1_pubkey: bytes,
    prefix_and_domain_separator: bytes,
    type_hash: bytes32 | None = None,
) -> Program:
    """Build the canonical CHIP-0037 EIP-712 MIPS member puzzle.

    Genesis planning needs both the member tree hash stored in the durable
    admin roster and the actual reveal used by the top-level CHIP-0043
    quorum.  Keeping both constructions here prevents the ceremony planner
    from reproducing the curry order independently.
    """
    if len(secp256k1_pubkey) != 33:
        raise ValueError(
            "secp256k1_pubkey must be 33 bytes (compressed), got "
            f"{len(secp256k1_pubkey)}"
        )
    if len(prefix_and_domain_separator) != 34:
        raise ValueError(
            "prefix_and_domain_separator must be 34 bytes, got "
            f"{len(prefix_and_domain_separator)}"
        )
    if prefix_and_domain_separator[:2] != b"\x19\x01":
        raise ValueError("prefix_and_domain_separator must start with 0x1901")
    resolved_type_hash = type_hash if type_hash is not None else eip712_type_hash()
    if len(resolved_type_hash) != 32:
        raise ValueError(f"type_hash must be 32 bytes, got {len(resolved_type_hash)}")
    return Program.from_bytes(_eip712_member_puzzle_bytes()).curry(
        prefix_and_domain_separator,
        resolved_type_hash,
        secp256k1_pubkey,
    )


__all__ = [
    "MAINNET_GENESIS_CHALLENGE",
    "TESTNET11_GENESIS_CHALLENGE",
    "genesis_challenge_for_network",
    "keccak256",
    "eip712_type_hash",
    "eip712_domain_separator",
    "eip712_prefix_and_domain_separator",
    "eip712_hash_to_sign",
    "compute_eip712_member_leaf_hash",
    "make_eip712_member_puzzle",
]
