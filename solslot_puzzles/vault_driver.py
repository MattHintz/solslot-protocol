"""
vault_driver.py — Driver for creating and spending user vault singletons.

A user vault is a standard Chia singleton wrapping vault_singleton_inner.clsp.
It is identified by its launcher ID (vault_launcher_id) which is fixed at deploy
time and never changes.  The p2_vault puzzle is derived deterministically from
vault_launcher_id and holds deed NFTs on the user's behalf.

Supported auth types (curried into the vault puzzle as AUTH_TYPE):
  AUTH_TYPE_BLS       (1) — Chia-native BLS wallet (Goby, Sage via WalletConnect)
                            OWNER_PUBKEY: 48-byte BLS G1Element
  AUTH_TYPE_SECP256R1 (2) — Passkey / WebAuthn (secp256r1)
                            OWNER_PUBKEY: 65-byte uncompressed secp256r1 pubkey
  AUTH_TYPE_SECP256K1 (3) — EVM wallet (MetaMask, Coinbase Wallet) via EIP-712
                            OWNER_PUBKEY: 33-byte compressed secp256k1 pubkey

Vault creation steps:
  1. Select a small XCH coin to spend as the launcher parent.
  2. Derive the launcher coin (child of the parent at SINGLETON_LAUNCHER puzzle).
  3. Curry vault_singleton_inner with the owner pubkey, auth_type, and pool params.
  4. Wrap in singleton_top_layer to get the full vault puzzle.
  5. Build a two-coin spend bundle: parent + launcher (unsigned).
  6. Return unsigned bundle + signing_message for the client to sign externally.
  7. Client returns signature; driver assembles final SpendBundle and pushes.

Usage (BLS):
    bundle, launcher_id, msg = build_create_vault_bundle(
        parent_coin, parent_puzzle, owner_pubkey_bytes, AUTH_TYPE_BLS, pool_launcher_id
    )
Usage (EVM / secp256k1):
    bundle, launcher_id, msg = build_create_vault_bundle(
        parent_coin, parent_puzzle, secp256k1_pubkey_bytes, AUTH_TYPE_SECP256K1, pool_launcher_id
    )
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.serialized_program import SerializedProgram
from chia.types.coin_spend import CoinSpend, make_spend
from chia_rs import SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    puzzle_for_pk,
    puzzle_hash_for_synthetic_public_key,
    solution_for_conditions,
)
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER,
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs import G1Element, G2Element, PrivateKey

from solslot_puzzles import load_puzzle
from solslot_puzzles.zkpassport_attestation import ZKPASSPORT_EMPTY_ATTEST_ROOT

logger = logging.getLogger(__name__)

SINGLETON_AMOUNT = uint64(1)

VAULT_INNER_MOD: Program = load_puzzle("vault_singleton_inner.clsp")
P2_VAULT_MOD: Program = load_puzzle("p2_vault.clsp")

# Auth type constants — mirror vault_singleton_inner.clsp
AUTH_TYPE_BLS = 1        # Chia-native BLS (Goby, Sage)
AUTH_TYPE_SECP256R1 = 2  # Passkey / WebAuthn secp256r1
AUTH_TYPE_SECP256K1 = 3  # EVM wallet secp256k1 (EIP-712)

DEFAULT_IDENTITY_ATTEST_ROOT: bytes32 = ZKPASSPORT_EMPTY_ATTEST_ROOT
DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH: bytes32 = bytes32(b"\x00" * 32)


def validate_owner_pubkey_for_auth_type(owner_pubkey: bytes, auth_type: int) -> bytes:
    if not isinstance(owner_pubkey, (bytes, bytearray)):
        raise TypeError("owner_pubkey must be bytes")
    owner = bytes(owner_pubkey)
    if auth_type == AUTH_TYPE_BLS:
        if len(owner) != 48:
            raise ValueError(f"BLS owner_pubkey must be 48 bytes, got {len(owner)}")
    elif auth_type == AUTH_TYPE_SECP256R1:
        if len(owner) != 65 or owner[0] != 0x04:
            raise ValueError(
                "secp256r1 owner_pubkey must be 65 bytes uncompressed "
                f"(0x04 || X || Y), got {len(owner)} bytes"
            )
    elif auth_type == AUTH_TYPE_SECP256K1:
        if len(owner) != 33 or owner[0] not in (0x02, 0x03):
            raise ValueError(
                "secp256k1 owner_pubkey must be 33 bytes compressed "
                f"(0x02/0x03 || X), got {len(owner)} bytes"
            )
    else:
        raise ValueError(f"Unsupported auth_type: {auth_type}")
    return owner


@dataclass(frozen=True)
class VaultInnerState:
    singleton_struct: Program
    owner_pubkey_bytes: bytes
    auth_type: int
    members_merkle_root: bytes32
    identity_attest_root: bytes32
    zkpassport_bridge_policy_hash: bytes32
    pool_singleton_mod_hash: bytes32
    pool_launcher_id: bytes32
    pool_launcher_puzzle_hash: bytes32


# ── Deterministic vault discovery hint (CHIP-22) ──────────────────────────
# When the faucet creates the singleton launcher coin during registration,
# we attach a deterministic hint derived from the user's pubkey + auth type.
# This makes the vault discoverable from chain alone — given just the user's
# pubkey, any client can call `get_coin_records_by_hint` to find the launcher
# without consulting the backend.
#
# The hint is namespaced per auth type so EVM and BLS pubkeys producing the
# same byte sequence (vanishingly unlikely but possible) cannot collide.
#
# Format: sha256(VAULT_HINT_DOMAIN || auth_type_byte || owner_pubkey_bytes)
VAULT_HINT_DOMAIN = b"solslot-vault-discovery-v2"


def vault_discovery_hint(auth_type: int, owner_pubkey: bytes) -> bytes32:
    """Deterministic 32-byte hint for vault discovery via CHIP-22 hints.

    Args:
        auth_type: AUTH_TYPE_BLS / AUTH_TYPE_SECP256R1 / AUTH_TYPE_SECP256K1
        owner_pubkey: the raw owner pubkey bytes for the selected auth type.

    Returns:
        32-byte hint to attach as the first memo of the launcher CREATE_COIN.
    """
    import hashlib
    if auth_type not in (AUTH_TYPE_BLS, AUTH_TYPE_SECP256R1, AUTH_TYPE_SECP256K1):
        raise ValueError(f"Unsupported auth_type: {auth_type}")
    if not isinstance(owner_pubkey, (bytes, bytearray)):
        raise TypeError("owner_pubkey must be bytes")
    digest = hashlib.sha256(
        VAULT_HINT_DOMAIN + bytes([auth_type]) + bytes(owner_pubkey)
    ).digest()
    return bytes32(digest)


# ---------------------------------------------------------------------------
# EIP-712 domain declaration — single source of truth.
#
# Any change to these three values requires regenerating PREFIX_AND_DOMAIN_SEPARATOR
# in solslot_puzzles/vault_singleton_inner.clsp to match.  See the eip712 audit
# helper `eip712_prefix_and_domain_separator()` below — it is the generator.
#
# chainId = 11155111 (Ethereum Sepolia) matches the Solslot alpha EVM deployment.
# The signature is a typed-data attestation bound to the chain where
# the emitter lives; update this if the emitter is redeployed to a different chain.
# ---------------------------------------------------------------------------
EIP712_DOMAIN_NAME: str = "Solslot Vault"
EIP712_DOMAIN_VERSION: str = "2"
EIP712_DOMAIN_CHAIN_ID: int = 11155111

# Typehash: keccak256("SolslotVaultSpend(bytes32 spend_case,bytes32 deed_launcher_id,bytes32 vault_coin_id)")
# Mirrors SOLSLOT_VAULT_TYPEHASH in vault_singleton_inner.clsp.
SOLSLOT_VAULT_TYPEHASH_STRING: bytes = (
    b"SolslotVaultSpend(bytes32 spend_case,bytes32 deed_launcher_id,bytes32 vault_coin_id)"
)


# ---------------------------------------------------------------------------
# Pure puzzle builders (no I/O — fully testable)
# ---------------------------------------------------------------------------

def puzzle_for_vault_inner(
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> Program:
    """Curry vault_singleton_inner with the owner pubkey, auth_type, merkle root, and pool identity.

    Args:
        owner_pubkey_bytes: Raw pubkey bytes.
            AUTH_TYPE_BLS:       48-byte BLS G1Element
            AUTH_TYPE_SECP256R1: 65-byte uncompressed secp256r1 (0x04 + X + Y)
            AUTH_TYPE_SECP256K1: 33-byte compressed secp256k1
        auth_type: One of AUTH_TYPE_BLS, AUTH_TYPE_SECP256R1, AUTH_TYPE_SECP256K1.
        members_merkle_root: 32-byte Merkle root of authorised public keys.
            Single-key vaults pass the one-leaf Merkle root: sha256(0x01 + owner_pubkey_bytes).
    """
    owner_pubkey_bytes = validate_owner_pubkey_for_auth_type(owner_pubkey_bytes, auth_type)
    singleton_struct = Program.to(
        (SINGLETON_MOD_HASH, (vault_launcher_id, SINGLETON_LAUNCHER_HASH))
    )
    return VAULT_INNER_MOD.curry(
        singleton_struct,
        owner_pubkey_bytes,
        auth_type,
        members_merkle_root,
        identity_attest_root,
        zkpassport_bridge_policy_hash,
        SINGLETON_MOD_HASH,         # POOL_SINGLETON_MOD_HASH
        pool_launcher_id,            # POOL_SINGLETON_LAUNCHER_ID
        SINGLETON_LAUNCHER_HASH,     # POOL_SINGLETON_LAUNCHER_PUZZLE_HASH
    )


def parse_vault_inner_puzzle(curried_inner_puzzle: Program) -> VaultInnerState:
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != bytes32(VAULT_INNER_MOD.get_tree_hash()):
        raise ValueError("puzzle reveal does not instantiate vault_singleton_inner.clsp")
    args_list = list(args.as_iter())
    if len(args_list) != 9:
        raise ValueError(f"vault_singleton_inner expects 9 curried args, got {len(args_list)}")
    return VaultInnerState(
        singleton_struct=args_list[0],
        owner_pubkey_bytes=bytes(args_list[1].as_atom()),
        auth_type=int(args_list[2].as_int()),
        members_merkle_root=bytes32(args_list[3].as_atom()),
        identity_attest_root=bytes32(args_list[4].as_atom()),
        zkpassport_bridge_policy_hash=bytes32(args_list[5].as_atom()),
        pool_singleton_mod_hash=bytes32(args_list[6].as_atom()),
        pool_launcher_id=bytes32(args_list[7].as_atom()),
        pool_launcher_puzzle_hash=bytes32(args_list[8].as_atom()),
    )


def puzzle_for_vault_full(
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> Program:
    """Return the full singleton-wrapped vault puzzle.

    NOTE: `puzzle_for_singleton` expects `launcher_id` as bytes32, not a SINGLETON_STRUCT
    tuple — it constructs the SINGLETON_STRUCT internally.  Passing a Program tuple
    here would double-wrap SINGLETON_STRUCT and break `(f (r SS))` lookups inside
    the singleton top layer (observed as "= used on list" at runtime).
    """
    inner = puzzle_for_vault_inner(
        vault_launcher_id,
        owner_pubkey_bytes,
        auth_type,
        members_merkle_root,
        pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    return puzzle_for_singleton(vault_launcher_id, inner)


def one_leaf_merkle_root(owner_pubkey_bytes: bytes) -> bytes32:
    """Compute the Merkle root for a single-key vault.

    A one-leaf Merkle tree has root = sha256(0x01 || leaf), which matches
    simplify_merkle_proof with an empty proof path.
    """
    import hashlib
    return bytes32(hashlib.sha256(b"\x01" + owner_pubkey_bytes).digest())


def puzzle_for_p2_vault(vault_launcher_id: bytes32) -> Program:
    """Return the p2_vault puzzle that holds deed NFTs for this vault."""
    return P2_VAULT_MOD.curry(
        SINGLETON_MOD_HASH,
        vault_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )


def owner_pubkey_bytes_from_bls(owner_pk: G1Element) -> bytes:
    """Extract raw bytes from a BLS G1Element for currying."""
    return bytes(owner_pk)


def _keccak256(data: bytes) -> bytes:
    """Return 32-byte Keccak-256 digest (Ethereum-style, not SHA3-256)."""
    from Crypto.Hash import keccak as _keccak  # lazy import — pycryptodome is a test dep

    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def eip712_domain_separator() -> bytes:
    """Return the 32-byte EIP-712 DOMAIN_SEPARATOR for the Solslot domain.

    Formula (EIP-712, no verifyingContract/salt):
        DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId)")
        DOMAIN_SEPARATOR = keccak256(
            DOMAIN_TYPEHASH
            || keccak256(name)
            || keccak256(version)
            || pad32(chainId)
        )

    This is what every EVM wallet's `eth_signTypedData_v4` computes internally
    when presented with the typed-data JSON returned by
    `eip712_typed_data_for_vault_spend()`.
    """
    domain_typehash = _keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId)"
    )
    name_hash = _keccak256(EIP712_DOMAIN_NAME.encode("utf-8"))
    version_hash = _keccak256(EIP712_DOMAIN_VERSION.encode("utf-8"))
    chain_id_pad = EIP712_DOMAIN_CHAIN_ID.to_bytes(32, "big")
    return _keccak256(domain_typehash + name_hash + version_hash + chain_id_pad)


def eip712_prefix_and_domain_separator() -> bytes:
    """Return the 34-byte `0x1901 || DOMAIN_SEPARATOR` bytestring.

    This is the exact value of `PREFIX_AND_DOMAIN_SEPARATOR` in
    `vault_singleton_inner.clsp`.  The puzzle uses it as a raw concatenation
    prefix to `keccak256(typehash || struct_fields...)` to produce the final
    EIP-712 digest.

    Regenerating the CLSP constant:
        >>> from solslot_puzzles.vault_driver import eip712_prefix_and_domain_separator
        >>> "0x" + eip712_prefix_and_domain_separator().hex()
    """
    return b"\x19\x01" + eip712_domain_separator()


def eip712_typed_data_for_vault_spend(
    spend_case: bytes,
    deed_launcher_id: bytes32,
    vault_coin_id: bytes32,
) -> dict:
    """Return the JSON-serializable typed-data dict for `eth_signTypedData_v4`.

    A frontend uses this value directly:

        const typedData = await fetchFromServer("/typed_data", {...});
        const sig = await window.ethereum.request({
            method: "eth_signTypedData_v4",
            params: [userAddress, JSON.stringify(typedData)],
        });
        // sig is 0x + 65 hex bytes; pass to compact_signature_from_evm().

    Every MetaMask / Coinbase Wallet / Trust / Rainbow / WalletConnect wallet
    reconstructs the same 32-byte digest internally from this JSON, which is
    identical to what `signing_message_for_vault_spend()` returns.
    """
    spend_case_padded = spend_case.ljust(32, b"\x00")
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
            ],
            "SolslotVaultSpend": [
                {"name": "spend_case", "type": "bytes32"},
                {"name": "deed_launcher_id", "type": "bytes32"},
                {"name": "vault_coin_id", "type": "bytes32"},
            ],
        },
        "domain": {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": EIP712_DOMAIN_CHAIN_ID,
        },
        "primaryType": "SolslotVaultSpend",
        "message": {
            "spend_case": "0x" + spend_case_padded.hex(),
            "deed_launcher_id": "0x" + bytes(deed_launcher_id).hex(),
            "vault_coin_id": "0x" + bytes(vault_coin_id).hex(),
        },
    }


def signing_message_for_vault_spend(
    spend_case: bytes,
    deed_launcher_id: bytes32,
    vault_coin_id: bytes32,
) -> bytes:
    """Compute the 32-byte EIP-712 digest that an EVM wallet produces for a vault spend.

    Matches `verify_secp256k1` inside `vault_singleton_inner.clsp` byte-for-byte
    AND matches `eth_signTypedData_v4(typed_data)` on any standard EVM wallet
    where `typed_data = eip712_typed_data_for_vault_spend(...)`.

    For BLS wallets the AGG_SIG_ME message is produced by the CLVM; this helper
    is only needed for the secp256k1 path.
    """
    typehash = _keccak256(SOLSLOT_VAULT_TYPEHASH_STRING)
    spend_case_padded = spend_case.ljust(32, b"\x00")
    struct_hash = _keccak256(
        typehash + spend_case_padded + bytes(deed_launcher_id) + bytes(vault_coin_id)
    )
    return _keccak256(eip712_prefix_and_domain_separator() + struct_hash)


# ---------------------------------------------------------------------------
# EVM signature helpers — unpack, low-s normalize, server-side verify
# ---------------------------------------------------------------------------

_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def compact_signature_from_evm(sig: "bytes | str") -> bytes:
    """Accept a 65-byte (r||s||v) EVM signature and return a 64-byte low-s (r||s) compact sig.

    EVM wallets return 65-byte signatures; CLVM's `secp256k1_verify` takes 64 bytes.
    This helper:
      1. Drops the recovery byte `v`.
      2. Normalises `s` to the lower half-order (BIP-62) — CHIP-0011 `secp256k1_verify`
         rejects high-s signatures.  MetaMask ≥v10 already produces low-s, but older
         wallets and Ledger firmware historically did not; normalising is defensive.

    Accepts `sig` as 65 raw bytes or hex string (with or without `0x` prefix).
    Returns 64 raw bytes.
    """
    if isinstance(sig, str):
        sig = bytes.fromhex(sig.removeprefix("0x"))
    if len(sig) != 65:
        raise ValueError(f"expected 65-byte EVM signature (r||s||v), got {len(sig)} bytes")
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    # v is sig[64] — discarded; we don't need recovery, the pubkey is already known.
    if s > _SECP256K1_N // 2:
        s = _SECP256K1_N - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify_evm_signature(
    compressed_pubkey_33: bytes,
    digest_32: bytes,
    compact_sig_64: bytes,
) -> bool:
    """Server-side sanity check: does `compact_sig_64` over `digest_32` verify against `compressed_pubkey_33`?

    Returns True on success, False on any failure (wrong pubkey, wrong sig, wrong digest).
    Never raises.  Useful for rejecting malformed client requests before building a
    spend bundle that would just fail on-chain.

    Implementation uses `cryptography`'s EC primitives — no new deps.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        if len(compressed_pubkey_33) != 33 or compressed_pubkey_33[0] not in (0x02, 0x03):
            return False
        if len(digest_32) != 32 or len(compact_sig_64) != 64:
            return False

        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), compressed_pubkey_33
        )
        r = int.from_bytes(compact_sig_64[:32], "big")
        s = int.from_bytes(compact_sig_64[32:], "big")
        der = ec_utils.encode_dss_signature(r, s)
        try:
            pub.verify(der, digest_32, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
            return True
        except InvalidSignature:
            return False
    except Exception:
        return False


def launcher_coin_for_parent(parent_coin: Coin) -> Coin:
    """Compute the launcher coin that will be created from parent_coin."""
    return Coin(
        parent_coin.name(),
        SINGLETON_LAUNCHER_HASH,
        SINGLETON_AMOUNT,
    )


# ---------------------------------------------------------------------------
# Vault SPEND builders — the primary user interactions after vault creation.
#
# Every function is pure: given the vault's current coin + the parameters the
# user wants to authorize, returns a `CoinSpend` ready to be packed into a
# SpendBundle.  The caller is responsible for co-spending the pool / p2_vault /
# deed coins in the same bundle.
#
# Solution shapes (inner puzzle `vault_singleton_inner.clsp`):
#   'o' deposit: (my_id my_inner_puzhash my_amount SPEND_CASE
#                  (deed_launcher_id current_timestamp signature_data))
#   'i' receive: (my_id my_inner_puzhash my_amount SPEND_CASE
#                  (deed_launcher_id p2_vault_coin_id
#                   current_timestamp signature_data))
#
# LOW-13 fix (2026-04-26): dropped the dead `pool_inner_puzhash` parameter
# from both 'o' and 'i' — the puzzle never consumed it.  See SECURITY_AUDIT_2026_04_19.md.
# ---------------------------------------------------------------------------

# Spend-case byte literals — mirror `vault_singleton_inner.clsp`.
SPEND_DEPOSIT_TO_POOL: int = 0x6F   # b'o'
SPEND_RECEIVE_FROM_POOL: int = 0x69  # b'i'
SPEND_ACCEPT_OFFER: int = 0x61      # b'a' (BLS-only; secp deferred — see CRIT-2 residual)
SPEND_UPDATE_KEYS: int = 0x6B       # b'k' (BLS-only; secp deferred)
SPEND_UPDATE_IDENTITY: int = 0x7A
SPEND_MIGRATE: int = 0x6D           # b'm' (BLS-only; secp deferred — see CRIT-2 residual)


def _inner_solution_for_deposit(
    my_id: bytes32,
    my_inner_puzhash: bytes32,
    my_amount: int,
    deed_launcher_id: bytes32,
    current_timestamp: int,
    signature_data: Optional[bytes],
) -> Program:
    """Construct the INNER puzzle solution for a 'o' deposit spend.

    `signature_data`:
        - BLS auth: pass `None` (or `b""`) — the AGG_SIG_ME condition is emitted
          by the puzzle and the wallet signs at the network layer.
        - secp256k1/r1 auth: pass the 64-byte compact signature produced by
          `compact_signature_from_evm(evm_sig_65)`.
    """
    return Program.to([
        bytes(my_id),
        bytes(my_inner_puzhash),
        int(my_amount),
        SPEND_DEPOSIT_TO_POOL,
        [
            bytes(deed_launcher_id),
            int(current_timestamp),
            signature_data if signature_data is not None else b"",
        ],
    ])


def _inner_solution_for_receive(
    my_id: bytes32,
    my_inner_puzhash: bytes32,
    my_amount: int,
    deed_launcher_id: bytes32,
    p2_vault_coin_id: bytes32,
    current_timestamp: int,
    signature_data: Optional[bytes],
) -> Program:
    """Construct the INNER puzzle solution for a 'i' receive spend."""
    return Program.to([
        bytes(my_id),
        bytes(my_inner_puzhash),
        int(my_amount),
        SPEND_RECEIVE_FROM_POOL,
        [
            bytes(deed_launcher_id),
            bytes(p2_vault_coin_id),
            int(current_timestamp),
            signature_data if signature_data is not None else b"",
        ],
    ])


def _inner_solution_for_accept_offer(
    my_id: bytes32,
    my_inner_puzhash: bytes32,
    my_amount: int,
    deed_launcher_id: bytes32,
    token_amount: int,
    pool_inner_puzhash: bytes32,
    attestation_leaf_hash: bytes32,
    attestation_proof: Program,
    current_timestamp: int,
    signature_data: Optional[bytes],
) -> Program:
    return Program.to([
        bytes(my_id),
        bytes(my_inner_puzhash),
        int(my_amount),
        SPEND_ACCEPT_OFFER,
        [
            bytes(deed_launcher_id),
            int(token_amount),
            bytes(pool_inner_puzhash),
            bytes(attestation_leaf_hash),
            attestation_proof,
            int(current_timestamp),
            signature_data if signature_data is not None else b"",
        ],
    ])


def _inner_solution_for_update_identity(
    my_id: bytes32,
    my_inner_puzhash: bytes32,
    my_amount: int,
    vault_inner_mod_hash: bytes32,
    new_identity_attest_root: bytes32,
    bridge_parent_id: bytes32,
    bridge_amount: int,
    current_timestamp: int,
    signature_data: Optional[bytes],
) -> Program:
    return Program.to([
        bytes(my_id),
        bytes(my_inner_puzhash),
        int(my_amount),
        SPEND_UPDATE_IDENTITY,
        [
            bytes(vault_inner_mod_hash),
            bytes(new_identity_attest_root),
            bytes(bridge_parent_id),
            int(bridge_amount),
            int(current_timestamp),
            signature_data if signature_data is not None else b"",
        ],
    ])


def _inner_solution_for_migrate(
    my_id: bytes32,
    my_inner_puzhash: bytes32,
    my_amount: int,
    deed_launcher_id: bytes32,
    new_p2_vault_puzzlehash: bytes32,
    current_timestamp: int,
    signature_data: Optional[bytes],
) -> Program:
    """Construct the INNER puzzle solution for a 'm' (migrate-deed) spend.

    p = (deed_launcher_id new_p2_vault_puzzlehash current_timestamp signature_data)
    """
    return Program.to([
        bytes(my_id),
        bytes(my_inner_puzhash),
        int(my_amount),
        SPEND_MIGRATE,
        [
            bytes(deed_launcher_id),
            bytes(new_p2_vault_puzzlehash),
            int(current_timestamp),
            signature_data if signature_data is not None else b"",
        ],
    ])


def build_vault_deposit_spend(
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    deed_launcher_id: bytes32,
    current_timestamp: int,
    lineage_proof: LineageProof,
    signature_data: Optional[bytes] = None,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> CoinSpend:
    """Build a CoinSpend for a vault 'o' (deposit to pool) operation.

    This is the primary user-facing flow: the user wants to deposit one of their
    deeds into the pool.  For EVM wallets, the frontend has:
      1. Called `eip712_typed_data_for_vault_spend(b"o", deed_launcher_id, vault_coin.name())`.
      2. Called `eth_signTypedData_v4(address, typedData)` to get a 65-byte sig.
      3. Called `compact_signature_from_evm(sig65)` to get a 64-byte compact sig.
    Pass that 64-byte sig as `signature_data`.

    For BLS wallets, `signature_data` must be None/empty — the vault emits an
    AGG_SIG_ME condition, and the wallet signs the resulting SpendBundle.

    `lineage_proof` must reflect the PARENT of `vault_coin`:
      - If the parent is the launcher coin, use the `(launcher_id, launcher_amount)`
        form (which `LineageProof(parent_name=launcher_id, amount=1)` produces).
      - Otherwise use the full `(parent_name, parent_inner_puzhash, parent_amount)`
        form, derived via `lineage_proof_for_coinsol(parent_spend)`.
    """
    inner_puzzle = puzzle_for_vault_inner(
        vault_launcher_id, owner_pubkey_bytes, auth_type,
        members_merkle_root, pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full_puzzle = puzzle_for_singleton(vault_launcher_id, inner_puzzle)
    my_id = vault_coin.name()
    inner_solution = _inner_solution_for_deposit(
        my_id=my_id,
        my_inner_puzhash=inner_puzzle.get_tree_hash(),
        my_amount=int(vault_coin.amount),
        deed_launcher_id=deed_launcher_id,
        current_timestamp=current_timestamp,
        signature_data=signature_data,
    )
    full_solution = solution_for_singleton(
        lineage_proof, uint64(vault_coin.amount), inner_solution,
    )
    return make_spend(vault_coin, full_puzzle, full_solution)


def build_vault_receive_spend(
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    deed_launcher_id: bytes32,
    p2_vault_coin_id: bytes32,
    current_timestamp: int,
    lineage_proof: LineageProof,
    signature_data: Optional[bytes] = None,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> CoinSpend:
    """Build a CoinSpend for a vault 'i' (receive from pool) operation.

    Co-spend requirements (the pool must build the corresponding bundle):
      - The p2_vault coin must emit the matching `CREATE_COIN_ANNOUNCEMENT`
        with content `PROTOCOL_PREFIX || sha256(my_id || deed_launcher_id || my_inner_puzhash)`.
      - `p2_vault_coin_id` must be the id of that p2_vault coin (the one
        delivering the deed to this vault's inner puzhash).

    For EVM wallets, the 64-byte compact sig is over the EIP-712 digest
    produced by `signing_message_for_vault_spend(b"i", deed_launcher_id, vault_coin.name())`.
    """
    if p2_vault_coin_id == vault_coin.name():
        raise ValueError(
            "p2_vault_coin_id must differ from the vault coin id — the vault "
            "cannot assert its own coin announcement."
        )
    inner_puzzle = puzzle_for_vault_inner(
        vault_launcher_id, owner_pubkey_bytes, auth_type,
        members_merkle_root, pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full_puzzle = puzzle_for_singleton(vault_launcher_id, inner_puzzle)
    my_id = vault_coin.name()
    inner_solution = _inner_solution_for_receive(
        my_id=my_id,
        my_inner_puzhash=inner_puzzle.get_tree_hash(),
        my_amount=int(vault_coin.amount),
        deed_launcher_id=deed_launcher_id,
        p2_vault_coin_id=p2_vault_coin_id,
        current_timestamp=current_timestamp,
        signature_data=signature_data,
    )
    full_solution = solution_for_singleton(
        lineage_proof, uint64(vault_coin.amount), inner_solution,
    )
    return make_spend(vault_coin, full_puzzle, full_solution)


def build_vault_accept_offer_spend(
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    deed_launcher_id: bytes32,
    token_amount: int,
    pool_inner_puzhash: bytes32,
    identity_attest_root: bytes32,
    attestation_leaf_hash: bytes32,
    attestation_proof: Program,
    current_timestamp: int,
    lineage_proof: LineageProof,
    signature_data: Optional[bytes] = None,
    *,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> CoinSpend:
    if auth_type != AUTH_TYPE_BLS:
        raise ValueError("accept-offer is currently BLS-only")
    if token_amount <= 0:
        raise ValueError("token_amount must be greater than zero")
    if pool_inner_puzhash == bytes32(b"\x00" * 32):
        raise ValueError("pool_inner_puzhash must not be zero")
    if identity_attest_root == DEFAULT_IDENTITY_ATTEST_ROOT:
        raise ValueError("identity_attest_root must be enrolled before accepting offers")
    inner_puzzle = puzzle_for_vault_inner(
        vault_launcher_id, owner_pubkey_bytes, auth_type,
        members_merkle_root, pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full_puzzle = puzzle_for_singleton(vault_launcher_id, inner_puzzle)
    my_id = vault_coin.name()
    inner_solution = _inner_solution_for_accept_offer(
        my_id=my_id,
        my_inner_puzhash=inner_puzzle.get_tree_hash(),
        my_amount=int(vault_coin.amount),
        deed_launcher_id=deed_launcher_id,
        token_amount=token_amount,
        pool_inner_puzhash=pool_inner_puzhash,
        attestation_leaf_hash=attestation_leaf_hash,
        attestation_proof=attestation_proof,
        current_timestamp=current_timestamp,
        signature_data=signature_data,
    )
    full_solution = solution_for_singleton(
        lineage_proof, uint64(vault_coin.amount), inner_solution,
    )
    return make_spend(vault_coin, full_puzzle, full_solution)


def build_vault_update_identity_spend(
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    new_identity_attest_root: bytes32,
    bridge_parent_id: bytes32,
    bridge_amount: int,
    current_timestamp: int,
    lineage_proof: LineageProof,
    signature_data: Optional[bytes] = None,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> CoinSpend:
    if identity_attest_root != DEFAULT_IDENTITY_ATTEST_ROOT:
        raise ValueError("identity enrollment can only be built from the empty attestation root")
    if new_identity_attest_root == DEFAULT_IDENTITY_ATTEST_ROOT:
        raise ValueError("new_identity_attest_root must not be the empty attestation root")
    if bridge_amount <= 0:
        raise ValueError("bridge_amount must be greater than zero")
    bridge_coin_id = Coin(bridge_parent_id, zkpassport_bridge_policy_hash, uint64(bridge_amount)).name()
    if bridge_coin_id == vault_coin.name():
        raise ValueError("derived bridge coin id must differ from the vault coin id")
    inner_puzzle = puzzle_for_vault_inner(
        vault_launcher_id, owner_pubkey_bytes, auth_type,
        members_merkle_root, pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full_puzzle = puzzle_for_singleton(vault_launcher_id, inner_puzzle)
    my_id = vault_coin.name()
    inner_solution = _inner_solution_for_update_identity(
        my_id=my_id,
        my_inner_puzhash=inner_puzzle.get_tree_hash(),
        my_amount=int(vault_coin.amount),
        vault_inner_mod_hash=VAULT_INNER_MOD.get_tree_hash(),
        new_identity_attest_root=new_identity_attest_root,
        bridge_parent_id=bridge_parent_id,
        bridge_amount=bridge_amount,
        current_timestamp=current_timestamp,
        signature_data=signature_data,
    )
    full_solution = solution_for_singleton(
        lineage_proof, uint64(vault_coin.amount), inner_solution,
    )
    return make_spend(vault_coin, full_puzzle, full_solution)


def migrate_bls_signing_tree(
    deed_launcher_id: bytes32,
    new_p2_vault_puzzlehash: bytes32,
    vault_coin_id: bytes32,
) -> bytes32:
    """Return the inner of the AGG_SIG_ME message a BLS owner signs for a 'm' spend.

    Matches `(sha256tree (list SPEND_MIGRATE deed_launcher_id new_p2_vault_puzzlehash my_id))`
    inside `vault_singleton_inner.clsp`.  The network appends the coin id and
    genesis challenge to form the full AGG_SIG_ME message; this is the puzzle's
    contribution to it.
    """
    return Program.to([
        SPEND_MIGRATE,
        bytes(deed_launcher_id),
        bytes(new_p2_vault_puzzlehash),
        bytes(vault_coin_id),
    ]).get_tree_hash()


def build_vault_migrate_spend(
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    deed_launcher_id: bytes32,
    new_vault_launcher_id: bytes32,
    current_timestamp: int,
    lineage_proof: LineageProof,
    signature_data: Optional[bytes] = None,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> CoinSpend:
    """Build a CoinSpend for a vault 'm' (migrate a deed to a new vault) operation.

    The deed NFT is an NFT singleton whose inner puzzle is `p2_vault` curried to
    THIS vault's launcher id.  Migration re-binds it to `new_vault_launcher_id`
    by spending the deed to `puzzle_for_p2_vault(new_vault_launcher_id)` — the
    deed keeps its launcher id (identity preserved); only its controller changes.

    Co-spend requirements (the caller must also spend the deed coin in the same
    SpendBundle):
      - The deed (p2_vault inner) is spent with
          `singleton_inner_puzzle_hash = <this vault's inner puzzle hash>`,
          `singleton_coin_id          = vault_coin.name()`,
          `my_launcher_id             = deed_launcher_id`,
          `next_puzzlehash            = puzzle_for_p2_vault(new_vault_launcher_id).get_tree_hash()`.
      - The deed's p2_vault asserts this vault's CREATE_PUZZLE_ANNOUNCEMENT whose
        content is `PROTOCOL_PREFIX || sha256tree([my_id, deed_launcher_id, next_puzzlehash])`.

    AUTH is BLS-only (`auth_type` must be `AUTH_TYPE_BLS`); the AGG_SIG_ME inner
    message is `migrate_bls_signing_tree(deed_launcher_id, new_p2_vault_puzzlehash,
    vault_coin.name())`, produced by the CLVM and signed by the wallet.  secp
    migrate is deferred (the puzzle raises for secp AUTH_TYPEs).
    """
    new_p2_vault_puzzlehash = puzzle_for_p2_vault(new_vault_launcher_id).get_tree_hash()
    inner_puzzle = puzzle_for_vault_inner(
        vault_launcher_id, owner_pubkey_bytes, auth_type,
        members_merkle_root, pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full_puzzle = puzzle_for_singleton(vault_launcher_id, inner_puzzle)
    my_id = vault_coin.name()
    inner_solution = _inner_solution_for_migrate(
        my_id=my_id,
        my_inner_puzhash=inner_puzzle.get_tree_hash(),
        my_amount=int(vault_coin.amount),
        deed_launcher_id=deed_launcher_id,
        new_p2_vault_puzzlehash=new_p2_vault_puzzlehash,
        current_timestamp=current_timestamp,
        signature_data=signature_data,
    )
    full_solution = solution_for_singleton(
        lineage_proof, uint64(vault_coin.amount), inner_solution,
    )
    return make_spend(vault_coin, full_puzzle, full_solution)


# ---------------------------------------------------------------------------
# Spend bundle builders
# ---------------------------------------------------------------------------

def build_create_vault_bundle(
    parent_coin: Coin,
    parent_puzzle: Program,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    fee: int = 0,
    *,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
) -> tuple[SpendBundle, bytes32]:
    """Build an *unsigned* spend bundle that deploys a vault singleton.

    Returns (unsigned_bundle, vault_launcher_id).
    The caller must sign and push the bundle.

    Args:
        parent_coin:          XCH coin funding the launcher (≥ 1 + fee mojos).
        parent_puzzle:        Puzzle for parent_coin.
        owner_pubkey_bytes:   Raw pubkey bytes (48-byte BLS, 65-byte r1, or 33-byte k1).
        auth_type:            AUTH_TYPE_BLS, AUTH_TYPE_SECP256R1, or AUTH_TYPE_SECP256K1.
        members_merkle_root:  32-byte Merkle root of authorised keys.
                              For single-key vaults use one_leaf_merkle_root(owner_pubkey_bytes).
        pool_launcher_id:     The Populis pool's launcher ID.
        fee:                  Network fee in mojos.
    """
    owner_pubkey_bytes = validate_owner_pubkey_for_auth_type(owner_pubkey_bytes, auth_type)
    launcher_coin = launcher_coin_for_parent(parent_coin)
    vault_launcher_id: bytes32 = launcher_coin.name()

    vault_full_puzzle = puzzle_for_vault_full(
        vault_launcher_id,
        owner_pubkey_bytes,
        auth_type,
        members_merkle_root,
        pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    vault_puzzle_hash = vault_full_puzzle.get_tree_hash()

    # Launcher solution: (vault_puzzle_hash amount key_value_list)
    launcher_solution = Program.to([vault_puzzle_hash, SINGLETON_AMOUNT, []])

    # Parent coin solution: send 1 mojo to launcher + change back, pay fee
    change_amount = parent_coin.amount - SINGLETON_AMOUNT - fee
    assert change_amount >= 0, "parent coin too small to cover 1 mojo + fee"

    # Build p2_delegated_puzzle solution for the parent coin.
    conditions = [
        Program.to([51, SINGLETON_LAUNCHER_HASH, SINGLETON_AMOUNT]),  # launcher coin
    ]
    if change_amount > 0:
        conditions.append(Program.to([51, parent_coin.puzzle_hash, change_amount]))
    if fee > 0:
        conditions.append(Program.to([52, fee]))  # RESERVE_FEE
    parent_solution = solution_for_conditions(conditions)

    parent_spend = make_spend(parent_coin, parent_puzzle, parent_solution)
    # chia-rs 0.41's `make_spend` accepts Program directly and handles serialization.
    # (`SerializedProgram.from_program` does not exist on this version.)
    launcher_spend = make_spend(launcher_coin, SINGLETON_LAUNCHER, launcher_solution)

    unsigned_bundle = SpendBundle([parent_spend, launcher_spend], G2Element())
    return unsigned_bundle, vault_launcher_id


# ---------------------------------------------------------------------------
# High-level async driver
# ---------------------------------------------------------------------------

class VaultDriver:
    """Async driver for vault singleton lifecycle operations.

    Requires a FullNodeRpcClient and the AGG_SIG_ME_ADDITIONAL_DATA bytes
    for the target network (mainnet or testnet).
    """

    def __init__(self, node_client, agg_sig_data: bytes):
        self.node_client = node_client
        self.agg_sig_data = agg_sig_data

    async def prepare_create_vault(
        self,
        parent_coin: Coin,
        owner_pubkey_bytes: bytes,
        auth_type: int,
        members_merkle_root: bytes32,
        pool_launcher_id: bytes32,
        fee: int = 0,
        parent_puzzle: Optional[Program] = None,
        identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
    ) -> dict:
        """Build an unsigned vault creation bundle for client-side signing.

        The server never holds the user's private key.  Returns a dict with:
          - coin_spends_json: serialised CoinSpend list to be signed by the wallet
          - vault_launcher_id: hex string — permanent vault identity
          - auth_type: echoed back so the client knows which signing method to use

        BLS wallets (Goby/Sage): sign via chip0002_signCoinSpends / WalletConnect.
          parent_puzzle is derived automatically from owner_pubkey_bytes.
        secp256k1/secp256r1 wallets (MetaMask/Coinbase/Passkey):
          sign via eth_signTypedData_v4 — use signing_message_for_vault_spend()
          to get the EIP-712 digest per spend case.
          parent_puzzle MUST be provided (the XCH address funding the launcher
          is separate from the secp owner key — e.g. a standard BLS fee-payer).

        Args:
            parent_coin:          Unspent XCH coin (≥ 1 + fee mojos).
            owner_pubkey_bytes:   48-byte BLS G1, 65-byte r1, or 33-byte k1 pubkey.
            auth_type:            AUTH_TYPE_BLS / AUTH_TYPE_SECP256R1 / AUTH_TYPE_SECP256K1.
            members_merkle_root:  32-byte Merkle root. Use one_leaf_merkle_root() for single-key.
            pool_launcher_id:     Populis pool launcher ID.
            fee:                  Network fee in mojos.
            parent_puzzle:        Required for secp auth types; ignored for BLS
                                  (derived automatically from owner_pubkey_bytes).
        """
        owner_pubkey_bytes = validate_owner_pubkey_for_auth_type(owner_pubkey_bytes, auth_type)
        if auth_type == AUTH_TYPE_BLS:
            owner_pk = G1Element.from_bytes(owner_pubkey_bytes)
            parent_puzzle = puzzle_for_pk(owner_pk)
        else:
            if parent_puzzle is None:
                raise ValueError(
                    "parent_puzzle is required for AUTH_TYPE_SECP256K1 / AUTH_TYPE_SECP256R1 — "
                    "the XCH fee-payer puzzle must be supplied separately from the secp owner key."
                )

        unsigned_bundle, vault_launcher_id = build_create_vault_bundle(
            parent_coin, parent_puzzle, owner_pubkey_bytes, auth_type,
            members_merkle_root, pool_launcher_id, fee,
            identity_attest_root=identity_attest_root,
            zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
        )

        coin_spends_json = [
            cs.to_json_dict() for cs in unsigned_bundle.coin_spends
        ]

        logger.info("Prepared vault creation bundle. launcher_id=0x%s auth_type=%s",
                    vault_launcher_id.hex(), auth_type)
        return {
            "coin_spends_json": coin_spends_json,
            "vault_launcher_id": vault_launcher_id.hex(),
            "auth_type": auth_type,
        }

    async def submit_signed(
        self,
        coin_spends_json: list,
        signature_hex: str,
    ) -> dict:
        """Assemble a signed SpendBundle and push to the full node.

        Args:
            coin_spends_json: The coin_spends_json returned by prepare_create_vault.
            signature_hex:    Aggregated BLS G2Element hex (from wallet signing)
                              OR 64-byte compact secp256k1 sig hex (from EVM wallet).
        """
        from chia.types.coin_spend import CoinSpend as _CoinSpend
        from chia_rs import G2Element as _G2Element

        coin_spends = [_CoinSpend.from_json_dict(cs) for cs in coin_spends_json]
        agg_sig = _G2Element.from_bytes(bytes.fromhex(signature_hex))
        signed_bundle = SpendBundle(coin_spends, agg_sig)

        status = await self.node_client.push_tx(signed_bundle)
        if not status.get("success"):
            raise RuntimeError(f"Vault submission failed: {status}")
        return {"success": True, "status": status}

    async def get_vault_coin(self, vault_launcher_id: bytes32) -> Optional[Coin]:
        """Return the current (unspent) vault singleton coin, or None."""
        records = await self.node_client.get_coin_records_by_parent_ids(
            [vault_launcher_id], include_spent_coins=False
        )
        if not records:
            return None
        return records[0].coin

    def vault_puzzle_hash(
        self,
        vault_launcher_id: bytes32,
        owner_pubkey_bytes: bytes,
        auth_type: int,
        members_merkle_root: bytes32,
        pool_launcher_id: bytes32,
        *,
        identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash: bytes32 = DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
    ) -> bytes32:
        """Compute the puzzle hash of the vault singleton."""
        return puzzle_for_vault_full(
            vault_launcher_id,
            owner_pubkey_bytes,
            auth_type,
            members_merkle_root,
            pool_launcher_id,
            identity_attest_root=identity_attest_root,
            zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
        ).get_tree_hash()

    def p2_vault_puzzle_hash(self, vault_launcher_id: bytes32) -> bytes32:
        """Compute the p2_vault puzzle hash — where deed NFTs land when returned from pool."""
        return puzzle_for_p2_vault(vault_launcher_id).get_tree_hash()
