"""RC22 vault helpers for reviewed SmartDeed/Sols operations."""
from __future__ import annotations

from typing import Optional

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    AUTH_TYPE_SECP256R1,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
    eip712_typed_data_for_vault_spend,
    signing_message_for_vault_spend,
    validate_owner_pubkey_for_auth_type,
)


SPEND_AUTHORIZE_SOLS_SWAP = 0x73  # "s"
VAULT_SOLS_SWAP_TAG = b"VSOL"

_VAULT_V2_MOD: Program | None = None


def vault_v2_inner_mod() -> Program:
    global _VAULT_V2_MOD
    if _VAULT_V2_MOD is None:
        _VAULT_V2_MOD = load_puzzle("vault_singleton_inner_v2.clsp")
    return _VAULT_V2_MOD


def vault_v2_inner_mod_hash() -> bytes32:
    return bytes32(vault_v2_inner_mod().get_tree_hash())


def puzzle_for_vault_v2_inner(
    *,
    vault_launcher_id: bytes32,
    owner_pubkey: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    identity_attest_root: bytes32 = DEFAULT_IDENTITY_ATTEST_ROOT,
    zkpassport_bridge_policy_hash: bytes32 = (
        DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH
    ),
) -> Program:
    owner = validate_owner_pubkey_for_auth_type(owner_pubkey, auth_type)
    singleton_struct = Program.to(
        (
            SINGLETON_MOD_HASH,
            (vault_launcher_id, SINGLETON_LAUNCHER_HASH),
        )
    )
    return vault_v2_inner_mod().curry(
        singleton_struct,
        owner,
        auth_type,
        members_merkle_root,
        identity_attest_root,
        zkpassport_bridge_policy_hash,
        SINGLETON_MOD_HASH,
        pool_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )


def puzzle_for_vault_v2_full(**kwargs: object) -> Program:
    launcher_id = kwargs["vault_launcher_id"]
    if not isinstance(launcher_id, bytes32):
        raise TypeError("vault_launcher_id must be bytes32")
    return puzzle_for_singleton(
        launcher_id,
        puzzle_for_vault_v2_inner(**kwargs),
    )


def vault_sols_operation_announcement(
    operation_hash: bytes32,
    vault_coin_id: bytes32,
) -> bytes:
    return b"S" + bytes(
        Program.to(
            [VAULT_SOLS_SWAP_TAG, operation_hash, vault_coin_id]
        ).get_tree_hash()
    )


def eip712_typed_data_for_sols_swap(
    operation_hash: bytes32,
    vault_coin_id: bytes32,
) -> dict:
    return eip712_typed_data_for_vault_spend(
        bytes([SPEND_AUTHORIZE_SOLS_SWAP]),
        operation_hash,
        vault_coin_id,
    )


def signing_digest_for_sols_swap(
    operation_hash: bytes32,
    vault_coin_id: bytes32,
) -> bytes32:
    return bytes32(
        signing_message_for_vault_spend(
            bytes([SPEND_AUTHORIZE_SOLS_SWAP]),
            operation_hash,
            vault_coin_id,
        )
    )


def inner_solution_for_sols_swap(
    *,
    vault_coin_id: bytes32,
    vault_inner_puzzle_hash: bytes32,
    vault_amount: int,
    operation_hash: bytes32,
    quote_expires_at: int,
    signature_data: Optional[bytes] = None,
) -> Program:
    if vault_amount <= 0:
        raise ValueError("vault_amount must be positive")
    if quote_expires_at <= 0:
        raise ValueError("quote_expires_at must be positive")
    return Program.to(
        [
            vault_coin_id,
            vault_inner_puzzle_hash,
            vault_amount,
            SPEND_AUTHORIZE_SOLS_SWAP,
            [
                operation_hash,
                quote_expires_at,
                signature_data or b"",
            ],
        ]
    )


def build_vault_sols_swap_spend(
    *,
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    identity_attest_root: bytes32,
    zkpassport_bridge_policy_hash: bytes32,
    operation_hash: bytes32,
    quote_expires_at: int,
    lineage_proof: LineageProof,
    signature_data: Optional[bytes] = None,
) -> CoinSpend:
    if identity_attest_root == DEFAULT_IDENTITY_ATTEST_ROOT:
        raise ValueError("vault must have a zkPassport attestation")
    if (
        zkpassport_bridge_policy_hash
        == DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH
    ):
        raise ValueError("zkPassport bridge policy must be pinned")
    inner = puzzle_for_vault_v2_inner(
        vault_launcher_id=vault_launcher_id,
        owner_pubkey=owner_pubkey,
        auth_type=auth_type,
        members_merkle_root=members_merkle_root,
        pool_launcher_id=pool_launcher_id,
        identity_attest_root=identity_attest_root,
        zkpassport_bridge_policy_hash=zkpassport_bridge_policy_hash,
    )
    full = puzzle_for_singleton(vault_launcher_id, inner)
    inner_solution = inner_solution_for_sols_swap(
        vault_coin_id=vault_coin.name(),
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        vault_amount=int(vault_coin.amount),
        operation_hash=operation_hash,
        quote_expires_at=quote_expires_at,
        signature_data=signature_data,
    )
    solution = solution_for_singleton(
        lineage_proof,
        uint64(vault_coin.amount),
        inner_solution,
    )
    return make_spend(vault_coin, full, solution)


__all__ = [
    "SPEND_AUTHORIZE_SOLS_SWAP",
    "VAULT_SOLS_SWAP_TAG",
    "vault_v2_inner_mod",
    "vault_v2_inner_mod_hash",
    "puzzle_for_vault_v2_inner",
    "puzzle_for_vault_v2_full",
    "vault_sols_operation_announcement",
    "eip712_typed_data_for_sols_swap",
    "signing_digest_for_sols_swap",
    "inner_solution_for_sols_swap",
    "build_vault_sols_swap_spend",
    "AUTH_TYPE_BLS",
    "AUTH_TYPE_SECP256R1",
    "AUTH_TYPE_SECP256K1",
]
