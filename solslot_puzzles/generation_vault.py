"""Exact SGT authorization behind a stable customer custody vault launcher.

This is an additive V2-compatible vault module. It does not change or stand in
for the recovery-aware administrator identity authority. No ID proof is needed
to receive, transfer or vote SGT. Contract message signing still requires the
existing client-side full-spend validation before reaching a wallet.
"""
from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.generation_registry import singleton_struct
from solslot_puzzles.generation_sgt import SGTBindings, SGTOutput, transition_digest
from solslot_puzzles.vault_driver import eip712_typed_data_for_vault_spend, signing_message_for_vault_spend
from solslot_puzzles.vault_v2_driver import puzzle_for_vault_v2_inner

SPEND_GENERATION_SGT = b'g'


def vault_inner(**kwargs) -> Program:
    # Reuse validated V2 argument construction, preserving all nine bindings.
    _, args = puzzle_for_vault_v2_inner(**kwargs).uncurry()
    return load_puzzle('vault_singleton_inner_generation_v1.clsp').curry(*args.as_iter())


def sgt_owner(generation: bytes32, vault_launcher: bytes32) -> Program:
    if generation == bytes32.zeros or vault_launcher == bytes32.zeros:
        raise ValueError('generation and recipient vault must be nonzero')
    return load_puzzle('generation_sgt_vault_owner_v1.clsp').curry(generation, singleton_struct(vault_launcher))


def authorization_hash(generation: bytes32, vault_coin_id: bytes32, sgt_coin_id: bytes32,
                       digest: bytes32, expires: int) -> bytes32:
    if any(v == bytes32.zeros for v in (generation, vault_coin_id, sgt_coin_id, digest)):
        raise ValueError('authorization commitments must be nonzero')
    if sgt_coin_id == vault_coin_id or type(expires) is not int or not 0 < expires < 2**64:
        raise ValueError('invalid SGT authorization input or expiry')
    return Program.to([b'SGT_VAULT_AUTH_V1', generation, vault_coin_id, sgt_coin_id, digest, expires]).get_tree_hash()


def signing_data(generation, vault_coin_id, sgt_coin_id, digest, expires) -> dict:
    operation = authorization_hash(generation, vault_coin_id, sgt_coin_id, digest, expires)
    return eip712_typed_data_for_vault_spend(SPEND_GENERATION_SGT, operation, vault_coin_id)


def signing_digest(generation, vault_coin_id, sgt_coin_id, digest, expires) -> bytes:
    operation = authorization_hash(generation, vault_coin_id, sgt_coin_id, digest, expires)
    return signing_message_for_vault_spend(SPEND_GENERATION_SGT, operation, vault_coin_id)


def authorization_solution(generation, vault_coin, inner, sgt_coin_id, digest, expires, signature=b'') -> Program:
    authorization_hash(generation, vault_coin.name(), sgt_coin_id, digest, expires)
    return Program.to([vault_coin.name(), inner.get_tree_hash(), vault_coin.amount, SPEND_GENERATION_SGT,
                       [generation, sgt_coin_id, digest, expires, signature]])


def owner_solution(vault_coin, inner, sgt_coin_id, action: str, outputs: tuple[SGTOutput, ...], expires: int) -> Program:
    if action not in {'TRANSFER', 'LOCK'}:
        raise ValueError('SGT owner may authorize only a transfer or complete-input lock')
    return Program.to([inner.get_tree_hash(), vault_coin.name(), sgt_coin_id, action.encode(),
                       [v.descriptor() for v in outputs], expires])
