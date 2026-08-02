from __future__ import annotations

import hashlib

import chia_rs
import pytest
from chia.types.blockchain_format.program import Program
from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_deployment import singleton_struct
from solslot_puzzles.sgt_driver import (
    SGT_LOCK,
    sgt_free_inner_mod,
    sgt_free_inner_puzzle,
    sgt_locked_inner_mod,
    sgt_locked_inner_puzzle,
)
from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    puzzle_for_p2_vault,
)
from solslot_puzzles.vault_v2_driver import (
    inner_solution_for_p2_vault_sgt_lock,
    inner_solution_for_sgt_lock,
    puzzle_for_vault_v2_inner,
    sgt_lock_operation_hash,
    signing_digest_for_sgt_lock,
    vault_sgt_lock_coin_announcement_id,
    vault_sgt_lock_puzzle_announcement,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


VAULT_LAUNCHER = b32(0x11)
POOL_LAUNCHER = b32(0x12)
MEMBERS_ROOT = b32(0x13)
IDENTITY_ROOT = b32(0x14)
BRIDGE_POLICY = b32(0x15)
VAULT_COIN_ID = b32(0x16)
SGT_COIN_ID = b32(0x17)
PROPOSAL_HASH = b32(0x18)
TRACKER = singleton_struct(b32(0x19))
LOCK_DEADLINE = 1_900_000_000
SGT_AMOUNT = 25_000
EIP712_RUN_FLAGS = (
    chia_rs.MEMPOOL_MODE
    | chia_rs.ENABLE_SECP_OPS
    | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
)


def opcode(value: ConditionOpcode) -> int:
    return int.from_bytes(value.value, "big", signed=True)


def conditions(output: Program) -> list[list[Program]]:
    return [list(item.as_iter()) for item in output.as_iter()]


def vault_inner(owner: bytes, auth_type: int) -> Program:
    return puzzle_for_vault_v2_inner(
        vault_launcher_id=VAULT_LAUNCHER,
        owner_pubkey=owner,
        auth_type=auth_type,
        members_merkle_root=MEMBERS_ROOT,
        pool_launcher_id=POOL_LAUNCHER,
        identity_attest_root=IDENTITY_ROOT,
        zkpassport_bridge_policy_hash=BRIDGE_POLICY,
    )


def locked_inner_hash() -> bytes32:
    return bytes32(
        sgt_locked_inner_puzzle(
            bytes32(sgt_free_inner_mod().get_tree_hash()),
            TRACKER,
            bytes32(puzzle_for_p2_vault(VAULT_LAUNCHER).get_tree_hash()),
            PROPOSAL_HASH,
            LOCK_DEADLINE,
        ).get_tree_hash()
    )


def operation_hash() -> bytes32:
    return sgt_lock_operation_hash(
        vault_coin_id=VAULT_COIN_ID,
        sgt_coin_id=SGT_COIN_ID,
        proposal_hash=PROPOSAL_HASH,
        lock_deadline=LOCK_DEADLINE,
        locked_inner_puzzle_hash=locked_inner_hash(),
    )


def secp256k1_keypair_and_sign(digest: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    private_key = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    der = private_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s > order // 2:
        s = order - s
    return public_key, r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_bls_vault_authorizes_only_the_exact_sgt_lock() -> None:
    inner = vault_inner(bytes(G1Element.generator()), AUTH_TYPE_BLS)
    output = inner.run(
        inner_solution_for_sgt_lock(
            vault_coin_id=VAULT_COIN_ID,
            vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
            vault_amount=1,
            sgt_coin_id=SGT_COIN_ID,
            proposal_hash=PROPOSAL_HASH,
            lock_deadline=LOCK_DEADLINE,
            locked_inner_puzzle_hash=locked_inner_hash(),
        )
    )
    conds = conditions(output)
    agg_sig = next(item for item in conds if item[0].as_int() == 50)
    assert bytes32(agg_sig[2].as_atom()) == operation_hash()
    puzzle_announcement = next(
        item for item in conds
        if item[0].as_int() == opcode(ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT)
    )
    assert puzzle_announcement[1].as_atom() == vault_sgt_lock_puzzle_announcement(
        vault_coin_id=VAULT_COIN_ID,
        sgt_coin_id=SGT_COIN_ID,
        locked_inner_puzzle_hash=locked_inner_hash(),
    )
    coin_assertion = next(
        item for item in conds
        if item[0].as_int() == opcode(ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT)
    )
    assert bytes32(coin_assertion[1].as_atom()) == vault_sgt_lock_coin_announcement_id(
        vault_coin_id=VAULT_COIN_ID,
        sgt_coin_id=SGT_COIN_ID,
        locked_inner_puzzle_hash=locked_inner_hash(),
    )


def test_existing_p2_vault_pairs_with_the_sgt_lock_without_a_new_custody_puzzle() -> None:
    owner = bytes(G1Element.generator())
    inner = vault_inner(owner, AUTH_TYPE_BLS)
    full = puzzle_for_singleton(VAULT_LAUNCHER, inner)
    p2_vault = puzzle_for_p2_vault(VAULT_LAUNCHER)
    free_inner = sgt_free_inner_puzzle(
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        TRACKER,
        bytes32(p2_vault.get_tree_hash()),
    )
    p2_solution = inner_solution_for_p2_vault_sgt_lock(
        vault_coin_id=VAULT_COIN_ID,
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        sgt_coin_id=SGT_COIN_ID,
        sgt_free_inner_puzzle_hash=bytes32(free_inner.get_tree_hash()),
        sgt_amount=SGT_AMOUNT,
        locked_inner_puzzle_hash=locked_inner_hash(),
    )
    p2_conditions = conditions(p2_vault.run(p2_solution))
    puzzle_assertion = next(
        item for item in p2_conditions
        if item[0].as_int() == opcode(ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT)
    )
    expected_puzzle_announcement_id = hashlib.sha256(
        bytes(full.get_tree_hash())
        + vault_sgt_lock_puzzle_announcement(
            vault_coin_id=VAULT_COIN_ID,
            sgt_coin_id=SGT_COIN_ID,
            locked_inner_puzzle_hash=locked_inner_hash(),
        )
    ).digest()
    assert puzzle_assertion[1].as_atom() == expected_puzzle_announcement_id

    free_output = free_inner.run(
        Program.to(
            [
                SGT_LOCK,
                p2_vault,
                p2_solution,
                [PROPOSAL_HASH, LOCK_DEADLINE, SGT_AMOUNT],
            ]
        )
    )
    free_conditions = conditions(free_output)
    locked_output = next(
        item for item in free_conditions
        if item[0].as_int() == opcode(ConditionOpcode.CREATE_COIN)
    )
    assert bytes32(locked_output[1].as_atom()) == locked_inner_hash()
    assert locked_output[2].as_int() == SGT_AMOUNT


def test_evm_signature_cannot_be_replayed_for_another_sgt_proposal() -> None:
    digest = signing_digest_for_sgt_lock(operation_hash(), VAULT_COIN_ID)
    public_key, signature = secp256k1_keypair_and_sign(digest)
    inner = vault_inner(public_key, AUTH_TYPE_SECP256K1)
    valid = inner_solution_for_sgt_lock(
        vault_coin_id=VAULT_COIN_ID,
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        vault_amount=1,
        sgt_coin_id=SGT_COIN_ID,
        proposal_hash=PROPOSAL_HASH,
        lock_deadline=LOCK_DEADLINE,
        locked_inner_puzzle_hash=locked_inner_hash(),
        signature_data=signature,
    )
    assert inner.run(valid, flags=EIP712_RUN_FLAGS)

    altered = inner_solution_for_sgt_lock(
        vault_coin_id=VAULT_COIN_ID,
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        vault_amount=1,
        sgt_coin_id=SGT_COIN_ID,
        proposal_hash=b32(0x55),
        lock_deadline=LOCK_DEADLINE,
        locked_inner_puzzle_hash=locked_inner_hash(),
        signature_data=signature,
    )
    with pytest.raises(Exception):
        inner.run(altered, flags=EIP712_RUN_FLAGS)


def test_sgt_lock_solution_rejects_a_vault_coin_as_its_own_sgt_coin() -> None:
    with pytest.raises(ValueError, match="differ from the vault coin"):
        inner_solution_for_sgt_lock(
            vault_coin_id=VAULT_COIN_ID,
            vault_inner_puzzle_hash=b32(0x61),
            vault_amount=1,
            sgt_coin_id=VAULT_COIN_ID,
            proposal_hash=PROPOSAL_HASH,
            lock_deadline=LOCK_DEADLINE,
            locked_inner_puzzle_hash=locked_inner_hash(),
        )
