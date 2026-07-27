from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs import G1Element
from chia_rs.sized_bytes import bytes32
import chia_rs
import pytest

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    ZKPASSPORT_EMPTY_ATTEST_ROOT,
)
from solslot_puzzles.vault_v2_driver import (
    SPEND_AUTHORIZE_SOLS_SWAP,
    inner_solution_for_sols_swap,
    puzzle_for_vault_v2_inner,
    signing_digest_for_sols_swap,
    vault_sols_operation_announcement,
    vault_v2_inner_mod,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


VAULT_ID = b32(0x11)
POOL_ID = b32(0x12)
MEMBERS_ROOT = b32(0x13)
IDENTITY_ROOT = b32(0x14)
BRIDGE_POLICY = b32(0x15)
OPERATION_HASH = b32(0x16)
VAULT_COIN_ID = b32(0x17)
QUOTE_EXPIRES = 1_900_000_000
EIP712_RUN_FLAGS = (
    chia_rs.MEMPOOL_MODE
    | chia_rs.ENABLE_SECP_OPS
    | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
)


def _secp256k1_keypair_and_sign(digest: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    private_key = ec.generate_private_key(
        ec.SECP256K1(),
        backend=default_backend(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    der = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    r, s = utils.decode_dss_signature(der)
    order = (
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    )
    if s > order // 2:
        s = order - s
    return public_key, r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _inner(owner: bytes, auth_type: int, *, identity: bytes32 = IDENTITY_ROOT) -> Program:
    return puzzle_for_vault_v2_inner(
        vault_launcher_id=VAULT_ID,
        owner_pubkey=owner,
        auth_type=auth_type,
        members_merkle_root=MEMBERS_ROOT,
        pool_launcher_id=POOL_ID,
        identity_attest_root=identity,
        zkpassport_bridge_policy_hash=BRIDGE_POLICY,
    )


def test_vault_v2_module_compiles_and_keeps_pool_identity() -> None:
    assert len(vault_v2_inner_mod().as_bin()) > 0
    inner = _inner(bytes(G1Element.generator()), AUTH_TYPE_BLS)
    uncurried = inner.uncurry()
    assert uncurried is not None
    _, args = uncurried
    values = list(args.as_iter())
    assert values[0] == Program.to(
        (
            SINGLETON_MOD_HASH,
            (VAULT_ID, SINGLETON_LAUNCHER_HASH),
        )
    )
    assert bytes32(values[7].as_atom()) == POOL_ID


def test_bls_vault_authorizes_one_exact_sols_operation() -> None:
    inner = _inner(bytes(G1Element.generator()), AUTH_TYPE_BLS)
    solution = inner_solution_for_sols_swap(
        vault_coin_id=VAULT_COIN_ID,
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        vault_amount=1,
        operation_hash=OPERATION_HASH,
        quote_expires_at=QUOTE_EXPIRES,
    )
    conditions = list(inner.run(solution).as_iter())
    agg_sig = next(
        condition
        for condition in conditions
        if condition.first().as_int() == 50
    )
    assert agg_sig.rest().rest().first().as_atom() == OPERATION_HASH
    announcement = next(
        condition
        for condition in conditions
        if condition.first().as_int() == 62
    )
    assert announcement.rest().first().as_atom() == (
        vault_sols_operation_announcement(
            OPERATION_HASH,
            VAULT_COIN_ID,
        )
    )


def test_evm_signature_is_bound_to_operation_and_current_vault_coin() -> None:
    digest = signing_digest_for_sols_swap(
        OPERATION_HASH,
        VAULT_COIN_ID,
    )
    public_key, signature = _secp256k1_keypair_and_sign(digest)
    inner = _inner(public_key, AUTH_TYPE_SECP256K1)
    solution = inner_solution_for_sols_swap(
        vault_coin_id=VAULT_COIN_ID,
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        vault_amount=1,
        operation_hash=OPERATION_HASH,
        quote_expires_at=QUOTE_EXPIRES,
        signature_data=signature,
    )
    conditions = inner.run(solution, flags=EIP712_RUN_FLAGS).as_python()
    assert any(
        condition[0] == b"\x01"
        and b"secp256k1 ok" in condition[1]
        for condition in conditions
    )
    assert not any(condition[0] == b"\x32" for condition in conditions)

    replay = inner_solution_for_sols_swap(
        vault_coin_id=b32(0x18),
        vault_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        vault_amount=1,
        operation_hash=OPERATION_HASH,
        quote_expires_at=QUOTE_EXPIRES,
        signature_data=signature,
    )
    with pytest.raises(Exception):
        inner.run(replay, flags=EIP712_RUN_FLAGS)


def test_unenrolled_vault_cannot_authorize_sols_swap() -> None:
    inner = _inner(
        bytes(G1Element.generator()),
        AUTH_TYPE_BLS,
        identity=ZKPASSPORT_EMPTY_ATTEST_ROOT,
    )
    solution = Program.to(
        [
            VAULT_COIN_ID,
            inner.get_tree_hash(),
            1,
            SPEND_AUTHORIZE_SOLS_SWAP,
            [OPERATION_HASH, QUOTE_EXPIRES, b""],
        ]
    )
    with pytest.raises(Exception):
        inner.run(solution)
