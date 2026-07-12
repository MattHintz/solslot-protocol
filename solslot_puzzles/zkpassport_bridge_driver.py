from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.lineage_proof import LineageProof
from chia_rs import G2Element, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle
from solslot_puzzles.vault_driver import build_vault_update_identity_spend
from solslot_puzzles.zkpassport_attestation import (
    compute_attestation_bridge_message,
    compute_validator_bridge_message,
)


# ---------------------------------------------------------------------------
# Testnet11 validator configuration (1-of-1, single operator validator node).
# These constants are derived once and pinned here so the protocol, API, and
# portal all reference the same authoritative values.
#
# To regenerate for a new validator keypair:
#   seed  = secrets.token_bytes(32)
#   sk    = AugSchemeMPL.key_gen(seed)
#   pk    = sk.get_g1()
#   hash  = make_bridge_policy_hash([bytes(pk)], threshold=1)
#
# This deterministic key is a test vector only. The clean genesis ceremony
# must generate a fresh key and publish its resulting policy hash.
# ---------------------------------------------------------------------------

TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY_HEX: str = (
    "a8f9b0c1f992c49210fc726fc610885b966f84747126753659c6c3f8ae5bf3ba"
    "f5b6e1a399fc8a749daf45dd74efac4c"
)
TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY: bytes = bytes.fromhex(
    TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY_HEX
)
TESTNET11_ZKPASSPORT_VALIDATOR_THRESHOLD: int = 1

TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH: bytes32 = bytes32.fromhex(
    "75e9cc22c2b717e4216b7d1fec34c14903b83598b308ecc4517bbbd8d17a9a2a"
)

_ZKPASSPORT_BRIDGE_MOD: Program | None = None


def zkpassport_bridge_mod() -> Program:
    global _ZKPASSPORT_BRIDGE_MOD
    if _ZKPASSPORT_BRIDGE_MOD is None:
        _ZKPASSPORT_BRIDGE_MOD = load_puzzle("zkpassport_bridge_message.clsp")
    return _ZKPASSPORT_BRIDGE_MOD


def make_bridge_puzzle(validator_pubkeys: Sequence[bytes], threshold: int) -> Program:
    _validate_pubkeys(validator_pubkeys, "validator_pubkeys")
    _validate_threshold(threshold, len(validator_pubkeys))
    return zkpassport_bridge_mod().curry(list(validator_pubkeys), int(threshold))


def make_bridge_policy_hash(validator_pubkeys: Sequence[bytes], threshold: int) -> bytes32:
    return bytes32(make_bridge_puzzle(validator_pubkeys, threshold).get_tree_hash())


@dataclass(frozen=True)
class BridgeSpendArtifacts:
    coin_spend: CoinSpend
    puzzle: Program
    solution: Program
    bridge_policy_hash: bytes32
    bridge_coin_id: bytes32
    bridge_message: bytes32
    validator_message: bytes32


@dataclass(frozen=True)
class BridgeVaultEnrollmentBundle:
    spend_bundle: SpendBundle
    bridge: BridgeSpendArtifacts
    vault_spend: CoinSpend


def build_bridge_spend(
    *,
    bridge_coin: Coin,
    validator_pubkeys: Sequence[bytes],
    threshold: int,
    signer_indices: Sequence[int],
    vault_launcher_id: bytes32,
    new_identity_attest_root: bytes32,
    attestation_leaf_hash: bytes32,
    scoped_nullifier: bytes32,
    nullifier_type: int,
    service_scope_hash: bytes32,
    service_subscope_hash: bytes32,
    proof_timestamp: int,
) -> BridgeSpendArtifacts:
    puzzle = make_bridge_puzzle(validator_pubkeys, threshold)
    bridge_policy_hash = bytes32(puzzle.get_tree_hash())
    if bridge_coin.puzzle_hash != bridge_policy_hash:
        raise ValueError("bridge_coin puzzle hash must equal the bridge policy hash")
    if int(bridge_coin.amount) <= 0:
        raise ValueError("bridge_coin amount must be greater than zero")
    _validate_signer_indices(signer_indices, threshold, len(validator_pubkeys))
    bridge_coin_id = bridge_coin.name()
    bridge_message = compute_attestation_bridge_message(
        vault_launcher_id=vault_launcher_id,
        attestation_root=new_identity_attest_root,
        bridge_policy_hash=bridge_policy_hash,
    )
    validator_message = compute_validator_bridge_message(
        vault_launcher_id=vault_launcher_id,
        attestation_root=new_identity_attest_root,
        bridge_policy_hash=bridge_policy_hash,
        bridge_coin_id=bridge_coin_id,
        bridge_message=bridge_message,
        attestation_leaf_hash=attestation_leaf_hash,
        scoped_nullifier=scoped_nullifier,
        nullifier_type=nullifier_type,
        service_scope_hash=service_scope_hash,
        service_subscope_hash=service_subscope_hash,
        proof_timestamp=proof_timestamp,
    )
    solution = solution_for_bridge_spend(
        bridge_coin=bridge_coin,
        bridge_policy_hash=bridge_policy_hash,
        vault_launcher_id=vault_launcher_id,
        new_identity_attest_root=new_identity_attest_root,
        attestation_leaf_hash=attestation_leaf_hash,
        scoped_nullifier=scoped_nullifier,
        nullifier_type=nullifier_type,
        service_scope_hash=service_scope_hash,
        service_subscope_hash=service_subscope_hash,
        proof_timestamp=proof_timestamp,
        signer_indices=signer_indices,
    )
    return BridgeSpendArtifacts(
        coin_spend=make_spend(bridge_coin, puzzle, solution),
        puzzle=puzzle,
        solution=solution,
        bridge_policy_hash=bridge_policy_hash,
        bridge_coin_id=bridge_coin_id,
        bridge_message=bridge_message,
        validator_message=validator_message,
    )


def solution_for_bridge_spend(
    *,
    bridge_coin: Coin,
    bridge_policy_hash: bytes32,
    vault_launcher_id: bytes32,
    new_identity_attest_root: bytes32,
    attestation_leaf_hash: bytes32,
    scoped_nullifier: bytes32,
    nullifier_type: int,
    service_scope_hash: bytes32,
    service_subscope_hash: bytes32,
    proof_timestamp: int,
    signer_indices: Sequence[int],
) -> Program:
    return Program.to(
        [
            bytes(bridge_coin.name()),
            bytes(bridge_policy_hash),
            int(bridge_coin.amount),
            bytes(vault_launcher_id),
            bytes(new_identity_attest_root),
            bytes(attestation_leaf_hash),
            bytes(scoped_nullifier),
            _uint_to_bytes32(nullifier_type),
            bytes(service_scope_hash),
            bytes(service_subscope_hash),
            _uint_to_bytes32(proof_timestamp),
            list(signer_indices),
        ]
    )


def build_bridge_and_vault_update_identity_bundle(
    *,
    bridge_parent_id: bytes32,
    bridge_amount: int,
    validator_pubkeys: Sequence[bytes],
    threshold: int,
    signer_indices: Sequence[int],
    vault_coin: Coin,
    vault_launcher_id: bytes32,
    owner_pubkey_bytes: bytes,
    auth_type: int,
    members_merkle_root: bytes32,
    pool_launcher_id: bytes32,
    new_identity_attest_root: bytes32,
    attestation_leaf_hash: bytes32,
    scoped_nullifier: bytes32,
    nullifier_type: int,
    service_scope_hash: bytes32,
    service_subscope_hash: bytes32,
    proof_timestamp: int,
    current_timestamp: int,
    lineage_proof: LineageProof,
    signature_data: bytes | None = None,
) -> BridgeVaultEnrollmentBundle:
    bridge_policy_hash = make_bridge_policy_hash(validator_pubkeys, threshold)
    bridge_coin = Coin(bridge_parent_id, bridge_policy_hash, uint64(bridge_amount))
    bridge = build_bridge_spend(
        bridge_coin=bridge_coin,
        validator_pubkeys=validator_pubkeys,
        threshold=threshold,
        signer_indices=signer_indices,
        vault_launcher_id=vault_launcher_id,
        new_identity_attest_root=new_identity_attest_root,
        attestation_leaf_hash=attestation_leaf_hash,
        scoped_nullifier=scoped_nullifier,
        nullifier_type=nullifier_type,
        service_scope_hash=service_scope_hash,
        service_subscope_hash=service_subscope_hash,
        proof_timestamp=proof_timestamp,
    )
    vault_spend = build_vault_update_identity_spend(
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher_id,
        owner_pubkey_bytes=owner_pubkey_bytes,
        auth_type=auth_type,
        members_merkle_root=members_merkle_root,
        pool_launcher_id=pool_launcher_id,
        new_identity_attest_root=new_identity_attest_root,
        bridge_parent_id=bridge_parent_id,
        bridge_amount=bridge_amount,
        current_timestamp=current_timestamp,
        lineage_proof=lineage_proof,
        signature_data=signature_data,
        zkpassport_bridge_policy_hash=bridge.bridge_policy_hash,
    )
    return BridgeVaultEnrollmentBundle(
        spend_bundle=SpendBundle([bridge.coin_spend, vault_spend], G2Element()),
        bridge=bridge,
        vault_spend=vault_spend,
    )


def _validate_pubkeys(pubkeys: Sequence[bytes], field: str) -> None:
    if not pubkeys:
        raise ValueError(f"{field} must not be empty")
    seen: set[bytes] = set()
    for i, pubkey in enumerate(pubkeys):
        value = bytes(pubkey)
        if len(value) != 48:
            raise ValueError(f"{field}[{i}] must be 48-byte BLS G1 pubkey, got {len(value)} bytes")
        if value in seen:
            raise ValueError(f"{field} contains duplicate pubkey at index {i}")
        seen.add(value)


def _validate_threshold(threshold: int, pubkey_count: int) -> None:
    if threshold < 1 or threshold > pubkey_count:
        raise ValueError(f"threshold must be in [1, {pubkey_count}], got {threshold}")


def _validate_signer_indices(indices: Sequence[int], threshold: int, pubkey_count: int) -> None:
    if len(indices) < threshold:
        raise ValueError(f"need ≥ {threshold} signers, got {len(indices)}")
    last = -1
    for idx in indices:
        if idx <= last:
            raise ValueError("signer_indices must be sorted strictly ascending")
        if idx < 0 or idx >= pubkey_count:
            raise ValueError(f"signer index {idx} out of range [0, {pubkey_count - 1}]")
        last = idx


def _uint_to_bytes32(value: int) -> bytes:
    if value < 0:
        raise ValueError("uint value must be non-negative")
    return int(value).to_bytes(32, "big")


__all__ = [
    "BridgeSpendArtifacts",
    "BridgeVaultEnrollmentBundle",
    "TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH",
    "TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY",
    "TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY_HEX",
    "TESTNET11_ZKPASSPORT_VALIDATOR_THRESHOLD",
    "build_bridge_and_vault_update_identity_bundle",
    "build_bridge_spend",
    "make_bridge_policy_hash",
    "make_bridge_puzzle",
    "solution_for_bridge_spend",
    "zkpassport_bridge_mod",
]
