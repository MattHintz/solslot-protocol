"""Explicit new-deployment bridge builder; legacy defaults remain unchanged."""
from __future__ import annotations
from typing import Sequence
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import make_spend
from chia_rs.sized_bytes import bytes32
from . import load_puzzle
from .enrollment_permit import EnrollmentPermit
from .zkpassport_bridge_driver import (
    BridgeSpendArtifacts, require_genesis_validator_set, solution_for_bridge_spend,
    _validate_signer_indices,
)
from .zkpassport_attestation import compute_attestation_bridge_message, compute_validator_bridge_message


def make_permit_bridge_puzzle(pubkeys: Sequence[bytes], context_hash: bytes32) -> Program:
    validators = require_genesis_validator_set(pubkeys, 2)
    if not isinstance(context_hash, bytes) or len(context_hash) != 32 or context_hash == bytes(32):
        raise ValueError("permit context must be a nonzero bytes32")
    return load_puzzle("zkpassport_bridge_permit_v1.clsp").curry(list(validators.pubkeys), 2, context_hash)


def build_permit_bridge_spend(*, permit: EnrollmentPermit, bridge_coin: Coin,
        validator_pubkeys: Sequence[bytes], signer_indices: Sequence[int],
        new_identity_attest_root: bytes32, attestation_leaf_hash: bytes32,
        scoped_nullifier: bytes32, nullifier_type: int, service_scope_hash: bytes32,
        service_subscope_hash: bytes32, proof_timestamp: int) -> BridgeSpendArtifacts:
    puzzle = make_permit_bridge_puzzle(validator_pubkeys, permit.context_hash)
    policy_hash = bytes32(puzzle.get_tree_hash())
    if bridge_coin.puzzle_hash != policy_hash or bridge_coin.name() != permit.bridge_coin_id:
        raise ValueError("permit bridge input differs from the exact authorized coin")
    if bridge_coin.amount != 1:
        raise ValueError("permit bridge input must contain exactly one mojo")
    _validate_signer_indices(signer_indices, 2, 3)
    bridge_message = compute_attestation_bridge_message(vault_launcher_id=permit.vault_launcher_id,
        attestation_root=new_identity_attest_root, bridge_policy_hash=policy_hash)
    fields = dict(vault_launcher_id=permit.vault_launcher_id, attestation_leaf_hash=attestation_leaf_hash,
        scoped_nullifier=scoped_nullifier, nullifier_type=nullifier_type, service_scope_hash=service_scope_hash,
        service_subscope_hash=service_subscope_hash, proof_timestamp=proof_timestamp)
    legacy_message = compute_validator_bridge_message(**fields, attestation_root=new_identity_attest_root,
        bridge_policy_hash=policy_hash, bridge_coin_id=permit.bridge_coin_id, bridge_message=bridge_message)
    legacy_solution = solution_for_bridge_spend(**fields, bridge_coin=bridge_coin,
        bridge_policy_hash=policy_hash, new_identity_attest_root=new_identity_attest_root,
        signer_indices=signer_indices)
    solution = Program.to(legacy_solution.as_python() + [permit.permit_id, permit.current_vault_coin_id,
        permit.owner_auth_type, permit.owner_key_hash, permit.issued_at, permit.expires_at])
    return BridgeSpendArtifacts(coin_spend=make_spend(bridge_coin, puzzle, solution), puzzle=puzzle,
        solution=solution, bridge_policy_hash=policy_hash, bridge_coin_id=permit.bridge_coin_id,
        bridge_message=bridge_message, validator_message=permit.validator_message(legacy_message))
