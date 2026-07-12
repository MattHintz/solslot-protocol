from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    SPEND_UPDATE_IDENTITY,
    VAULT_INNER_MOD,
    puzzle_for_vault_inner,
)
from solslot_puzzles.zkpassport_attestation import (
    compute_attestation_bridge_message,
    compute_validator_bridge_message,
)
from solslot_puzzles.zkpassport_bridge_driver import (
    TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH,
    TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY,
    TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY_HEX,
    TESTNET11_ZKPASSPORT_VALIDATOR_THRESHOLD,
    build_bridge_and_vault_update_identity_bundle,
    build_bridge_spend,
    make_bridge_policy_hash,
    make_bridge_puzzle,
    solution_for_bridge_spend,
    zkpassport_bridge_mod,
)


OP_AGG_SIG_ME = bytes([50])
OP_CREATE_COIN_ANN = bytes([60])
OP_ASSERT_COIN_ANN = bytes([61])
PROTOCOL_PREFIX = b"\x53"

VALIDATOR_A = b"\x11" * 48
VALIDATOR_B = b"\x22" * 48
VALIDATOR_C = b"\x33" * 48
VALIDATORS = [VALIDATOR_A, VALIDATOR_B, VALIDATOR_C]
THRESHOLD = 2

VAULT_LAUNCHER_ID = bytes32(b"\xaa" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
VAULT_OWNER_PUBKEY = b"\xcc" * 48
MEMBERS_MERKLE_ROOT = bytes32(b"\xdd" * 32)
BRIDGE_PARENT_ID = bytes32(b"\xee" * 32)
BRIDGE_AMOUNT = 1
NEW_IDENTITY_ROOT = bytes32(b"\x77" * 32)
ATTESTATION_LEAF_HASH = bytes32(b"\x44" * 32)
SCOPED_NULLIFIER = bytes32(b"\x55" * 32)
SERVICE_SCOPE_HASH = bytes32(b"\x66" * 32)
SERVICE_SUBSCOPE_HASH = bytes32(b"\x88" * 32)
NULLIFIER_TYPE = 1
PROOF_TIMESTAMP = 1_779_120_000
CURRENT_TIMESTAMP = 1_779_120_060


def _bridge_coin() -> Coin:
    policy_hash = make_bridge_policy_hash(VALIDATORS, THRESHOLD)
    return Coin(BRIDGE_PARENT_ID, policy_hash, BRIDGE_AMOUNT)


def _bridge_spend(signer_indices=(0, 2)):
    return build_bridge_spend(
        bridge_coin=_bridge_coin(),
        validator_pubkeys=VALIDATORS,
        threshold=THRESHOLD,
        signer_indices=signer_indices,
        vault_launcher_id=VAULT_LAUNCHER_ID,
        new_identity_attest_root=NEW_IDENTITY_ROOT,
        attestation_leaf_hash=ATTESTATION_LEAF_HASH,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=NULLIFIER_TYPE,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
    )


def test_bridge_puzzle_compiles_and_policy_hash_is_curried_puzzle_hash():
    puzzle = make_bridge_puzzle(VALIDATORS, THRESHOLD)
    assert zkpassport_bridge_mod().get_tree_hash() is not None
    assert make_bridge_policy_hash(VALIDATORS, THRESHOLD) == bytes32(puzzle.get_tree_hash())


def test_threshold_signatures_emit_vault_announcement():
    artifacts = _bridge_spend()
    conds = artifacts.puzzle.run(artifacts.solution).as_python()
    bridge_message = compute_attestation_bridge_message(
        vault_launcher_id=VAULT_LAUNCHER_ID,
        attestation_root=NEW_IDENTITY_ROOT,
        bridge_policy_hash=artifacts.bridge_policy_hash,
    )
    validator_message = compute_validator_bridge_message(
        vault_launcher_id=VAULT_LAUNCHER_ID,
        attestation_root=NEW_IDENTITY_ROOT,
        bridge_policy_hash=artifacts.bridge_policy_hash,
        bridge_coin_id=artifacts.bridge_coin_id,
        bridge_message=bridge_message,
        attestation_leaf_hash=ATTESTATION_LEAF_HASH,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=NULLIFIER_TYPE,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
    )
    assert artifacts.bridge_message == bridge_message
    assert artifacts.validator_message == validator_message
    assert [OP_AGG_SIG_ME, VALIDATOR_A, bytes(validator_message)] in conds
    assert [OP_AGG_SIG_ME, VALIDATOR_C, bytes(validator_message)] in conds
    assert [OP_CREATE_COIN_ANN, PROTOCOL_PREFIX + bytes(bridge_message)] in conds


def test_validator_message_is_bound_to_bridge_coin_id():
    first = _bridge_spend()
    second_coin = Coin(bytes32(b"\xef" * 32), first.bridge_policy_hash, BRIDGE_AMOUNT)
    second = build_bridge_spend(
        bridge_coin=second_coin,
        validator_pubkeys=VALIDATORS,
        threshold=THRESHOLD,
        signer_indices=[0, 2],
        vault_launcher_id=VAULT_LAUNCHER_ID,
        new_identity_attest_root=NEW_IDENTITY_ROOT,
        attestation_leaf_hash=ATTESTATION_LEAF_HASH,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=NULLIFIER_TYPE,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
    )

    assert first.bridge_coin_id != second.bridge_coin_id
    assert first.validator_message != second.validator_message


def test_insufficient_signatures_fail_in_clvm():
    puzzle = make_bridge_puzzle(VALIDATORS, THRESHOLD)
    bridge_policy_hash = bytes32(puzzle.get_tree_hash())
    bridge_coin = Coin(BRIDGE_PARENT_ID, bridge_policy_hash, BRIDGE_AMOUNT)
    solution = solution_for_bridge_spend(
        bridge_coin=bridge_coin,
        bridge_policy_hash=bridge_policy_hash,
        vault_launcher_id=VAULT_LAUNCHER_ID,
        new_identity_attest_root=NEW_IDENTITY_ROOT,
        attestation_leaf_hash=ATTESTATION_LEAF_HASH,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=NULLIFIER_TYPE,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
        signer_indices=[0],
    )
    with pytest.raises(Exception):
        puzzle.run(solution)


def test_driver_builds_bridge_and_vault_identity_spends_with_matching_announcement():
    bridge_policy_hash = make_bridge_policy_hash(VALIDATORS, THRESHOLD)
    current_inner = puzzle_for_vault_inner(
        VAULT_LAUNCHER_ID,
        VAULT_OWNER_PUBKEY,
        AUTH_TYPE_BLS,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    vault_coin = Coin(bytes32(b"\x99" * 32), current_inner.get_tree_hash(), 1)
    bundle = build_bridge_and_vault_update_identity_bundle(
        bridge_parent_id=BRIDGE_PARENT_ID,
        bridge_amount=BRIDGE_AMOUNT,
        validator_pubkeys=VALIDATORS,
        threshold=THRESHOLD,
        signer_indices=[0, 1],
        vault_coin=vault_coin,
        vault_launcher_id=VAULT_LAUNCHER_ID,
        owner_pubkey_bytes=VAULT_OWNER_PUBKEY,
        auth_type=AUTH_TYPE_BLS,
        members_merkle_root=MEMBERS_MERKLE_ROOT,
        pool_launcher_id=POOL_LAUNCHER_ID,
        new_identity_attest_root=NEW_IDENTITY_ROOT,
        attestation_leaf_hash=ATTESTATION_LEAF_HASH,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=NULLIFIER_TYPE,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
        current_timestamp=CURRENT_TIMESTAMP,
        lineage_proof=LineageProof(parent_name=VAULT_LAUNCHER_ID, amount=1),
    )
    assert list(bundle.spend_bundle.coin_spends) == [bundle.bridge.coin_spend, bundle.vault_spend]
    assert bundle.bridge.bridge_policy_hash == bridge_policy_hash
    assert bundle.vault_spend.coin == vault_coin

    payload = PROTOCOL_PREFIX + bytes(bundle.bridge.bridge_message)
    expected_assertion = hashlib.sha256(bytes(bundle.bridge.bridge_coin_id) + payload).digest()
    bridge_conds = bundle.bridge.puzzle.run(bundle.bridge.solution).as_python()
    assert [OP_CREATE_COIN_ANN, payload] in bridge_conds

    vault_solution = Program.to([
        vault_coin.name(), current_inner.get_tree_hash(), 1,
        SPEND_UPDATE_IDENTITY,
        [VAULT_INNER_MOD.get_tree_hash(), NEW_IDENTITY_ROOT, BRIDGE_PARENT_ID, BRIDGE_AMOUNT, CURRENT_TIMESTAMP, None],
    ])
    vault_conds = current_inner.run(vault_solution).as_python()
    assert [OP_ASSERT_COIN_ANN, expected_assertion] in vault_conds


class TestTestnet11ValidatorConstants:
    def test_pubkey_hex_is_48_bytes(self):
        assert len(TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY_HEX) == 96
        assert bytes.fromhex(TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY_HEX) == TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY

    def test_pubkey_bytes_is_48_bytes(self):
        assert len(TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY) == 48

    def test_threshold_is_one_of_one(self):
        assert TESTNET11_ZKPASSPORT_VALIDATOR_THRESHOLD == 1

    def test_bridge_policy_hash_matches_computed(self):
        computed = make_bridge_policy_hash(
            [TESTNET11_ZKPASSPORT_VALIDATOR_PUBKEY],
            TESTNET11_ZKPASSPORT_VALIDATOR_THRESHOLD,
        )
        assert computed == TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH, (
            f"Pinned hash {TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH.hex()!r} does not match "
            f"computed {computed.hex()!r} — re-run make_bridge_policy_hash and update the constant."
        )

    def test_bridge_policy_hash_is_32_bytes(self):
        assert len(TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH) == 32

    def test_different_pubkey_gives_different_policy_hash(self):
        other = make_bridge_policy_hash([b"\x11" * 48], 1)
        assert other != TESTNET11_ZKPASSPORT_BRIDGE_POLICY_HASH
