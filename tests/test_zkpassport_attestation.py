from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.zkpassport_attestation import (
    ZKPASSPORT_ATTEST_DOMAIN,
    ZKPASSPORT_EMPTY_ATTEST_ROOT,
    ZKPASSPORT_POLICY_VERSION,
    ZkPassportAttestation,
    compute_attestation_bridge_message,
    compute_attestation_leaf,
    compute_attestation_root,
    compute_vault_subscope,
    verify_merkle_proof,
)


VAULT_LAUNCHER_ID = bytes32(b"\x11" * 32)
SCOPED_NULLIFIER = bytes32(b"\x22" * 32)
SERVICE_SCOPE_HASH = bytes32(b"\x33" * 32)
SERVICE_SUBSCOPE_HASH = bytes32(b"\x44" * 32)
BRIDGE_POLICY_HASH = bytes32(b"\x55" * 32)
PROOF_TIMESTAMP = 1_779_120_000


def _attestation(**overrides) -> ZkPassportAttestation:
    values = dict(
        vault_launcher_id=VAULT_LAUNCHER_ID,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=1,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
    )
    values.update(overrides)
    return ZkPassportAttestation(**values)


def _pair(left: bytes32, right: bytes32) -> bytes32:
    return bytes32(hashlib.sha256(b"\x02" + bytes(left) + bytes(right)).digest())


class TestZkPassportAttestationLeaf:
    def test_leaf_hash_matches_canonical_program_tree_hash(self):
        att = _attestation()
        expected = bytes32(
            Program.to(
                [
                    ZKPASSPORT_ATTEST_DOMAIN,
                    ZKPASSPORT_POLICY_VERSION,
                    VAULT_LAUNCHER_ID,
                    SCOPED_NULLIFIER,
                    1,
                    SERVICE_SCOPE_HASH,
                    SERVICE_SUBSCOPE_HASH,
                    PROOF_TIMESTAMP,
                ]
            ).get_tree_hash()
        )
        assert compute_attestation_leaf(att) == expected
        assert att.leaf_hash == expected

    def test_leaf_hash_is_bound_to_vault_launcher_id(self):
        a = compute_attestation_leaf(_attestation(vault_launcher_id=bytes32(b"\x11" * 32)))
        b = compute_attestation_leaf(_attestation(vault_launcher_id=bytes32(b"\x12" * 32)))
        assert a != b

    def test_leaf_hash_is_bound_to_scoped_nullifier(self):
        a = compute_attestation_leaf(_attestation(scoped_nullifier=bytes32(b"\x22" * 32)))
        b = compute_attestation_leaf(_attestation(scoped_nullifier=bytes32(b"\x23" * 32)))
        assert a != b

    def test_rejects_non_uint_fields(self):
        with pytest.raises(ValueError, match="nullifier_type must be uint16"):
            compute_attestation_leaf(_attestation(nullifier_type=-1))
        with pytest.raises(ValueError, match="policy_version must be uint16"):
            compute_attestation_leaf(_attestation(policy_version=0x1_0000))
        with pytest.raises(ValueError, match="proof_timestamp must be uint64"):
            compute_attestation_leaf(_attestation(proof_timestamp=-1))


class TestZkPassportAttestationRoot:
    def test_empty_root_matches_clvm_empty_list_tree_hash(self):
        assert ZKPASSPORT_EMPTY_ATTEST_ROOT == bytes32(Program.to([]).get_tree_hash())
        assert compute_attestation_root([]) == ZKPASSPORT_EMPTY_ATTEST_ROOT

    def test_single_leaf_root_is_leaf(self):
        leaf = compute_attestation_leaf(_attestation())
        assert compute_attestation_root([leaf]) == leaf

    def test_even_leaf_root_uses_pair_tree_hash(self):
        leaves = [bytes32(bytes([i]) * 32) for i in (1, 2, 3, 4)]
        expected = _pair(_pair(leaves[0], leaves[1]), _pair(leaves[2], leaves[3]))
        assert compute_attestation_root(leaves) == expected

    def test_odd_leaf_root_duplicates_last_leaf(self):
        leaves = [bytes32(bytes([i]) * 32) for i in (1, 2, 3)]
        expected = _pair(_pair(leaves[0], leaves[1]), _pair(leaves[2], leaves[2]))
        assert compute_attestation_root(leaves) == expected

    def test_rejects_short_leaf(self):
        with pytest.raises(ValueError, match="leaf must be 32 bytes"):
            compute_attestation_root([b"short"])


class TestZkPassportBridgeMessage:
    def test_bridge_message_matches_canonical_program_tree_hash(self):
        root = compute_attestation_root([compute_attestation_leaf(_attestation())])
        got = compute_attestation_bridge_message(
            vault_launcher_id=VAULT_LAUNCHER_ID,
            attestation_root=root,
            bridge_policy_hash=BRIDGE_POLICY_HASH,
        )
        expected = bytes32(
            Program.to(
                [
                    ZKPASSPORT_ATTEST_DOMAIN,
                    ZKPASSPORT_POLICY_VERSION,
                    VAULT_LAUNCHER_ID,
                    root,
                    BRIDGE_POLICY_HASH,
                ]
            ).get_tree_hash()
        )
        assert got == expected

    def test_bridge_message_is_bound_to_policy_hash(self):
        root = compute_attestation_root([compute_attestation_leaf(_attestation())])
        a = compute_attestation_bridge_message(
            vault_launcher_id=VAULT_LAUNCHER_ID,
            attestation_root=root,
            bridge_policy_hash=bytes32(b"\x55" * 32),
        )
        b = compute_attestation_bridge_message(
            vault_launcher_id=VAULT_LAUNCHER_ID,
            attestation_root=root,
            bridge_policy_hash=bytes32(b"\x56" * 32),
        )
        assert a != b


class TestZkPassportMerkleProof:
    def test_verify_left_leaf_proof(self):
        left = bytes32(b"\x01" * 32)
        right = bytes32(b"\x02" * 32)
        root = _pair(left, right)
        assert verify_merkle_proof(
            leaf_hash=left,
            root=root,
            bitpath=0,
            siblings=[right],
        )

    def test_verify_right_leaf_proof(self):
        left = bytes32(b"\x01" * 32)
        right = bytes32(b"\x02" * 32)
        root = _pair(left, right)
        assert verify_merkle_proof(
            leaf_hash=right,
            root=root,
            bitpath=1,
            siblings=[left],
        )

    def test_rejects_wrong_sibling(self):
        left = bytes32(b"\x01" * 32)
        right = bytes32(b"\x02" * 32)
        root = _pair(left, right)
        assert not verify_merkle_proof(
            leaf_hash=left,
            root=root,
            bitpath=0,
            siblings=[bytes32(b"\x03" * 32)],
        )

    def test_rejects_negative_bitpath(self):
        with pytest.raises(ValueError, match="bitpath must be >= 0"):
            verify_merkle_proof(
                leaf_hash=bytes32(b"\x01" * 32),
                root=bytes32(b"\x02" * 32),
                bitpath=-1,
                siblings=[],
            )


class TestZkPassportSubscope:
    def test_vault_subscope_is_launcher_bound(self):
        assert (
            compute_vault_subscope(VAULT_LAUNCHER_ID)
            == "vault:0x" + "11" * 32
        )

    def test_vault_subscope_rejects_short_launcher_id(self):
        with pytest.raises(ValueError, match="vault_launcher_id must be 32 bytes"):
            compute_vault_subscope(b"short")
