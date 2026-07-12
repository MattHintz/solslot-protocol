"""Pure helpers for zkPassport vault attestation commitments.

Brick 1 of the zkPassport overhaul deliberately avoids Chialisp changes.
These helpers define the Chia-side commitment format that later vault
spends will consume after an EVM verifier / bridge path has already
validated the zkPassport proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Sequence

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32


ZKPASSPORT_EMPTY_ATTEST_ROOT: bytes32 = bytes32(
    bytes.fromhex("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a")
)
ZKPASSPORT_ATTEST_DOMAIN = b"populis-zkpassport-vault-attestation-v1"
ZKPASSPORT_SCOPE = "populis.app"
ZKPASSPORT_POLICY_VERSION = 1


@dataclass(frozen=True)
class ZkPassportAttestation:
    """Bridge-attested anonymous identity commitment consumed by a vault.

    The fields are already commitments / roots from the zkPassport/EVM side;
    no raw passport data belongs here.  The Chia puzzle can later verify a
    bridge message and Merkle membership against the values derived here.
    """

    vault_launcher_id: bytes32
    scoped_nullifier: bytes32
    nullifier_type: int
    service_scope_hash: bytes32
    service_subscope_hash: bytes32
    proof_timestamp: int
    policy_version: int = ZKPASSPORT_POLICY_VERSION

    def to_program(self) -> Program:
        """Canonical tree-hash preimage for the anonymous attestation leaf."""
        _validate_uint64("proof_timestamp", self.proof_timestamp)
        _validate_uint16("policy_version", self.policy_version)
        _validate_uint16("nullifier_type", self.nullifier_type)
        return Program.to(
            [
                ZKPASSPORT_ATTEST_DOMAIN,
                self.policy_version,
                self.vault_launcher_id,
                self.scoped_nullifier,
                self.nullifier_type,
                self.service_scope_hash,
                self.service_subscope_hash,
                self.proof_timestamp,
            ]
        )

    @property
    def leaf_hash(self) -> bytes32:
        """sha256tree of :meth:`to_program`, used as the Merkle leaf."""
        return bytes32(self.to_program().get_tree_hash())


def compute_vault_subscope(vault_launcher_id: bytes32) -> str:
    """Return the canonical zkPassport service_subscope string for a vault."""
    _require_bytes32("vault_launcher_id", vault_launcher_id)
    return f"vault:0x{bytes(vault_launcher_id).hex()}"


def compute_attestation_leaf(attestation: ZkPassportAttestation) -> bytes32:
    """Return the deterministic Chia-side attestation leaf hash."""
    return attestation.leaf_hash


def compute_attestation_root(leaves: Sequence[bytes32]) -> bytes32:
    """Compute the deterministic binary Merkle root for attestation leaves.

    Empty roots intentionally use the same sha256tree(empty-list) value as
    CLVM/Program.to([]), which is already used elsewhere in Populis for empty
    flat-list state hashes.  A single leaf is its own root.  Odd-width levels
    duplicate the final node, matching the conventional Chia-side binary tree
    helper shape used by off-chain proof builders.
    """
    if not leaves:
        return ZKPASSPORT_EMPTY_ATTEST_ROOT
    level = [_coerce_bytes32("leaf", leaf) for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [
            _combine_nodes(level[i], level[i + 1])
            for i in range(0, len(level), 2)
        ]
    return level[0]


def compute_attestation_bridge_message(
    *,
    vault_launcher_id: bytes32,
    attestation_root: bytes32,
    bridge_policy_hash: bytes32,
    policy_version: int = ZKPASSPORT_POLICY_VERSION,
) -> bytes32:
    """Compute the message a bridge/verifier path must bind to a vault.

    Later CLSP spends can reproduce this sha256tree preimage to ensure the
    consumed bridge message is specific to this vault, verifier/bridge policy,
    and attestation root.
    """
    _require_bytes32("vault_launcher_id", vault_launcher_id)
    _require_bytes32("attestation_root", attestation_root)
    _require_bytes32("bridge_policy_hash", bridge_policy_hash)
    _validate_uint16("policy_version", policy_version)
    return bytes32(
        Program.to(
            [
                ZKPASSPORT_ATTEST_DOMAIN,
                policy_version,
                vault_launcher_id,
                attestation_root,
                bridge_policy_hash,
            ]
        ).get_tree_hash()
    )


def compute_validator_bridge_message(
    *,
    vault_launcher_id: bytes32,
    attestation_root: bytes32,
    bridge_policy_hash: bytes32,
    bridge_coin_id: bytes32,
    bridge_message: bytes32,
    attestation_leaf_hash: bytes32,
    scoped_nullifier: bytes32,
    nullifier_type: int,
    service_scope_hash: bytes32,
    service_subscope_hash: bytes32,
    proof_timestamp: int,
    policy_version: int = ZKPASSPORT_POLICY_VERSION,
) -> bytes32:
    _require_bytes32("vault_launcher_id", vault_launcher_id)
    _require_bytes32("attestation_root", attestation_root)
    _require_bytes32("bridge_policy_hash", bridge_policy_hash)
    _require_bytes32("bridge_coin_id", bridge_coin_id)
    _require_bytes32("bridge_message", bridge_message)
    _require_bytes32("attestation_leaf_hash", attestation_leaf_hash)
    _require_bytes32("scoped_nullifier", scoped_nullifier)
    _require_bytes32("service_scope_hash", service_scope_hash)
    _require_bytes32("service_subscope_hash", service_subscope_hash)
    _validate_uint16("policy_version", policy_version)
    _validate_uint16("nullifier_type", nullifier_type)
    _validate_uint64("proof_timestamp", proof_timestamp)
    return bytes32(
        Program.to(
            [
                _uint_to_bytes32(policy_version),
                vault_launcher_id,
                attestation_root,
                bridge_policy_hash,
                bridge_coin_id,
                bridge_message,
                attestation_leaf_hash,
                scoped_nullifier,
                _uint_to_bytes32(nullifier_type),
                service_scope_hash,
                service_subscope_hash,
                _uint_to_bytes32(proof_timestamp),
            ]
        ).get_tree_hash()
    )


def verify_merkle_proof(
    *,
    leaf_hash: bytes32,
    root: bytes32,
    bitpath: int,
    siblings: Sequence[bytes32],
) -> bool:
    """Verify a binary Merkle proof using ``merkle_utils.clib`` semantics.

    `bitpath` uses the same low-bit-first convention as
    `simplify_merkle_proof_after_leaf`: bit 1 means the sibling is on the left,
    bit 0 means the sibling is on the right.
    """
    _require_bytes32("leaf_hash", leaf_hash)
    _require_bytes32("root", root)
    if bitpath < 0:
        raise ValueError(f"bitpath must be >= 0, got {bitpath}")
    acc = bytes32(leaf_hash)
    remaining = bitpath
    for sibling in siblings:
        sib = _coerce_bytes32("sibling", sibling)
        if remaining & 1:
            acc = _combine_nodes(sib, acc)
        else:
            acc = _combine_nodes(acc, sib)
        remaining >>= 1
    return acc == root


def _combine_nodes(left: bytes32, right: bytes32) -> bytes32:
    return bytes32(hashlib.sha256(b"\x02" + bytes(left) + bytes(right)).digest())


def _uint_to_bytes32(value: int) -> bytes:
    return int(value).to_bytes(32, "big")


def _coerce_bytes32(name: str, value: bytes) -> bytes32:
    _require_bytes32(name, value)
    return bytes32(value)


def _require_bytes32(name: str, value: bytes) -> None:
    if len(value) != 32:
        raise ValueError(f"{name} must be 32 bytes, got {len(value)}")


def _validate_uint16(name: str, value: int) -> None:
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} must be uint16, got {value}")


def _validate_uint64(name: str, value: int) -> None:
    if not 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"{name} must be uint64, got {value}")


__all__ = [
    "ZKPASSPORT_ATTEST_DOMAIN",
    "ZKPASSPORT_EMPTY_ATTEST_ROOT",
    "ZKPASSPORT_POLICY_VERSION",
    "ZKPASSPORT_SCOPE",
    "ZkPassportAttestation",
    "compute_attestation_bridge_message",
    "compute_attestation_leaf",
    "compute_attestation_root",
    "compute_validator_bridge_message",
    "compute_vault_subscope",
    "verify_merkle_proof",
]
