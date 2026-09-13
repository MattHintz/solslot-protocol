"""Additive enrollment authorization format. Never upgrades a legacy signature.

The permit context must come from separately authenticated deployment evidence.
It commits to environment, both networks, emitter, issuer, bridge policy,
deployment and exact source release. No runtime activation is implied here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping
from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

PERMIT_DOMAIN = b"solslot-enrollment-permit-v1"
VALIDATOR_PERMIT_DOMAIN = b"solslot-enrollment-validator-v1"
MAX_PERMIT_SECONDS = 3600


@dataclass(frozen=True)
class EnrollmentPermitContext:
    environment: str
    network: str
    evm_chain_id: int
    emitter: bytes
    issuer: bytes
    deployment_id: bytes32
    release_identity: bytes32

    def __post_init__(self) -> None:
        if (self.environment not in ("staging-alpha", "production-alpha")
                or self.network != "testnet11" or type(self.evm_chain_id) is not int
                or self.evm_chain_id != 84532):
            raise ValueError("permit context must identify an isolated alpha Testnet deployment")
        for name, size in (("emitter", 20), ("issuer", 20), ("deployment_id", 32), ("release_identity", 32)):
            value = getattr(self, name)
            if not isinstance(value, bytes) or len(value) != size or value == bytes(size):
                raise ValueError(f"permit context {name} must be a nonzero {size}-byte value")

    @property
    def context_hash(self) -> bytes32:
        # release_identity binds the complete reviewed nine-component source
        # manifest. The emitter is planned before deployment (e.g. CREATE2).
        # Do not include this context's curried puzzle hash: that is circular.
        # The exact bridge input/policy is bound separately by the permit.
        return bytes32(Program.to([b"solslot-enrollment-context-v1", self.environment.encode(),
            self.network.encode(), self.evm_chain_id, self.emitter, self.issuer,
            self.deployment_id, self.release_identity]).get_tree_hash())


def owner_key_hash(auth_type: int, owner_key: bytes) -> bytes32:
    if type(auth_type) is not int or auth_type not in (1, 2):
        raise ValueError("permit owner must be Chia BLS or EVM")
    if not isinstance(owner_key, bytes) or len(owner_key) != (48 if auth_type == 1 else 20):
        raise ValueError("permit owner key has the wrong width")
    return bytes32(hashlib.sha256(owner_key).digest())


@dataclass(frozen=True)
class EnrollmentPermit:
    permit_id: bytes32
    context_hash: bytes32
    vault_launcher_id: bytes32
    current_vault_coin_id: bytes32
    owner_auth_type: int
    owner_key_hash: bytes32
    bridge_coin_id: bytes32
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for field in ("permit_id", "context_hash", "vault_launcher_id", "current_vault_coin_id",
                      "owner_key_hash", "bridge_coin_id"):
            value = getattr(self, field)
            if not isinstance(value, bytes) or len(value) != 32 or value == bytes(32):
                raise ValueError(f"{field} must be a nonzero bytes32")
        if type(self.owner_auth_type) is not int or self.owner_auth_type not in (1, 2):
            raise ValueError("permit owner must be Chia BLS or EVM")
        if (type(self.issued_at) is not int or type(self.expires_at) is not int
                or not 0 < self.issued_at < self.expires_at < 2**64
                or self.expires_at - self.issued_at > MAX_PERMIT_SECONDS):
            raise ValueError("permit must have an immutable positive lifetime of at most one hour")

    def to_program(self) -> Program:
        return Program.to([PERMIT_DOMAIN, self.permit_id, self.context_hash, self.vault_launcher_id,
            self.current_vault_coin_id, self.owner_auth_type, self.owner_key_hash,
            self.bridge_coin_id, self.issued_at, self.expires_at])

    @property
    def permit_hash(self) -> bytes32:
        return bytes32(self.to_program().get_tree_hash())

    def require_live(self, now: int) -> None:
        if type(now) is not int or not self.issued_at <= now < self.expires_at:
            raise ValueError("enrollment permit is not live")

    def validator_message(self, legacy_message: bytes32) -> bytes32:
        if not isinstance(legacy_message, bytes) or len(legacy_message) != 32:
            raise ValueError("legacy validator message must be bytes32")
        return bytes32(Program.to([VALIDATOR_PERMIT_DOMAIN, legacy_message, self.permit_hash]).get_tree_hash())

    def to_wire(self) -> dict[str, Any]:
        return dict(permitId='0x'+self.permit_id.hex(),contextHash='0x'+self.context_hash.hex(),
            vaultLauncherId='0x'+self.vault_launcher_id.hex(),currentVaultCoinId='0x'+self.current_vault_coin_id.hex(),
            ownerAuthType=self.owner_auth_type,ownerKeyHash='0x'+self.owner_key_hash.hex(),
            bridgeCoinId='0x'+self.bridge_coin_id.hex(),issuedAt=self.issued_at,expiresAt=self.expires_at,
            permitHash='0x'+self.permit_hash.hex())

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> EnrollmentPermit:
        names={'permitId':'permit_id','contextHash':'context_hash','vaultLauncherId':'vault_launcher_id',
            'currentVaultCoinId':'current_vault_coin_id','ownerKeyHash':'owner_key_hash','bridgeCoinId':'bridge_coin_id'}
        if not isinstance(value,Mapping) or set(value)!=set(names)|{'ownerAuthType','issuedAt','expiresAt','permitHash'}:
            raise ValueError('enrollment permit wire fields are incomplete')
        parsed={}
        for field,target in names.items():
            raw=value[field]
            if not isinstance(raw,str) or re.fullmatch(r'0x[0-9a-f]{64}',raw) is None:
                raise ValueError('enrollment permit hashes must be canonical bytes32')
            parsed[target]=bytes32.from_hexstr(raw)
        permit=cls(**parsed,owner_auth_type=value['ownerAuthType'],issued_at=value['issuedAt'],expires_at=value['expiresAt'])
        if value['permitHash']!='0x'+permit.permit_hash.hex():
            raise ValueError('enrollment permit hash does not match its immutable fields')
        return permit


def permit_owner_from_native(auth_type: int, owner_key: bytes) -> tuple[int, bytes32]:
    if type(auth_type) is not int or auth_type not in (1,3):
        raise ValueError('enrollment permits support native BLS and secp256k1 owners only')
    permit_type={1:1,3:2}[auth_type]
    return permit_type,owner_key_hash(permit_type,owner_key)


def permit_signing_typed_data(permit: EnrollmentPermit, context: EnrollmentPermitContext) -> dict[str,Any]:
    if permit.context_hash!=context.context_hash:
        raise ValueError('enrollment permit belongs to another deployment context')
    return dict(domain=dict(name='SolslotEnrollmentPermit',version='1',chainId=context.evm_chain_id,
        verifyingContract='0x'+context.emitter.hex()),primaryType='EnrollmentPermit',
        types={'EIP712Domain':[dict(name='name',type='string'),dict(name='version',type='string'),
            dict(name='chainId',type='uint256'),dict(name='verifyingContract',type='address')],
            'EnrollmentPermit':[dict(name='permitHash',type='bytes32')]},
        message=dict(permitHash='0x'+permit.permit_hash.hex()))
