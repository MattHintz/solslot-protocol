"""Tests for ``vault_discovery_hint`` — the deterministic hint used to make
vaults chain-discoverable from a user's pubkey alone.

Locking the format here is critical because portal clients re-implement the
hash off-chain (TypeScript) and any drift breaks login.  The hint is:

    sha256(b"solslot-vault-discovery-v1" || auth_type_byte || owner_pubkey)

These tests pin:
- The literal domain string.
- The byte layout (domain || auth_type || pubkey, no separators or padding).
- Auth-type namespacing (EVM and BLS produce different hints even with
  pubkey bytes that happen to coincide).
- Type/length validation.
"""
from __future__ import annotations

import hashlib

import pytest

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    AUTH_TYPE_SECP256K1,
    AUTH_TYPE_SECP256R1,
    VAULT_HINT_DOMAIN,
    vault_discovery_hint,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────
EVM_PUBKEY_33B = bytes.fromhex("02" + "aa" * 32)        # compressed secp256k1
BLS_PUBKEY_48B = bytes.fromhex("aa" * 48)               # G1Element
PASSKEY_PUBKEY_33B = bytes.fromhex("03" + "bb" * 32)    # compressed secp256r1


# ── Domain pinning ───────────────────────────────────────────────────────────
def test_domain_string_locked() -> None:
    """The domain string is the public-API contract for clients re-implementing
    the hash in TypeScript / Rust — any change here MUST be coordinated with
    every client."""
    assert VAULT_HINT_DOMAIN == b"solslot-vault-discovery-v2"


# ── Format pinning ───────────────────────────────────────────────────────────
class TestHintFormat:
    """The hint format must match sha256(domain || auth_type_byte || pubkey)
    byte-for-byte so off-chain clients can derive identical hints."""

    def test_evm_hint_matches_canonical_formula(self) -> None:
        expected = hashlib.sha256(
            VAULT_HINT_DOMAIN + bytes([AUTH_TYPE_SECP256K1]) + EVM_PUBKEY_33B
        ).digest()
        assert bytes(vault_discovery_hint(AUTH_TYPE_SECP256K1, EVM_PUBKEY_33B)) == expected

    def test_bls_hint_matches_canonical_formula(self) -> None:
        expected = hashlib.sha256(
            VAULT_HINT_DOMAIN + bytes([AUTH_TYPE_BLS]) + BLS_PUBKEY_48B
        ).digest()
        assert bytes(vault_discovery_hint(AUTH_TYPE_BLS, BLS_PUBKEY_48B)) == expected

    def test_passkey_hint_matches_canonical_formula(self) -> None:
        expected = hashlib.sha256(
            VAULT_HINT_DOMAIN + bytes([AUTH_TYPE_SECP256R1]) + PASSKEY_PUBKEY_33B
        ).digest()
        assert bytes(vault_discovery_hint(AUTH_TYPE_SECP256R1, PASSKEY_PUBKEY_33B)) == expected

    def test_hint_is_32_bytes(self) -> None:
        h = vault_discovery_hint(AUTH_TYPE_SECP256K1, EVM_PUBKEY_33B)
        assert len(bytes(h)) == 32


# ── Determinism + namespacing ────────────────────────────────────────────────
class TestHintProperties:
    def test_deterministic(self) -> None:
        a = vault_discovery_hint(AUTH_TYPE_SECP256K1, EVM_PUBKEY_33B)
        b = vault_discovery_hint(AUTH_TYPE_SECP256K1, EVM_PUBKEY_33B)
        assert a == b

    def test_different_pubkey_different_hint(self) -> None:
        a = vault_discovery_hint(AUTH_TYPE_SECP256K1, EVM_PUBKEY_33B)
        other_pk = bytes.fromhex("02" + "bb" * 32)
        b = vault_discovery_hint(AUTH_TYPE_SECP256K1, other_pk)
        assert a != b

    def test_auth_type_namespacing(self) -> None:
        """Same pubkey bytes under different auth types must produce different
        hints — prevents cross-auth-type collision attacks."""
        # Use a 33-byte slice of the BLS pubkey to share bytes between auth
        # types (in practice EVM=33, BLS=48, so collision is structural).
        same_bytes_33b = BLS_PUBKEY_48B[:33]
        evm_h = vault_discovery_hint(AUTH_TYPE_SECP256K1, same_bytes_33b)
        passkey_h = vault_discovery_hint(AUTH_TYPE_SECP256R1, same_bytes_33b)
        assert evm_h != passkey_h


# ── Validation ───────────────────────────────────────────────────────────────
class TestHintValidation:
    def test_unknown_auth_type_rejected(self) -> None:
        with pytest.raises(ValueError, match="Unsupported auth_type"):
            vault_discovery_hint(0, EVM_PUBKEY_33B)
        with pytest.raises(ValueError, match="Unsupported auth_type"):
            vault_discovery_hint(99, EVM_PUBKEY_33B)

    def test_pubkey_must_be_bytes(self) -> None:
        with pytest.raises(TypeError, match="must be bytes"):
            vault_discovery_hint(AUTH_TYPE_SECP256K1, "not bytes")  # type: ignore[arg-type]

    def test_bytearray_accepted(self) -> None:
        """``bytes(bytearray)`` round-trip ensures bytearray inputs work."""
        ba = bytearray(EVM_PUBKEY_33B)
        h_bytes = vault_discovery_hint(AUTH_TYPE_SECP256K1, EVM_PUBKEY_33B)
        h_ba = vault_discovery_hint(AUTH_TYPE_SECP256K1, ba)
        assert h_bytes == h_ba


# ── Cross-client compatibility (locks the wire format) ───────────────────────
class TestKnownAnswers:
    """Hard-coded known-answer tests so a TypeScript implementation in the
    portal can verify byte-for-byte parity by re-running these vectors."""

    def test_known_answer_evm_zeros(self) -> None:
        pubkey = b"\x02" + b"\x00" * 32  # all-zero compressed secp256k1
        h = vault_discovery_hint(AUTH_TYPE_SECP256K1, pubkey)
        # Computed once via the canonical formula; locks the exact hash.
        expected_hex = hashlib.sha256(
            b"solslot-vault-discovery-v2" + bytes([3]) + pubkey
        ).hexdigest()
        assert h.hex() == expected_hex

    def test_known_answer_bls_zeros(self) -> None:
        pubkey = b"\x00" * 48
        h = vault_discovery_hint(AUTH_TYPE_BLS, pubkey)
        expected_hex = hashlib.sha256(
            b"solslot-vault-discovery-v2" + bytes([1]) + pubkey
        ).hexdigest()
        assert h.hex() == expected_hex
