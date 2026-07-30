"""Tests for ``solslot_puzzles.eip712_helpers``.

These pin the new module's outputs to the existing inline test
helpers in ``test_admin_authority_v2.py`` (which were promoted to
``eip712_helpers.py`` for cross-repo use by the Solslot API + portal).

If a value here drifts, the API and portal will hash admin records
differently than the chain's view, silently breaking admin-desk
gating after a rotation.  These tests are the canary.
"""
from __future__ import annotations

import pytest
from chia.types.blockchain_format.program import Program
import chia_rs
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.eip712_helpers import (
    MAINNET_GENESIS_CHALLENGE,
    TESTNET11_GENESIS_CHALLENGE,
    build_eip712_member_solution,
    compute_eip712_member_leaf_hash,
    compute_eip712_member_v2_leaf_hash,
    eip712_domain_separator,
    eip712_hash_to_sign,
    eip712_prefix_and_domain_separator,
    eip712_typed_data_for_coin_spend,
    eip712_type_hash,
    genesis_challenge_for_network,
    make_eip712_member_v2_puzzle,
    normalize_eip712_member_signature,
)


# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────


class TestConstants:
    def test_type_hash_is_canonical(self):
        """The CHIP-0037 type hash is keccak256 of a fixed string;
        any change here would break wire-compat with the upstream
        chia-wallet-sdk Eip712Member puzzle.
        """
        # Pinned value.  If this fails, the canonical CHIP-0037
        # type signature has changed and every existing admin's
        # signature scheme changes with it.
        expected = bytes32.fromhex(
            "72930978f119c79f9de7a13bd50c9b3261132d7b4819bdf0d3ca4d4c37ade070"
        )
        assert eip712_type_hash() == expected

    def test_mainnet_genesis_challenge(self):
        """Pinned from chia-blockchain initial-config.yaml."""
        assert MAINNET_GENESIS_CHALLENGE.hex() == (
            "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
        )

    def test_testnet11_genesis_challenge(self):
        """Pinned from chia-blockchain testnet11 overrides."""
        assert TESTNET11_GENESIS_CHALLENGE.hex() == (
            "37a90eb5185a9c4439a91ddc98bbadce7b4feba060d50116a067de66bf236615"
        )


class TestNetworkSelector:
    def test_mainnet(self):
        assert genesis_challenge_for_network("mainnet") == MAINNET_GENESIS_CHALLENGE

    def test_testnet11(self):
        assert (
            genesis_challenge_for_network("testnet11")
            == TESTNET11_GENESIS_CHALLENGE
        )

    def test_unsupported_network_raises(self):
        with pytest.raises(ValueError, match="Unsupported network"):
            genesis_challenge_for_network("simulator")


# ──────────────────────────────────────────────────────────────────────
# Domain separator + prefix
# ──────────────────────────────────────────────────────────────────────


class TestDomainSeparator:
    def test_prefix_starts_with_0x1901(self):
        """EIP-712 envelope prefix is mandated by the spec."""
        prefix = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        assert len(prefix) == 34
        assert prefix[:2] == b"\x19\x01"

    def test_mainnet_vs_testnet11_differ(self):
        """The genesis challenge is part of the domain salt; signatures
        must NOT be replayable across networks.
        """
        mainnet = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        testnet = eip712_prefix_and_domain_separator(TESTNET11_GENESIS_CHALLENGE)
        assert mainnet != testnet
        # The 0x1901 prefix is the same on both; only the trailing 32 bytes differ.
        assert mainnet[:2] == testnet[:2]
        assert mainnet[2:] != testnet[2:]

    def test_domain_separator_is_32_bytes(self):
        sep = eip712_domain_separator(MAINNET_GENESIS_CHALLENGE)
        assert len(sep) == 32


# ──────────────────────────────────────────────────────────────────────
# hash_to_sign
# ──────────────────────────────────────────────────────────────────────


class TestHashToSign:
    def test_deterministic_for_same_inputs(self):
        prefix = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        coin_id = b"\x11" * 32
        dph = b"\x22" * 32
        a = eip712_hash_to_sign(prefix, coin_id, dph)
        b = eip712_hash_to_sign(prefix, coin_id, dph)
        assert a == b

    def test_different_coin_id_different_hash(self):
        prefix = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        a = eip712_hash_to_sign(prefix, b"\x11" * 32, b"\x22" * 32)
        b = eip712_hash_to_sign(prefix, b"\x33" * 32, b"\x22" * 32)
        assert a != b

    def test_different_network_different_hash(self):
        """Same coin_id + dph but different prefix → different signed hash."""
        a = eip712_hash_to_sign(
            eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE),
            b"\x11" * 32,
            b"\x22" * 32,
        )
        b = eip712_hash_to_sign(
            eip712_prefix_and_domain_separator(TESTNET11_GENESIS_CHALLENGE),
            b"\x11" * 32,
            b"\x22" * 32,
        )
        assert a != b


# ──────────────────────────────────────────────────────────────────────
# Leaf hash computation
# ──────────────────────────────────────────────────────────────────────


VALID_PUBKEY = b"\x02" + b"\x11" * 32  # 33-byte compressed pubkey


class TestComputeLeafHash:
    def test_deterministic(self):
        prefix = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        a = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=VALID_PUBKEY,
            prefix_and_domain_separator=prefix,
        )
        b = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=VALID_PUBKEY,
            prefix_and_domain_separator=prefix,
        )
        assert a == b

    def test_different_pubkey_different_leaf(self):
        prefix = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        a = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=b"\x02" + b"\x11" * 32,
            prefix_and_domain_separator=prefix,
        )
        b = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=b"\x03" + b"\x11" * 32,
            prefix_and_domain_separator=prefix,
        )
        assert a != b

    def test_different_network_different_leaf(self):
        """An admin's leaf hash on mainnet must NOT match their leaf
        hash on testnet11 — the genesis challenge is curried in via
        prefix_and_domain_separator, so different networks → different
        hashes for the same operator pubkey.
        """
        a = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=VALID_PUBKEY,
            prefix_and_domain_separator=eip712_prefix_and_domain_separator(
                MAINNET_GENESIS_CHALLENGE
            ),
        )
        b = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=VALID_PUBKEY,
            prefix_and_domain_separator=eip712_prefix_and_domain_separator(
                TESTNET11_GENESIS_CHALLENGE
            ),
        )
        assert a != b

    def test_rejects_wrong_pubkey_length(self):
        prefix = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        with pytest.raises(ValueError, match="33 bytes"):
            compute_eip712_member_leaf_hash(
                secp256k1_pubkey=b"\x02" + b"\x11" * 31,  # 32 bytes
                prefix_and_domain_separator=prefix,
            )

    def test_rejects_wrong_prefix_length(self):
        with pytest.raises(ValueError, match="34 bytes"):
            compute_eip712_member_leaf_hash(
                secp256k1_pubkey=VALID_PUBKEY,
                prefix_and_domain_separator=b"\x19\x01" + b"\x00" * 31,  # 33 bytes
            )

    def test_rejects_wrong_prefix_marker(self):
        bad = b"\x00\x00" + b"\x00" * 32  # right length, wrong marker
        with pytest.raises(ValueError, match="0x1901"):
            compute_eip712_member_leaf_hash(
                secp256k1_pubkey=VALID_PUBKEY,
                prefix_and_domain_separator=bad,
            )

    def test_matches_chia_curry_and_treehash(self):
        """The pure-bytes helper must produce the **exact** same hash as
        ``chia.wallet.util.curry_and_treehash`` operating on the same
        inputs.  This is the semantic invariant the on-chain
        ``(= (sha256tree approving_member_reveal) <leaf>)`` check
        relies on at admin-spend time.

        Regression test for a bug where the bytes-only helper used
        wrong constants (double-hashed the mod_hash, conflated
        ``ONE_TREEHASH = sha256(0x01||0x01)`` with
        ``NIL_TREEHASH = sha256(0x01)``) and produced leaf hashes that
        diverged from ``Program.curry().get_tree_hash()`` and from the
        chia-wallet-sdk Rust ``Eip712Member::curry_tree_hash``.
        """
        from chia.wallet.util.curry_and_treehash import (
            calculate_hash_of_quoted_mod_hash,
            curry_and_treehash,
        )
        from chia.types.blockchain_format.program import Program

        from solslot_puzzles.eip712_helpers import (
            _eip712_member_mod_hash,
            eip712_type_hash,
        )

        prefix = eip712_prefix_and_domain_separator(TESTNET11_GENESIS_CHALLENGE)
        type_hash = eip712_type_hash()

        # Method 1: solslot bytes-only helper.
        solslot_hash = compute_eip712_member_leaf_hash(
            secp256k1_pubkey=VALID_PUBKEY,
            prefix_and_domain_separator=prefix,
            type_hash=type_hash,
        )

        # Method 2: chia's reference curry_and_treehash.
        qmh = calculate_hash_of_quoted_mod_hash(_eip712_member_mod_hash())
        chia_hash = curry_and_treehash(
            qmh,
            Program.to(prefix).get_tree_hash(),
            Program.to(type_hash).get_tree_hash(),
            Program.to(VALID_PUBKEY).get_tree_hash(),
        )

        assert solslot_hash == chia_hash, (
            f"solslot bytes-only curry diverges from chia reference:\n"
            f"  solslot: 0x{solslot_hash.hex()}\n"
            f"  chia:    0x{chia_hash.hex()}\n"
            f"This means admin-record leaf hashes won't match the actual "
            f"sha256tree of the curried Eip712Member puzzle and the "
            f"on-chain admin-spend signature check would always fail."
        )


class TestAuthorityV3Eip712Member:
    RUN_FLAGS = (
        chia_rs.MEMPOOL_MODE
        | chia_rs.ENABLE_SECP_OPS
        | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
    )

    @staticmethod
    def _compressed_pubkey(private_key: object) -> bytes:
        raw = private_key.public_key.to_bytes()
        return (b"\x02" if int.from_bytes(raw[32:], "big") % 2 == 0 else b"\x03") + raw[:32]

    def test_valid_signature_emits_consensus_assert_my_coin_id(self):
        from eth_keys import keys

        private_key = keys.PrivateKey(b"\xa1" * 32)
        public_key = self._compressed_pubkey(private_key)
        prefix = eip712_prefix_and_domain_separator(
            TESTNET11_GENESIS_CHALLENGE
        )
        coin_id = bytes32(b"\xa2" * 32)
        delegated_puzzle_hash = bytes32(b"\xa3" * 32)
        digest = eip712_hash_to_sign(
            prefix,
            coin_id,
            delegated_puzzle_hash,
        )
        signature = private_key.sign_msg_hash(digest).to_bytes()[:64]
        member = make_eip712_member_v2_puzzle(
            secp256k1_pubkey=public_key,
            prefix_and_domain_separator=prefix,
        )

        result = member.run(
            Program.to(
                [
                    delegated_puzzle_hash,
                    coin_id,
                    digest,
                    signature,
                ]
            ),
            flags=self.RUN_FLAGS,
        )
        conditions = list(result.as_iter())
        assert len(conditions) == 1
        assert conditions[0].first().as_int() == 70
        assert conditions[0].rest().first().as_atom() == coin_id
        assert compute_eip712_member_v2_leaf_hash(
            secp256k1_pubkey=public_key,
            prefix_and_domain_separator=prefix,
        ) == bytes32(member.get_tree_hash())

    def test_tampered_signature_and_cross_network_replay_fail(self):
        from eth_keys import keys

        private_key = keys.PrivateKey(b"\xb1" * 32)
        public_key = self._compressed_pubkey(private_key)
        testnet_prefix = eip712_prefix_and_domain_separator(
            TESTNET11_GENESIS_CHALLENGE
        )
        mainnet_prefix = eip712_prefix_and_domain_separator(
            MAINNET_GENESIS_CHALLENGE
        )
        coin_id = bytes32(b"\xb2" * 32)
        delegated_puzzle_hash = bytes32(b"\xb3" * 32)
        testnet_digest = eip712_hash_to_sign(
            testnet_prefix,
            coin_id,
            delegated_puzzle_hash,
        )
        signature = private_key.sign_msg_hash(testnet_digest).to_bytes()[:64]
        member = make_eip712_member_v2_puzzle(
            secp256k1_pubkey=public_key,
            prefix_and_domain_separator=testnet_prefix,
        )
        tampered = bytes([signature[0] ^ 1]) + signature[1:]
        with pytest.raises(Exception):
            member.run(
                Program.to(
                    [
                        delegated_puzzle_hash,
                        coin_id,
                        testnet_digest,
                        tampered,
                    ]
                ),
                flags=self.RUN_FLAGS,
            )

        mainnet_digest = eip712_hash_to_sign(
            mainnet_prefix,
            coin_id,
            delegated_puzzle_hash,
        )
        with pytest.raises(Exception):
            member.run(
                Program.to(
                    [
                        delegated_puzzle_hash,
                        coin_id,
                        mainnet_digest,
                        signature,
                    ]
                ),
                flags=self.RUN_FLAGS,
            )

    def test_wallet_payload_and_signature_normalization(self):
        from eth_keys import keys

        private_key = keys.PrivateKey(b"\xc1" * 32)
        public_key = private_key.public_key.to_compressed_bytes()
        coin_id = bytes32(b"\xc2" * 32)
        delegated_puzzle_hash = bytes32(b"\xc3" * 32)
        typed_data = eip712_typed_data_for_coin_spend(
            network="testnet11",
            coin_id=coin_id,
            delegated_puzzle_hash=delegated_puzzle_hash,
        )
        assert typed_data["primaryType"] == "ChiaCoinSpend"
        assert typed_data["domain"] == {
            "name": "Chia Coin Spend",
            "version": "1",
            "salt": "0x" + TESTNET11_GENESIS_CHALLENGE.hex(),
        }
        assert typed_data["message"] == {
            "coin_id": "0x" + coin_id.hex(),
            "delegated_puzzle_hash": "0x" + delegated_puzzle_hash.hex(),
        }

        digest = eip712_hash_to_sign(
            eip712_prefix_and_domain_separator(
                TESTNET11_GENESIS_CHALLENGE
            ),
            coin_id,
            delegated_puzzle_hash,
        )
        signature = private_key.sign_msg_hash(digest).to_bytes()
        assert normalize_eip712_member_signature(
            signature=signature,
            digest=digest,
            compressed_pubkey=public_key,
        ) == signature[:64]
        assert build_eip712_member_solution(
            network="testnet11",
            coin_id=coin_id,
            delegated_puzzle_hash=delegated_puzzle_hash,
            compressed_pubkey=public_key,
            signature=signature,
        ).as_python() == [coin_id, digest, signature[:64]]

    def test_signature_normalizer_rejects_wrong_key_and_recovery_id(self):
        from eth_keys import keys

        private_key = keys.PrivateKey(b"\xd1" * 32)
        public_key = private_key.public_key.to_compressed_bytes()
        digest = bytes32(b"\xd2" * 32)
        signature = private_key.sign_msg_hash(digest).to_bytes()
        with pytest.raises(ValueError, match="committed key"):
            normalize_eip712_member_signature(
                signature=signature,
                digest=digest,
                compressed_pubkey=keys.PrivateKey(
                    b"\xd3" * 32
                ).public_key.to_compressed_bytes(),
            )
        with pytest.raises(ValueError, match="recovery id"):
            normalize_eip712_member_signature(
                signature=signature[:64] + b"\x05",
                digest=digest,
                compressed_pubkey=public_key,
            )


# ──────────────────────────────────────────────────────────────────────
# Cross-binding: new module matches the inline test fixture helpers
# ──────────────────────────────────────────────────────────────────────


class TestMatchesInlineFixtures:
    """The helpers in this module were promoted from inline test
    helpers in ``test_admin_authority_v2.py``.  These tests pin the
    new module's outputs to the inline fixtures so the move is
    verifiable and any future drift surfaces immediately.
    """

    def test_type_hash_matches_inline(self):
        from tests.test_admin_authority_v2 import _eip712_type_hash
        assert eip712_type_hash() == _eip712_type_hash()

    def test_prefix_matches_inline(self):
        from tests.test_admin_authority_v2 import (
            _eip712_prefix_and_domain_separator,
            MAINNET_GENESIS,
        )
        # Inline helper takes raw bytes; module helper takes bytes32.
        # Both should produce the same value.
        a = eip712_prefix_and_domain_separator(MAINNET_GENESIS_CHALLENGE)
        b = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        assert a == b

    def test_hash_to_sign_matches_inline(self):
        from tests.test_admin_authority_v2 import (
            _eip712_hash_to_sign,
            _eip712_prefix_and_domain_separator,
            MAINNET_GENESIS,
        )
        prefix = _eip712_prefix_and_domain_separator(MAINNET_GENESIS)
        coin_id = b"\xaa" * 32
        dph = b"\xbb" * 32
        new = eip712_hash_to_sign(prefix, coin_id, dph)
        old = _eip712_hash_to_sign(prefix, coin_id, dph)
        assert new == old
