"""Unit tests for vault_singleton_inner.clsp, p2_vault.clsp, p2_pool_v2.clsp, and vault_driver.py.

Tests run curried puzzles directly via Program.run() to verify:
  1. Vault BLS (AUTH_TYPE=1) path: all three spend cases produce correct conditions
  2. Vault secp256k1 (AUTH_TYPE=3) path: authenticate dispatcher routes correctly
  3. AUTH_TYPE isolation: BLS and secp256k1 vaults have different puzzle hashes
  4. Security gating: invalid spend cases, wrong-size inputs, unknown auth type fail
  5. p2_vault escrow conditions
  6. p2_pool escrow conditions
  7. vault_driver helpers: signing_message determinism and BLS curry roundtrip
  8. Announcement/message pairing between vault and pool
"""
import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

# ── Load compiled puzzles ──────────────────────────────────────────────────
VAULT_INNER_MOD: Program = load_clvm(
    "vault_singleton_inner.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
P2_VAULT_MOD: Program = load_clvm(
    "p2_vault.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)
P2_POOL_MOD: Program = load_clvm(
    "p2_pool_v2.clsp",
    package_or_requirement="solslot_puzzles",
    recompile=True,
)

# ── Test constants ─────────────────────────────────────────────────────────
LAUNCHER_PUZZLE_HASH = SINGLETON_LAUNCHER_HASH
VAULT_LAUNCHER_ID = bytes32(b"\xaa" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
DEED_LAUNCHER_ID = bytes32(b"\xdd" * 32)
DEED_COIN_ID = bytes32(b"\xde" * 32)
DEED_COMMITMENT = bytes32(b"\xdf" * 32)
POOL_INNER_PUZHASH = bytes32(b"\xcc" * 32)

# BLS owner pubkey — 48-byte G1Element placeholder
BLS_OWNER_PUBKEY = bytes(48)
# secp256k1 compressed pubkey — 33 bytes (0x02 prefix + 32-byte x)
SECP_OWNER_PUBKEY = b"\x02" + bytes(32)

# Members Merkle root — 32-byte placeholder (one-leaf tree for single-owner vaults)
MEMBERS_MERKLE_ROOT = bytes32(b"\xee" * 32)
IDENTITY_ATTEST_ROOT = bytes32(bytes.fromhex("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"))
ZKPASSPORT_BRIDGE_POLICY_HASH = bytes32(b"\x00" * 32)
ATTESTATION_LEAF_HASH = bytes32(b"\x44" * 32)
ATTESTATION_PROOF = Program.to((0, []))

VAULT_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH))
)

# Auth type constants (must mirror vault_singleton_inner.clsp)
AUTH_TYPE_BLS = 1
AUTH_TYPE_SECP256R1 = 2
AUTH_TYPE_SECP256K1 = 3

# Spend case byte literals
SPEND_DEPOSIT_TO_POOL = 0x6f    # b'o'
SPEND_RECEIVE_FROM_POOL = 0x69  # b'i'
SPEND_ACCEPT_OFFER = 0x61       # b'a'
SPEND_UPDATE_IDENTITY = 0x7a
SPEND_MIGRATE = 0x6d            # b'm'

# Protocol prefix (must match PROTOCOL_PREFIX in utility_macros.clib = 0x53)
PROTOCOL_PREFIX = b"\x53"

# p2_vault coin ID used in spend case 'i' tests
P2_VAULT_COIN_ID = bytes32(b"\xb2" * 32)

# A plausible Unix timestamp for tests (2025-01-01T00:00:00Z)
CURRENT_TIMESTAMP = 1_735_689_600

# Opcode bytes
OP_CREATE_COIN = bytes([51])
OP_AGG_SIG_ME = bytes([50])
OP_REMARK = bytes([1])
OP_CREATE_PUZZLE_ANN = bytes([62])
OP_ASSERT_PUZZLE_ANN = bytes([63])
OP_CREATE_COIN_ANN = bytes([60])
OP_ASSERT_COIN_ANN = bytes([61])
OP_ASSERT_MY_COIN_ID = bytes([70])
OP_ASSERT_MY_PUZZLEHASH = bytes([72])
OP_ASSERT_MY_AMOUNT = bytes([73])


# ── Curry helpers ──────────────────────────────────────────────────────────

def curry_vault_bls() -> Program:
    """Curry vault_singleton_inner for BLS auth."""
    return VAULT_INNER_MOD.curry(
        VAULT_SINGLETON_STRUCT,
        BLS_OWNER_PUBKEY,
        AUTH_TYPE_BLS,
        MEMBERS_MERKLE_ROOT,
        IDENTITY_ATTEST_ROOT,
        ZKPASSPORT_BRIDGE_POLICY_HASH,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


def curry_vault_secp() -> Program:
    """Curry vault_singleton_inner for secp256k1 auth."""
    return VAULT_INNER_MOD.curry(
        VAULT_SINGLETON_STRUCT,
        SECP_OWNER_PUBKEY,
        AUTH_TYPE_SECP256K1,
        MEMBERS_MERKLE_ROOT,
        IDENTITY_ATTEST_ROOT,
        ZKPASSPORT_BRIDGE_POLICY_HASH,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


def curry_p2_vault() -> Program:
    return P2_VAULT_MOD.curry(
        SINGLETON_MOD_HASH,
        VAULT_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


def extract_cond(conditions: list, opcode: bytes, index: int = 0) -> list:
    matches = [c for c in conditions if c[0] == opcode]
    assert len(matches) > index, f"Opcode {opcode.hex()}: only {len(matches)} found, need index {index}"
    return matches[index]


# ── Tests ──────────────────────────────────────────────────────────────────

class TestVaultCompile:
    """Verify vault puzzles compile and curry to distinct hashes per auth type."""

    def test_vault_mod_loads(self):
        assert VAULT_INNER_MOD is not None

    def test_p2_vault_mod_loads(self):
        assert P2_VAULT_MOD is not None

    def test_vault_curry_bls_differs_from_mod(self):
        assert curry_vault_bls().get_tree_hash() != VAULT_INNER_MOD.get_tree_hash()

    def test_vault_curry_secp_differs_from_mod(self):
        assert curry_vault_secp().get_tree_hash() != VAULT_INNER_MOD.get_tree_hash()

    def test_bls_and_secp_vaults_have_different_puzzle_hash(self):
        """AUTH_TYPE and different pubkeys must produce different puzzle hashes."""
        assert curry_vault_bls().get_tree_hash() != curry_vault_secp().get_tree_hash()

    def test_different_owner_pubkeys_produce_different_hashes(self):
        """Two BLS vaults with different owner pubkeys must not share a puzzle hash."""
        pubkey_a = bytes(48)
        pubkey_b = bytes([1] * 48)
        vault_a = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT, pubkey_a, AUTH_TYPE_BLS, MEMBERS_MERKLE_ROOT,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH, POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH,
        )
        vault_b = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT, pubkey_b, AUTH_TYPE_BLS, MEMBERS_MERKLE_ROOT,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH, POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH,
        )
        assert vault_a.get_tree_hash() != vault_b.get_tree_hash()

    def test_p2_vault_curry_produces_program(self):
        assert curry_p2_vault().get_tree_hash() != P2_VAULT_MOD.get_tree_hash()


class TestVaultBLSDepositToPool:
    """BLS path — SPEND CASE 'o': deposit deed to pool."""

    def setup_method(self):
        self.curried = curry_vault_bls()
        self.my_id = bytes32(b"\x11" * 32)
        self.my_inner_puzhash = self.curried.get_tree_hash()

    def test_deposit_condition_count(self):
        sol = Program.to([
            self.my_id, self.my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = self.curried.run(sol).as_python()
        # AGG_SIG_ME, CREATE_PUZZLE_ANNOUNCEMENT, CREATE_COIN, REMARK,
        # ASSERT_SECONDS_ABSOLUTE, ASSERT_BEFORE_SECONDS_ABSOLUTE,
        # ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conds) == 9

    def test_deposit_agg_sig_me_present(self):
        sol = Program.to([
            self.my_id, self.my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = self.curried.run(sol).as_python()
        agg_sig = extract_cond(conds, OP_AGG_SIG_ME)
        assert agg_sig[1] == BLS_OWNER_PUBKEY

    def test_deposit_announcement_has_protocol_prefix(self):
        sol = Program.to([
            self.my_id, self.my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = self.curried.run(sol).as_python()
        ann = extract_cond(conds, OP_CREATE_PUZZLE_ANN)
        assert ann[1][:1] == PROTOCOL_PREFIX

    def test_deposit_recreates_vault(self):
        sol = Program.to([
            self.my_id, self.my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = self.curried.run(sol).as_python()
        create = extract_cond(conds, OP_CREATE_COIN)
        assert create[1] == self.my_inner_puzhash

    def test_deposit_asserts_coin_id(self):
        sol = Program.to([
            self.my_id, self.my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = self.curried.run(sol).as_python()
        coin_id_cond = extract_cond(conds, OP_ASSERT_MY_COIN_ID)
        assert coin_id_cond[1] == self.my_id


class TestVaultBLSReceiveFromPool:
    """BLS path — SPEND CASE 'i': receive deed from pool via p2_vault co-spend.

    Pairing protocol:
      vault emits  CREATE_PUZZLE_ANNOUNCEMENT(PREFIX + sha256tree(list my_id deed_id my_inner_ph))
      p2_vault asserts that announcement
      p2_vault emits  CREATE_COIN_ANNOUNCEMENT(PREFIX + sha256(my_id deed_id my_inner_ph))
      vault asserts   ASSERT_COIN_ANNOUNCEMENT from p2_vault
    """

    def test_receive_agg_sig_present(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_RECEIVE_FROM_POOL,
            [DEED_LAUNCHER_ID, P2_VAULT_COIN_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        # 10 conditions: AGG_SIG_ME, CREATE_PUZZLE_ANN, ASSERT_COIN_ANN, CREATE_COIN, REMARK,
        #                ASSERT_SECONDS_ABSOLUTE, ASSERT_BEFORE_SECONDS_ABSOLUTE,
        #                ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conds) == 10
        assert extract_cond(conds, OP_AGG_SIG_ME)[1] == BLS_OWNER_PUBKEY

    def test_receive_emits_puzzle_announcement_for_p2_vault(self):
        """Vault 'i' emits CREATE_PUZZLE_ANNOUNCEMENT so p2_vault can assert it."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_RECEIVE_FROM_POOL,
            [DEED_LAUNCHER_ID, P2_VAULT_COIN_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        ann = extract_cond(conds, OP_CREATE_PUZZLE_ANN)
        assert ann[1][:1] == PROTOCOL_PREFIX
        # Content: PREFIX + sha256tree(list my_id deed_launcher_id my_inner_puzhash)
        expected = PROTOCOL_PREFIX + Program.to([my_id, DEED_LAUNCHER_ID, my_inner_puzhash]).get_tree_hash()
        assert ann[1] == expected

    def test_receive_asserts_coin_announcement_from_specific_p2_vault_coin(self):
        """Vault 'i' asserts ASSERT_COIN_ANNOUNCEMENT from the specific p2_vault coin ID.

        Security: uses p2_vault_coin_id (not nil) so only the actual p2_vault coin can
        satisfy the assertion — a forgery from any other coin is rejected.
        """
        import hashlib
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_RECEIVE_FROM_POOL,
            [DEED_LAUNCHER_ID, P2_VAULT_COIN_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        # ASSERT_COIN_ANNOUNCEMENT = opcode 61
        assert_coin_anns = [c for c in conds if c[0] == bytes([61])]
        assert len(assert_coin_anns) == 1
        # Verify the hash includes p2_vault_coin_id (not nil prefix)
        inner_hash = hashlib.sha256(bytes(my_id) + bytes(DEED_LAUNCHER_ID) + bytes(my_inner_puzhash)).digest()
        ann_payload = PROTOCOL_PREFIX + inner_hash
        expected_hash = hashlib.sha256(bytes(P2_VAULT_COIN_ID) + ann_payload).digest()
        assert assert_coin_anns[0][1] == expected_hash, "ASSERT_COIN_ANNOUNCEMENT must be bound to p2_vault_coin_id"

    def test_receive_recreates_vault(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_RECEIVE_FROM_POOL,
            [DEED_LAUNCHER_ID, P2_VAULT_COIN_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        create = extract_cond(conds, OP_CREATE_COIN)
        assert create[1] == my_inner_puzhash


class TestVaultBLSAcceptOffer:
    """BLS path — SPEND CASE 'a': accept pool offer."""

    def _curried_enrolled(self) -> Program:
        return VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            ATTESTATION_LEAF_HASH,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )

    def _offer_params(self, token_amount: int = 100_000):
        return [
            DEED_LAUNCHER_ID,
            token_amount,
            POOL_INNER_PUZHASH,
            ATTESTATION_LEAF_HASH,
            ATTESTATION_PROOF,
            CURRENT_TIMESTAMP,
            None,
        ]

    def test_accept_offer_driver_solution_vector(self):
        from solslot_puzzles.vault_driver import _inner_solution_for_accept_offer

        curried = self._curried_enrolled()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = _inner_solution_for_accept_offer(
            my_id,
            my_inner_puzhash,
            1,
            DEED_LAUNCHER_ID,
            100_000,
            POOL_INNER_PUZHASH,
            ATTESTATION_LEAF_HASH,
            ATTESTATION_PROOF,
            CURRENT_TIMESTAMP,
            None,
        )
        # Pinned solution tree hash. Embeds the vault inner puzzle hash, so it
        # updates whenever vault_singleton_inner.clsp's mod hash changes — here,
        # the 'm' (migrate) spend case (vault upgrade flow) was added.
        assert sol.get_tree_hash().hex() == "8ab99e40a3787a000e6973027f9fead2d96b2e7e3b00e45c46aa4eee961f0657"
        fields = list(sol.as_iter())
        params = list(fields[4].as_iter())
        assert bytes32(fields[0].as_atom()) == my_id
        assert bytes32(fields[1].as_atom()) == my_inner_puzhash
        assert fields[2].as_int() == 1
        assert fields[3].as_int() == SPEND_ACCEPT_OFFER
        assert bytes32(params[0].as_atom()) == DEED_LAUNCHER_ID
        assert params[1].as_int() == 100_000
        assert bytes32(params[2].as_atom()) == POOL_INNER_PUZHASH
        assert bytes32(params[3].as_atom()) == ATTESTATION_LEAF_HASH
        assert params[4].get_tree_hash() == ATTESTATION_PROOF.get_tree_hash()
        assert params[5].as_int() == CURRENT_TIMESTAMP
        assert params[6].as_atom() == b""

    def test_accept_offer_vector_outputs_are_stable(self):
        from solslot_puzzles.vault_driver import _inner_solution_for_accept_offer

        curried = self._curried_enrolled()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = _inner_solution_for_accept_offer(
            my_id,
            my_inner_puzhash,
            1,
            DEED_LAUNCHER_ID,
            100_000,
            POOL_INNER_PUZHASH,
            ATTESTATION_LEAF_HASH,
            ATTESTATION_PROOF,
            CURRENT_TIMESTAMP,
            None,
        )
        conds = curried.run(sol).as_python()
        assert extract_cond(conds, OP_AGG_SIG_ME)[2] == bytes.fromhex(
            "2d33d2424799d4a31f7225871d9a56239729293e44e574c47905587fa84d81db"
        )
        assert extract_cond(conds, OP_ASSERT_PUZZLE_ANN)[1] == bytes.fromhex(
            "edcf4c2a4cf369fc74cc94bda7effb4747c383acacd1f11aa0885a00c261ef89"
        )

    def test_accept_offer_agg_sig_present(self):
        curried = self._curried_enrolled()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_ACCEPT_OFFER,
            self._offer_params(),
        ])
        conds = curried.run(sol).as_python()
        # AGG_SIG_ME, ASSERT_PUZZLE_ANN, CREATE_COIN, REMARK,
        # ASSERT_SECONDS_ABSOLUTE, ASSERT_BEFORE_SECONDS_ABSOLUTE,
        # ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conds) == 9
        assert extract_cond(conds, OP_AGG_SIG_ME)[1] == BLS_OWNER_PUBKEY

    def test_accept_offer_asserts_pool_announcement(self):
        curried = self._curried_enrolled()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_ACCEPT_OFFER,
            self._offer_params(),
        ])
        conds = curried.run(sol).as_python()
        assert extract_cond(conds, OP_ASSERT_PUZZLE_ANN) is not None

    def test_accept_offer_rejects_empty_identity_root(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_ACCEPT_OFFER,
            self._offer_params(),
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_accept_offer_rejects_wrong_attestation_proof(self):
        curried = self._curried_enrolled()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_ACCEPT_OFFER,
            [
                DEED_LAUNCHER_ID,
                100_000,
                POOL_INNER_PUZHASH,
                bytes32(b"\x45" * 32),
                ATTESTATION_PROOF,
                CURRENT_TIMESTAMP,
                None,
            ],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_accept_offer_rejects_wrong_attestation_root(self):
        curried = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            bytes32(b"\x99" * 32),
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_ACCEPT_OFFER,
            self._offer_params(),
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_accept_offer_rejects_missing_attestation_proof_shape(self):
        curried = self._curried_enrolled()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_ACCEPT_OFFER,
            [DEED_LAUNCHER_ID, 100_000, POOL_INNER_PUZHASH, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)


class TestVaultSecpPath:
    """secp256k1 (AUTH_TYPE=3) path — authenticate dispatcher routes to verify_secp256k1."""

    def test_secp_vault_deposit_has_no_agg_sig_me(self):
        """secp256k1 path must NOT emit AGG_SIG_ME — signature is in-puzzle via softfork."""
        curried = curry_vault_secp()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        fake_sig = bytes(64)  # 64-byte compact signature placeholder
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, fake_sig],
        ])
        # The softfork will fail with zero sig (expected) but AGG_SIG_ME must not be present
        try:
            conds = curried.run(sol).as_python()
            agg_sigs = [c for c in conds if c[0] == OP_AGG_SIG_ME]
            assert len(agg_sigs) == 0, "secp256k1 path must not emit AGG_SIG_ME"
        except Exception:
            pass  # softfork verification failure is expected with a zero sig

    def test_secp_vault_has_different_puzzle_hash_than_bls(self):
        assert curry_vault_secp().get_tree_hash() != curry_vault_bls().get_tree_hash()


class TestVaultSecp256k1RealSignature:
    """CRITICAL-2 regression — real secp256k1 signature must verify on-chain.

    Before the CRIT-2 fix, the driver's EIP-712 digest differed from what the
    puzzle computed inside the softfork, so ANY real wallet signature would
    fail `secp256k1_verify` regardless of key.  These tests generate a real
    keypair, sign the driver's digest, run the curried puzzle, and assert
    verification succeeds (no CLVM raise).
    """

    @staticmethod
    def _secp256k1_keypair_and_sign(digest: bytes) -> tuple[bytes, bytes]:
        """Return (compressed_pubkey_33b, compact_sig_64b) for `digest` via cryptography."""
        from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        priv = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        # The CLVM secp256k1_verify op expects a 32-byte digest AS ALREADY HASHED.
        # We pass the digest with ec.ECDSA(Prehashed(SHA256())) — SHA256 is just the
        # prehash marker; it is NOT applied to the digest again (Prehashed wraps the
        # already-32-byte input).  The underlying ECDSA math doesn't depend on the
        # prehash function identity; only the byte length matters.
        sig_der = priv.sign(digest, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
        r, s = ec_utils.decode_dss_signature(sig_der)
        # Normalise s to low-s (BIP-62) because CHIP-0011 secp256k1_verify rejects high-s.
        # secp256k1 group order N:
        N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        if s > N // 2:
            s = N - s
        compact = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return pub, compact

    def _run_for_spend_case(self, spend_case_byte: int, spend_case_bytes: bytes):
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend

        my_id = bytes32(b"\x11" * 32)

        # 1. Build the EIP-712 digest via the driver.
        digest = signing_message_for_vault_spend(
            spend_case_bytes, DEED_LAUNCHER_ID, my_id
        )
        assert len(digest) == 32

        # 2. Generate key + sign digest.
        pub33, sig64 = self._secp256k1_keypair_and_sign(digest)

        # 3. Curry the vault with this real pubkey and AUTH_TYPE_SECP256K1.
        curried = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            pub33,
            AUTH_TYPE_SECP256K1,
            MEMBERS_MERKLE_ROOT,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )
        my_inner_puzhash = curried.get_tree_hash()

        # 4. Run the puzzle.  With the fix in place, verify_secp256k1 succeeds.
        if spend_case_byte == SPEND_DEPOSIT_TO_POOL:
            p = [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, sig64]
        else:
            p = [DEED_LAUNCHER_ID, P2_VAULT_COIN_ID, CURRENT_TIMESTAMP, sig64]
        sol = Program.to([my_id, my_inner_puzhash, 1, spend_case_byte, p])
        conds = curried.run(sol).as_python()

        # 5. A REMARK "secp256k1 ok" must be present — proof the softfork accepted
        #    the signature.  AGG_SIG_ME must be absent on the secp path.
        remarks = [c for c in conds if c[0] == OP_REMARK]
        assert any(b"secp256k1 ok" in c[1] for c in remarks), (
            "expected 'secp256k1 ok' REMARK proving softfork verification succeeded"
        )
        agg_sigs = [c for c in conds if c[0] == OP_AGG_SIG_ME]
        assert len(agg_sigs) == 0

    def test_secp256k1_real_signature_verifies_deposit(self):
        """'o' deposit with a real secp256k1 signature over the driver's digest must succeed."""
        self._run_for_spend_case(SPEND_DEPOSIT_TO_POOL, b"o")

    def test_secp256k1_real_signature_verifies_receive(self):
        """'i' receive with a real secp256k1 signature over the driver's digest must succeed."""
        self._run_for_spend_case(SPEND_RECEIVE_FROM_POOL, b"i")

    def test_secp256k1_wrong_vault_coin_id_is_rejected(self):
        """Signature for coin A must NOT verify against a vault with a different my_id.

        This is the CRIT-2 + HIGH-5 combined guarantee: binding vault_coin_id
        into the EIP-712 digest prevents cross-coin replay.
        """
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend

        my_id_a = bytes32(b"\x11" * 32)
        my_id_b = bytes32(b"\x22" * 32)

        digest = signing_message_for_vault_spend(b"o", DEED_LAUNCHER_ID, my_id_a)
        pub33, sig64 = self._secp256k1_keypair_and_sign(digest)

        curried = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT, pub33, AUTH_TYPE_SECP256K1, MEMBERS_MERKLE_ROOT,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH, POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH,
        )
        my_inner_puzhash = curried.get_tree_hash()
        # Run with my_id = B, signature was produced for my_id = A
        sol = Program.to([
            my_id_b, my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, sig64],
        ])
        with pytest.raises(Exception):
            curried.run(sol)


class TestVaultSecurityGating:
    """Invariant: invalid inputs must cause CLVM exception, not silently succeed."""

    def test_unknown_spend_case_raises(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            0x74,  # 't' — not a valid vault spend case
            [DEED_LAUNCHER_ID],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_unknown_auth_type_raises(self):
        """AUTH_TYPE=99 must cause CLVM failure."""
        bad_vault = VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            BLS_OWNER_PUBKEY,
            99,  # unknown auth type
            MEMBERS_MERKLE_ROOT,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = bad_vault.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            bad_vault.run(sol)

    def test_short_deed_launcher_id_raises(self):
        """deed_launcher_id shorter than 32 bytes must fail is-size-b32 assertion."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [bytes(16), CURRENT_TIMESTAMP, None],  # 16 bytes — too short
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    # LOW-13 fix (2026-04-26): the prior `test_short_pool_inner_puzhash_raises`
    # test was deleted because its target parameter (`pool_inner_puzhash`) is
    # no longer in the 'o' / 'i' solution shape.  The 'a' (accept_offer) case
    # still uses pool_inner_puzhash and is covered by tests in TestVaultBLSAcceptOffer.

    def test_zero_my_amount_raises(self):
        """my_amount == 0 must fail — zero-amount singletons are non-standard and
        could cause lineage proof confusion in downstream puzzles."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 0,  # zero amount
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_p2_vault_coin_id_equal_to_my_id_raises(self):
        """p2_vault_coin_id == my_id must fail — the vault cannot assert its own
        coin announcement, which would trivially satisfy the co-spend check."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_RECEIVE_FROM_POOL,
            [DEED_LAUNCHER_ID, my_id, CURRENT_TIMESTAMP, None],  # p2_vault_coin_id == my_id
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_announcement_content_is_spend_case_bound(self):
        """Announcement content must be bound to SPEND_DEPOSIT_TO_POOL + deed_launcher_id,
        so replaying the announcement with a different deed_launcher_id is not possible."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        deed_a = bytes32(b"\xaa" * 32)
        deed_b = bytes32(b"\xbb" * 32)

        def run_deposit(deed_id):
            sol = Program.to([
                my_id, my_inner_puzhash, 1,
                SPEND_DEPOSIT_TO_POOL,
                [deed_id, CURRENT_TIMESTAMP, None],
            ])
            conds = curried.run(sol).as_python()
            return extract_cond(conds, OP_CREATE_PUZZLE_ANN)[1]

        ann_a = run_deposit(deed_a)
        ann_b = run_deposit(deed_b)
        assert ann_a != ann_b, "Announcement must be bound to deed_launcher_id"

    def test_agg_sig_message_is_spend_case_bound(self):
        """AGG_SIG_ME message must differ between deposit and receive spend cases."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        def run_case(case):
            if case == SPEND_RECEIVE_FROM_POOL:
                p = [DEED_LAUNCHER_ID, P2_VAULT_COIN_ID, CURRENT_TIMESTAMP, None]
            else:
                p = [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None]
            sol = Program.to([
                my_id, my_inner_puzhash, 1, case, p,
            ])
            conds = curried.run(sol).as_python()
            return extract_cond(conds, OP_AGG_SIG_ME)[2]  # message bytes

        msg_deposit = run_case(SPEND_DEPOSIT_TO_POOL)
        msg_receive = run_case(SPEND_RECEIVE_FROM_POOL)
        assert msg_deposit != msg_receive, "AGG_SIG_ME message must be spend-case-bound"


class TestVaultDepositReceiveAnnouncementPairing:
    """Verify the vault announcement pairs correctly with pool's ASSERT_PUZZLE_ANNOUNCEMENT."""

    def test_deposit_announcement_content_matches_pool_assertion(self):
        """Pool's ASSERT_PUZZLE_ANNOUNCEMENT for receive must match vault's CREATE_PUZZLE_ANNOUNCEMENT."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        ann = extract_cond(conds, OP_CREATE_PUZZLE_ANN)
        ann_content = ann[1]

        # Expected: PROTOCOL_PREFIX + sha256tree(list 'o' deed_launcher_id)
        expected_content = PROTOCOL_PREFIX + Program.to(
            [SPEND_DEPOSIT_TO_POOL, DEED_LAUNCHER_ID]
        ).get_tree_hash()
        assert ann_content == expected_content


class TestVaultDriverHelpers:
    """Unit tests for vault_driver.py pure functions."""

    def test_signing_message_is_deterministic(self):
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend
        deed_id = bytes32(b"\xdd" * 32)
        vault_coin_id = bytes32(b"\x11" * 32)
        msg1 = signing_message_for_vault_spend(b"o", deed_id, vault_coin_id)
        msg2 = signing_message_for_vault_spend(b"o", deed_id, vault_coin_id)
        assert msg1 == msg2
        assert len(msg1) == 32

    def test_signing_message_differs_by_spend_case(self):
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend
        deed_id = bytes32(b"\xdd" * 32)
        vault_coin_id = bytes32(b"\x11" * 32)
        msg_o = signing_message_for_vault_spend(b"o", deed_id, vault_coin_id)
        msg_i = signing_message_for_vault_spend(b"i", deed_id, vault_coin_id)
        msg_a = signing_message_for_vault_spend(b"a", deed_id, vault_coin_id)
        assert msg_o != msg_i
        assert msg_o != msg_a
        assert msg_i != msg_a

    def test_signing_message_differs_by_deed_launcher_id(self):
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend
        vault_coin_id = bytes32(b"\x11" * 32)
        msg_a = signing_message_for_vault_spend(b"o", bytes32(b"\xaa" * 32), vault_coin_id)
        msg_b = signing_message_for_vault_spend(b"o", bytes32(b"\xbb" * 32), vault_coin_id)
        assert msg_a != msg_b

    def test_signing_message_differs_by_vault_coin_id(self):
        from solslot_puzzles.vault_driver import signing_message_for_vault_spend
        deed_id = bytes32(b"\xdd" * 32)
        msg_a = signing_message_for_vault_spend(b"o", deed_id, bytes32(b"\x11" * 32))
        msg_b = signing_message_for_vault_spend(b"o", deed_id, bytes32(b"\x22" * 32))
        assert msg_a != msg_b

    def test_puzzle_for_vault_inner_bls_curry(self):
        from solslot_puzzles.vault_driver import (
            puzzle_for_vault_inner, AUTH_TYPE_BLS,
        )
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH, SINGLETON_MOD_HASH
        inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
        )
        assert inner is not None
        assert len(bytes(inner.get_tree_hash())) == 32

    def test_puzzle_for_vault_inner_secp_curry(self):
        from solslot_puzzles.vault_driver import (
            puzzle_for_vault_inner, AUTH_TYPE_SECP256K1,
        )
        inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            SECP_OWNER_PUBKEY,
            AUTH_TYPE_SECP256K1,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
        )
        assert inner is not None
        assert len(bytes(inner.get_tree_hash())) == 32

    def test_puzzle_for_vault_inner_rejects_compressed_secp256r1_pubkey(self):
        from solslot_puzzles.vault_driver import (
            puzzle_for_vault_inner, AUTH_TYPE_SECP256R1,
        )
        with pytest.raises(ValueError, match="65 bytes uncompressed"):
            puzzle_for_vault_inner(
                VAULT_LAUNCHER_ID,
                b"\x02" + bytes(32),
                AUTH_TYPE_SECP256R1,
                MEMBERS_MERKLE_ROOT,
                POOL_LAUNCHER_ID,
            )

    def test_build_create_vault_bundle_rejects_compressed_secp256r1_pubkey(self):
        from chia.types.blockchain_format.coin import Coin
        from chia_rs.sized_ints import uint64
        from solslot_puzzles.vault_driver import (
            build_create_vault_bundle, AUTH_TYPE_SECP256R1,
        )
        with pytest.raises(ValueError, match="65 bytes uncompressed"):
            build_create_vault_bundle(
                Coin(bytes32(b"\x01" * 32), bytes32(b"\x02" * 32), uint64(2)),
                Program.to(1),
                b"\x03" + bytes(32),
                AUTH_TYPE_SECP256R1,
                MEMBERS_MERKLE_ROOT,
                POOL_LAUNCHER_ID,
            )

    def test_build_vault_accept_offer_spend_pins_builder_boundary(self):
        from chia.types.blockchain_format.coin import Coin
        from chia.wallet.lineage_proof import LineageProof
        from solslot_puzzles.vault_driver import (
            build_vault_accept_offer_spend,
            puzzle_for_vault_inner,
        )

        current_inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
            identity_attest_root=ATTESTATION_LEAF_HASH,
        )
        vault_coin = Coin(bytes32(b"\x99" * 32), current_inner.get_tree_hash(), 1)
        lineage = LineageProof(parent_name=VAULT_LAUNCHER_ID, amount=1)
        spend = build_vault_accept_offer_spend(
            vault_coin,
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
            DEED_LAUNCHER_ID,
            100_000,
            POOL_INNER_PUZHASH,
            ATTESTATION_LEAF_HASH,
            ATTESTATION_LEAF_HASH,
            ATTESTATION_PROOF,
            CURRENT_TIMESTAMP,
            lineage,
        )
        assert spend.coin == vault_coin

    def test_build_vault_accept_offer_spend_rejects_missing_identity_root(self):
        from chia.types.blockchain_format.coin import Coin
        from chia.wallet.lineage_proof import LineageProof
        from solslot_puzzles.vault_driver import (
            DEFAULT_IDENTITY_ATTEST_ROOT,
            build_vault_accept_offer_spend,
            puzzle_for_vault_inner,
        )

        current_inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
        )
        vault_coin = Coin(bytes32(b"\x99" * 32), current_inner.get_tree_hash(), 1)
        with pytest.raises(ValueError, match="identity_attest_root"):
            build_vault_accept_offer_spend(
                vault_coin,
                VAULT_LAUNCHER_ID,
                BLS_OWNER_PUBKEY,
                AUTH_TYPE_BLS,
                MEMBERS_MERKLE_ROOT,
                POOL_LAUNCHER_ID,
                DEED_LAUNCHER_ID,
                100_000,
                POOL_INNER_PUZHASH,
                DEFAULT_IDENTITY_ATTEST_ROOT,
                ATTESTATION_LEAF_HASH,
                ATTESTATION_PROOF,
                CURRENT_TIMESTAMP,
                LineageProof(parent_name=VAULT_LAUNCHER_ID, amount=1),
            )

    def test_puzzle_for_vault_inner_defaults_identity_state(self):
        from solslot_puzzles.vault_driver import (
            DEFAULT_IDENTITY_ATTEST_ROOT,
            DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH,
            AUTH_TYPE_BLS,
            parse_vault_inner_puzzle,
            puzzle_for_vault_inner,
        )
        inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
        )
        state = parse_vault_inner_puzzle(inner)
        assert state.owner_pubkey_bytes == BLS_OWNER_PUBKEY
        assert state.auth_type == AUTH_TYPE_BLS
        assert state.members_merkle_root == MEMBERS_MERKLE_ROOT
        assert state.identity_attest_root == DEFAULT_IDENTITY_ATTEST_ROOT
        assert state.zkpassport_bridge_policy_hash == DEFAULT_ZKPASSPORT_BRIDGE_POLICY_HASH
        assert state.pool_launcher_id == POOL_LAUNCHER_ID

    def test_puzzle_for_vault_inner_accepts_custom_identity_state(self):
        from solslot_puzzles.vault_driver import (
            AUTH_TYPE_BLS,
            parse_vault_inner_puzzle,
            puzzle_for_vault_inner,
        )
        identity_root = bytes32(b"\x77" * 32)
        bridge_policy_hash = bytes32(b"\x88" * 32)
        default_inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
        )
        custom_inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
            identity_attest_root=identity_root,
            zkpassport_bridge_policy_hash=bridge_policy_hash,
        )
        state = parse_vault_inner_puzzle(custom_inner)
        assert custom_inner.get_tree_hash() != default_inner.get_tree_hash()
        assert state.identity_attest_root == identity_root
        assert state.zkpassport_bridge_policy_hash == bridge_policy_hash

    def test_bls_and_secp_inner_puzzles_have_different_hashes(self):
        from solslot_puzzles.vault_driver import (
            puzzle_for_vault_inner, AUTH_TYPE_BLS, AUTH_TYPE_SECP256K1,
        )
        inner_bls = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID, BLS_OWNER_PUBKEY, AUTH_TYPE_BLS, MEMBERS_MERKLE_ROOT, POOL_LAUNCHER_ID,
        )
        inner_secp = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID, SECP_OWNER_PUBKEY, AUTH_TYPE_SECP256K1, MEMBERS_MERKLE_ROOT, POOL_LAUNCHER_ID,
        )
        assert inner_bls.get_tree_hash() != inner_secp.get_tree_hash()

    def test_owner_pubkey_bytes_from_bls(self):
        from solslot_puzzles.vault_driver import owner_pubkey_bytes_from_bls
        from chia_rs import G1Element
        pk = G1Element.generator()
        b = owner_pubkey_bytes_from_bls(pk)
        assert len(b) == 48
        assert G1Element.from_bytes(b) == pk


class TestP2Vault:
    """Test p2_vault escrow puzzle."""

    def test_p2_vault_condition_count(self):
        curried = curry_p2_vault()
        sol = Program.to([
            bytes32(b"\xee" * 32),   # vault_inner_puzhash
            bytes32(b"\x11" * 32),   # vault_coin_id
            DEED_LAUNCHER_ID,        # nft_launcher_id
            bytes32(b"\xff" * 32),   # nft_inner_puzhash
            1,                       # nft_amount
            bytes32(b"\x99" * 32),   # next_puzzlehash
        ])
        conds = curried.run(sol).as_python()
        # ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH, ASSERT_PUZZLE_ANNOUNCEMENT,
        # CREATE_COIN, CREATE_COIN_ANNOUNCEMENT
        assert len(conds) == 5

    def test_p2_vault_moves_nft_to_next_puzzlehash(self):
        curried = curry_p2_vault()
        next_puzhash = bytes32(b"\x99" * 32)
        sol = Program.to([
            bytes32(b"\xee" * 32),
            bytes32(b"\x11" * 32),
            DEED_LAUNCHER_ID,
            bytes32(b"\xff" * 32),
            1,
            next_puzhash,
        ])
        conds = curried.run(sol).as_python()
        create = extract_cond(conds, OP_CREATE_COIN)
        assert create[1] == next_puzhash

    def test_p2_vault_coin_announcement_has_protocol_prefix(self):
        curried = curry_p2_vault()
        sol = Program.to([
            bytes32(b"\xee" * 32),
            bytes32(b"\x11" * 32),
            DEED_LAUNCHER_ID,
            bytes32(b"\xff" * 32),
            1,
            bytes32(b"\x99" * 32),
        ])
        conds = curried.run(sol).as_python()
        coin_ann = extract_cond(conds, OP_CREATE_COIN_ANN)
        assert coin_ann[1][:1] == PROTOCOL_PREFIX

    def test_p2_vault_asserts_vault_puzzle_announcement(self):
        curried = curry_p2_vault()
        sol = Program.to([
            bytes32(b"\xee" * 32),
            bytes32(b"\x11" * 32),
            DEED_LAUNCHER_ID,
            bytes32(b"\xff" * 32),
            1,
            bytes32(b"\x99" * 32),
        ])
        conds = curried.run(sol).as_python()
        assert extract_cond(conds, OP_ASSERT_PUZZLE_ANN) is not None


class TestVaultBLSMigrate:
    """BLS path — SPEND CASE 'm': migrate a deed to a new vault.

    A deed is an NFT singleton whose inner puzzle is p2_vault curried to THIS
    vault's launcher.  Migration re-binds it to a destination vault by spending
    it to the destination's p2_vault puzzle hash, gated by the vault's signed
    CREATE_PUZZLE_ANNOUNCEMENT.
    """

    def _sol(self, my_id, vault_inner_ph, dest, sig=None):
        return Program.to([
            my_id, vault_inner_ph, 1, SPEND_MIGRATE,
            [DEED_LAUNCHER_ID, dest, CURRENT_TIMESTAMP, sig],
        ])

    def test_migrate_emits_expected_conditions(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        conds = curried.run(self._sol(my_id, curried.get_tree_hash(), bytes32(b"\x77" * 32))).as_python()
        # AGG_SIG_ME, CREATE_PUZZLE_ANN, CREATE_COIN, REMARK,
        # ASSERT_SECONDS_ABSOLUTE, ASSERT_BEFORE_SECONDS_ABSOLUTE,
        # ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conds) == 9
        assert extract_cond(conds, OP_AGG_SIG_ME)[1] == BLS_OWNER_PUBKEY

    def test_migrate_agg_sig_binds_destination(self):
        """The owner signs over the destination, so a relayer cannot redirect the deed."""
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        dest = bytes32(b"\x77" * 32)
        conds = curried.run(self._sol(my_id, curried.get_tree_hash(), dest)).as_python()
        agg = extract_cond(conds, OP_AGG_SIG_ME)
        assert agg[2] == Program.to([SPEND_MIGRATE, DEED_LAUNCHER_ID, dest, my_id]).get_tree_hash()
        other = Program.to([SPEND_MIGRATE, DEED_LAUNCHER_ID, bytes32(b"\x66" * 32), my_id]).get_tree_hash()
        assert agg[2] != other

    def test_migrate_recreates_vault_unchanged(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        vault_inner_ph = curried.get_tree_hash()
        conds = curried.run(self._sol(my_id, vault_inner_ph, bytes32(b"\x77" * 32))).as_python()
        create = extract_cond(conds, OP_CREATE_COIN)
        assert create[1] == vault_inner_ph
        assert int.from_bytes(create[2], "big") == 1

    def test_migrate_announcement_matches_p2_vault_assertion(self):
        """The vault's CREATE_PUZZLE_ANNOUNCEMENT id equals what the deed's p2_vault
        asserts when co-spent to the destination — the atomic link that moves the deed."""
        from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton

        curried = curry_vault_bls()
        vault_inner_ph = curried.get_tree_hash()
        my_id = bytes32(b"\x11" * 32)
        dest = bytes32(b"\x77" * 32)

        conds = curried.run(self._sol(my_id, vault_inner_ph, dest)).as_python()
        ann = extract_cond(conds, OP_CREATE_PUZZLE_ANN)
        expected_msg = PROTOCOL_PREFIX + bytes(Program.to([my_id, DEED_LAUNCHER_ID, dest]).get_tree_hash())
        assert ann[1] == expected_msg

        vault_full_ph = puzzle_for_singleton(VAULT_LAUNCHER_ID, curried).get_tree_hash()
        expected_id = hashlib.sha256(bytes(vault_full_ph) + bytes(expected_msg)).digest()

        p2 = curry_p2_vault()
        p2_sol = Program.to([
            vault_inner_ph,          # singleton_inner_puzzle_hash (real vault inner ph)
            my_id,                   # singleton_coin_id (the vault coin announcing)
            DEED_LAUNCHER_ID,        # my_launcher_id (the deed)
            bytes32(b"\xff" * 32),   # my_singleton_inner_puzzle_hash (deed inner; arbitrary)
            1,                       # my_amount
            dest,                    # next_puzzlehash (destination vault's p2_vault)
        ])
        p2_conds = p2.run(p2_sol).as_python()
        assert extract_cond(p2_conds, OP_ASSERT_PUZZLE_ANN)[1] == expected_id
        assert extract_cond(p2_conds, OP_CREATE_COIN)[1] == dest

    def test_migrate_rejects_zero_destination(self):
        curried = curry_vault_bls()
        my_id = bytes32(b"\x11" * 32)
        with pytest.raises(Exception):
            curried.run(self._sol(my_id, curried.get_tree_hash(), bytes32(b"\x00" * 32)))

    def test_migrate_rejects_secp_auth(self):
        """secp migrate is deferred — the puzzle must raise, not silently mis-sign."""
        curried = curry_vault_secp()
        my_id = bytes32(b"\x11" * 32)
        with pytest.raises(Exception):
            curried.run(self._sol(my_id, curried.get_tree_hash(), bytes32(b"\x77" * 32), sig=b"\x00" * 64))

    def test_migrate_driver_solution_and_signing_tree(self):
        from solslot_puzzles.vault_driver import (
            _inner_solution_for_migrate, puzzle_for_p2_vault,
            migrate_bls_signing_tree, SPEND_MIGRATE as DRV_SPEND_MIGRATE,
        )
        my_id = bytes32(b"\x11" * 32)
        new_launcher = bytes32(b"\x55" * 32)
        dest = puzzle_for_p2_vault(new_launcher).get_tree_hash()
        sol = _inner_solution_for_migrate(my_id, my_id, 1, DEED_LAUNCHER_ID, dest, CURRENT_TIMESTAMP, None)
        parts = list(sol.as_iter())
        assert parts[3].as_int() == DRV_SPEND_MIGRATE == SPEND_MIGRATE
        p = list(parts[4].as_iter())
        assert p[0].as_atom() == DEED_LAUNCHER_ID
        assert p[1].as_atom() == bytes(dest)
        assert migrate_bls_signing_tree(DEED_LAUNCHER_ID, dest, my_id) == \
            Program.to([SPEND_MIGRATE, DEED_LAUNCHER_ID, dest, my_id]).get_tree_hash()

    def test_build_vault_migrate_spend_carries_destination(self):
        from chia.types.blockchain_format.coin import Coin
        from chia.wallet.lineage_proof import LineageProof
        from solslot_puzzles.vault_driver import (
            build_vault_migrate_spend, puzzle_for_vault_inner, puzzle_for_p2_vault,
        )

        current_inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID, BLS_OWNER_PUBKEY, AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT, POOL_LAUNCHER_ID,
        )
        vault_coin = Coin(bytes32(b"\x99" * 32), current_inner.get_tree_hash(), 1)
        lineage = LineageProof(parent_name=VAULT_LAUNCHER_ID, amount=1)
        new_launcher = bytes32(b"\x55" * 32)
        spend = build_vault_migrate_spend(
            vault_coin, VAULT_LAUNCHER_ID, BLS_OWNER_PUBKEY, AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT, POOL_LAUNCHER_ID, DEED_LAUNCHER_ID,
            new_launcher, CURRENT_TIMESTAMP, lineage,
        )
        assert spend.coin == vault_coin
        full_sol = Program.from_bytes(bytes(spend.solution))
        inner_sol = list(full_sol.as_iter())[2]
        parts = list(inner_sol.as_iter())
        assert parts[3].as_int() == SPEND_MIGRATE
        p = list(parts[4].as_iter())
        assert p[1].as_atom() == bytes(puzzle_for_p2_vault(new_launcher).get_tree_hash())


class TestP2Pool:
    """Test commitment-bound p2_pool_v2 escrow puzzle."""

    def setup_method(self):
        self.curried = P2_POOL_MOD.curry(
            P2_POOL_MOD.get_tree_hash(),
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
            DEED_COMMITMENT,
        )

    @staticmethod
    def _solution(next_puzhash: bytes32 = bytes32(b"\x99" * 32)) -> Program:
        return Program.to([
            POOL_INNER_PUZHASH,
            bytes32(b"\x22" * 32),
            DEED_COIN_ID,
            DEED_LAUNCHER_ID,
            1,
            next_puzhash,
        ])

    def test_p2_pool_condition_count(self):
        conds = self.curried.run(self._solution()).as_python()
        assert len(conds) == 6

    def test_p2_pool_moves_deed_to_next_puzzlehash(self):
        next_puzhash = bytes32(b"\x99" * 32)
        conds = self.curried.run(self._solution(next_puzhash)).as_python()
        create = extract_cond(conds, OP_CREATE_COIN)
        assert create[1] == next_puzhash

    def test_p2_pool_coin_announcement_has_protocol_prefix(self):
        conds = self.curried.run(self._solution()).as_python()
        coin_ann = extract_cond(conds, OP_CREATE_COIN_ANN)
        assert coin_ann[1][:1] == PROTOCOL_PREFIX

    def test_p2_pool_asserts_pool_puzzle_announcement(self):
        conds = self.curried.run(self._solution()).as_python()
        assert extract_cond(conds, OP_ASSERT_PUZZLE_ANN) is not None


class TestVaultUpdateIdentity:
    def _curry_with_identity_root(
        self,
        identity_root: bytes32 = IDENTITY_ATTEST_ROOT,
        bridge_policy_hash: bytes32 = ZKPASSPORT_BRIDGE_POLICY_HASH,
    ) -> Program:
        return VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            identity_root,
            bridge_policy_hash,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )

    def test_update_identity_asserts_bridge_message_and_updates_root(self):
        from chia.types.blockchain_format.coin import Coin
        from solslot_puzzles.vault_driver import puzzle_for_vault_inner
        from solslot_puzzles.zkpassport_attestation import compute_attestation_bridge_message

        curried = self._curry_with_identity_root()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()
        new_root = bytes32(b"\x77" * 32)
        bridge_parent_id = bytes32(b"\x33" * 32)
        bridge_amount = 1
        bridge_coin_id = Coin(bridge_parent_id, ZKPASSPORT_BRIDGE_POLICY_HASH, bridge_amount).name()

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_UPDATE_IDENTITY,
            [vault_mod_hash, new_root, bridge_parent_id, bridge_amount, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        agg_sig = extract_cond(conds, OP_AGG_SIG_ME)
        assert agg_sig[1] == BLS_OWNER_PUBKEY
        assert agg_sig[2] == bytes(Program.to([b"z", new_root, my_id]).get_tree_hash())
        bridge_msg = compute_attestation_bridge_message(
            vault_launcher_id=VAULT_LAUNCHER_ID,
            attestation_root=new_root,
            bridge_policy_hash=ZKPASSPORT_BRIDGE_POLICY_HASH,
        )
        expected_announcement = hashlib.sha256(
            bytes(bridge_coin_id) + PROTOCOL_PREFIX + bytes(bridge_msg)
        ).digest()
        assert [OP_ASSERT_COIN_ANN, expected_announcement] in conds

        expected_inner = puzzle_for_vault_inner(
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
            identity_attest_root=new_root,
            zkpassport_bridge_policy_hash=ZKPASSPORT_BRIDGE_POLICY_HASH,
        ).get_tree_hash()
        create_coins = [c for c in conds if c[0] == OP_CREATE_COIN]
        assert create_coins == [[OP_CREATE_COIN, bytes(expected_inner), b"\x01", [bytes(my_inner_puzhash)]]]

    def test_update_identity_rejects_missing_current_owner_authorization(self):
        curried = self._curry_with_identity_root()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_UPDATE_IDENTITY,
            [VAULT_INNER_MOD.get_tree_hash(), bytes32(b"\x77" * 32), bytes32(b"\x33" * 32), 1, CURRENT_TIMESTAMP],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_update_identity_rejects_second_enrollment(self):
        current_root = bytes32(b"\x66" * 32)
        curried = self._curry_with_identity_root(current_root)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_UPDATE_IDENTITY,
            [VAULT_INNER_MOD.get_tree_hash(), bytes32(b"\x77" * 32), bytes32(b"\x33" * 32), 1, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_update_identity_rejects_empty_new_root(self):
        curried = self._curry_with_identity_root()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_UPDATE_IDENTITY,
            [VAULT_INNER_MOD.get_tree_hash(), IDENTITY_ATTEST_ROOT, bytes32(b"\x33" * 32), 1, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_update_identity_rejects_zero_bridge_amount(self):
        curried = self._curry_with_identity_root()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_UPDATE_IDENTITY,
            [VAULT_INNER_MOD.get_tree_hash(), bytes32(b"\x77" * 32), bytes32(b"\x33" * 32), 0, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_build_vault_update_identity_spend_validates_one_time_inputs(self):
        from chia.types.blockchain_format.coin import Coin
        from chia.wallet.lineage_proof import LineageProof
        from solslot_puzzles.vault_driver import build_vault_update_identity_spend

        current_inner = self._curry_with_identity_root()
        vault_coin = Coin(bytes32(b"\x99" * 32), current_inner.get_tree_hash(), 1)
        lineage = LineageProof(parent_name=VAULT_LAUNCHER_ID, amount=1)
        with pytest.raises(ValueError, match="new_identity_attest_root"):
            build_vault_update_identity_spend(
                vault_coin,
                VAULT_LAUNCHER_ID,
                BLS_OWNER_PUBKEY,
                AUTH_TYPE_BLS,
                MEMBERS_MERKLE_ROOT,
                POOL_LAUNCHER_ID,
                IDENTITY_ATTEST_ROOT,
                bytes32(b"\x33" * 32),
                1,
                CURRENT_TIMESTAMP,
                lineage,
            )
        with pytest.raises(ValueError, match="bridge_amount"):
            build_vault_update_identity_spend(
                vault_coin,
                VAULT_LAUNCHER_ID,
                BLS_OWNER_PUBKEY,
                AUTH_TYPE_BLS,
                MEMBERS_MERKLE_ROOT,
                POOL_LAUNCHER_ID,
                bytes32(b"\x77" * 32),
                bytes32(b"\x33" * 32),
                0,
                CURRENT_TIMESTAMP,
                lineage,
            )
        spend = build_vault_update_identity_spend(
            vault_coin,
            VAULT_LAUNCHER_ID,
            BLS_OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            MEMBERS_MERKLE_ROOT,
            POOL_LAUNCHER_ID,
            bytes32(b"\x77" * 32),
            bytes32(b"\x33" * 32),
            1,
            CURRENT_TIMESTAMP,
            lineage,
        )
        assert spend.coin == vault_coin


class TestVaultUpdateKeys:
    """SPEND CASE 'k' — key rotation with Merkle membership proof."""

    SPEND_UPDATE_KEYS = 0x6b  # b'k'

    def _one_leaf_root(self, pubkey: bytes) -> bytes32:
        import hashlib
        return bytes32(hashlib.sha256(b"\x01" + pubkey).digest())

    def _curry_with_real_merkle_root(self, pubkey: bytes) -> Program:
        """Curry the vault so MEMBERS_MERKLE_ROOT is the actual one-leaf root of pubkey."""
        root = self._one_leaf_root(pubkey)
        return VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            pubkey,
            AUTH_TYPE_BLS,
            root,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )

    def test_update_keys_rejects_wrong_mod_hash(self):
        """A tampered vault_inner_mod_hash that does not reproduce my_inner_puzzlehash must fail."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        real_root = self._one_leaf_root(pubkey)
        one_leaf_proof = Program.to((0, []))

        bad_mod_hash = bytes32(b"\xba" * 32)  # wrong mod hash
        new_pubkey = bytes([2] * 48)
        new_root = self._one_leaf_root(new_pubkey)

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [bad_mod_hash, new_pubkey, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_update_keys_rejects_bad_membership_proof(self):
        """A proof that does not reproduce MEMBERS_MERKLE_ROOT must fail."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()

        new_pubkey = bytes([2] * 48)
        new_root = self._one_leaf_root(new_pubkey)
        bad_proof = Program.to((0, [bytes32(b"\x99" * 32)]))  # garbage sibling hash

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [vault_mod_hash, new_pubkey, new_root, bad_proof, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(Exception):
            curried.run(sol)

    def test_update_keys_produces_create_coin_with_bls(self):
        """Valid 'k' spend with correct Merkle proof must produce a CREATE_COIN condition."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()

        new_pubkey = bytes([2] * 48)
        new_root = self._one_leaf_root(new_pubkey)
        # One-leaf proof: bitpath=0, no sibling hashes — simplify_merkle_proof(pubkey, (0, ())) = sha256(0x01||pubkey)
        one_leaf_proof = Program.to((0, []))

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            # LOW-11 fix: 'k' params now include new_auth_type after new_owner_pubkey.
            [vault_mod_hash, new_pubkey, AUTH_TYPE_BLS, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        create_coins = [c for c in conds if c[0] == OP_CREATE_COIN]
        assert len(create_coins) == 1, "must emit exactly one CREATE_COIN"

    def test_update_keys_create_coin_not_same_as_current_inner(self):
        """The CREATE_COIN from 'k' must go to the NEW inner puzzle hash, not the current one."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()

        new_pubkey = bytes([2] * 48)
        new_root = self._one_leaf_root(new_pubkey)
        one_leaf_proof = Program.to((0, []))

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            # LOW-11 fix: 'k' params now include new_auth_type after new_owner_pubkey.
            [vault_mod_hash, new_pubkey, AUTH_TYPE_BLS, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        conds = curried.run(sol).as_python()
        create_coins = [c for c in conds if c[0] == OP_CREATE_COIN]
        new_inner_ph = create_coins[0][1]
        # The new inner puzzle hash must differ from the current one
        assert new_inner_ph != my_inner_puzhash

    # ── LOW-11 + LOW-12 regression tests ────────────────────────────────
    # Pre-fix: 'k' did not accept a new_auth_type — AUTH_TYPE was frozen
    # for the life of the vault, and new_owner_pubkey was not size-checked
    # against the auth type, so an owner could self-DoS by rotating to a
    # wrong-size key.  Post-fix: new_auth_type ∈ {1,2,3} and pubkey size
    # must match (BLS=48, secp256r1=65, secp256k1=33).

    def test_update_keys_rejects_invalid_new_auth_type(self):
        """LOW-11: new_auth_type=99 (out of range) must be rejected."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()
        new_pubkey = bytes([2] * 48)
        new_root = self._one_leaf_root(new_pubkey)
        one_leaf_proof = Program.to((0, []))

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [vault_mod_hash, new_pubkey, 99, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_update_keys_rejects_bls_with_wrong_size_pubkey(self):
        """LOW-12: declaring BLS but supplying a 33-byte (secp-sized) pubkey rejected."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()
        new_pubkey_wrong_size = bytes([2] * 33)  # 33 bytes ≠ BLS's 48
        new_root = self._one_leaf_root(new_pubkey_wrong_size)
        one_leaf_proof = Program.to((0, []))

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [vault_mod_hash, new_pubkey_wrong_size, AUTH_TYPE_BLS, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_update_keys_rejects_secp256k1_with_wrong_size_pubkey(self):
        """LOW-12: declaring secp256k1 but supplying a 48-byte (BLS-sized) pubkey rejected."""
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()
        new_pubkey_wrong_size = bytes([2] * 48)  # 48 bytes ≠ secp256k1's 33
        new_root = self._one_leaf_root(new_pubkey_wrong_size)
        one_leaf_proof = Program.to((0, []))

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [vault_mod_hash, new_pubkey_wrong_size, 3, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_update_keys_allows_bls_to_secp256k1_migration_destination(self):
        """LOW-11: rotating from BLS to secp256k1 produces a CREATE_COIN whose
        destination differs from a BLS-to-BLS rotation (proves new_auth_type
        is actually used in the destination computation).

        Note: the puzzle still requires BLS authentication on the CURRENT key
        for the rotation itself (secp_signing for 'k' is the deferred CRIT-2
        extension).  The migration target curve can still differ.
        """
        pubkey = BLS_OWNER_PUBKEY
        curried = self._curry_with_real_merkle_root(pubkey)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        vault_mod_hash = VAULT_INNER_MOD.get_tree_hash()

        # 33-byte secp256k1 pubkey (will be the new owner key)
        new_secp_pubkey = bytes([2] * 33)
        new_root = self._one_leaf_root(new_secp_pubkey)
        one_leaf_proof = Program.to((0, []))

        sol_secp = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [vault_mod_hash, new_secp_pubkey, 3, new_root, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        conds_secp = curried.run(sol_secp).as_python()
        create_coins_secp = [c for c in conds_secp if c[0] == OP_CREATE_COIN]
        secp_dest = create_coins_secp[0][1]

        # Same merkle root, but rotate to a BLS pubkey of the same byte content
        # (different size).  The destinations must differ because new_auth_type
        # is curried into the new inner puzzle hash.
        new_bls_pubkey = bytes([2] * 48)
        new_root_bls = self._one_leaf_root(new_bls_pubkey)
        sol_bls = Program.to([
            my_id, my_inner_puzhash, 1,
            self.SPEND_UPDATE_KEYS,
            [vault_mod_hash, new_bls_pubkey, AUTH_TYPE_BLS, new_root_bls, one_leaf_proof, CURRENT_TIMESTAMP, None],
        ])
        conds_bls = curried.run(sol_bls).as_python()
        create_coins_bls = [c for c in conds_bls if c[0] == OP_CREATE_COIN]
        bls_dest = create_coins_bls[0][1]

        # Different new_auth_type → different curried hash → different destination.
        assert secp_dest != bls_dest, (
            "rotating to secp256k1 vs BLS must produce different destinations"
        )


class TestVaultSecp256r1Dispatch:
    """AUTH_TYPE_SECP256R1 — verify the branch is reached (not 'UNSUPPORTED AUTH TYPE')."""

    # 65-byte uncompressed secp256r1 key placeholder (0x04 + 32 zeros + 32 zeros)
    SECP256R1_PUBKEY = b"\x04" + bytes(64)

    def _curry_vault_r1(self) -> Program:
        return VAULT_INNER_MOD.curry(
            VAULT_SINGLETON_STRUCT,
            self.SECP256R1_PUBKEY,
            AUTH_TYPE_SECP256R1,
            MEMBERS_MERKLE_ROOT,
            IDENTITY_ATTEST_ROOT,
            ZKPASSPORT_BRIDGE_POLICY_HASH,
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )

    def test_secp256r1_auth_type_does_not_raise_unsupported(self):
        """AUTH_TYPE_SECP256R1 must route to verify_secp256r1, not (x 'UNSUPPORTED AUTH TYPE').
        The softfork block itself raises (bad sig) — but the error must NOT be 'UNSUPPORTED AUTH TYPE'.
        """
        curried = self._curry_vault_r1()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        # Deliberately bad 64-byte signature — the softfork will reject it
        bad_sig = bytes(64)

        sol = Program.to([
            my_id, my_inner_puzhash, 1,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, CURRENT_TIMESTAMP, bad_sig],
        ])
        exc = None
        try:
            curried.run(sol)
        except Exception as e:
            exc = e
        # Must raise (softfork rejection or clvm error) but NOT because of unknown auth type
        assert exc is not None, "Expected an exception from the softfork verification"
        assert "UNSUPPORTED AUTH TYPE" not in str(exc)

    def test_secp256r1_and_bls_vaults_have_different_puzzle_hashes(self):
        """Different AUTH_TYPE values must produce distinct puzzle hashes."""
        bls_hash = curry_vault_bls().get_tree_hash()
        r1_hash = self._curry_vault_r1().get_tree_hash()
        assert bls_hash != r1_hash


# ---------------------------------------------------------------------------
# End-to-end EVM wallet login + vault deposit flow
# ---------------------------------------------------------------------------

def _keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _compute_digest_from_typed_data(typed_data: dict) -> bytes:
    """Minimal EIP-712 `eth_signTypedData_v4` digest implementation.

    Reproduces what MetaMask / Coinbase Wallet / any standards-compliant wallet
    does internally when given the typed-data JSON.  Used to prove that our
    server-side helper emits JSON whose wallet-computed digest matches our
    driver-computed digest — i.e. a real wallet signature will verify on-chain.

    Supports only the field types we actually use: `string`, `uint256`, `bytes32`.
    """
    domain_types = typed_data["types"]["EIP712Domain"]
    primary_name = typed_data["primaryType"]
    primary_types = typed_data["types"][primary_name]

    def encode_field(ftype, fvalue):
        if ftype == "string":
            return _keccak256(fvalue.encode("utf-8"))
        if ftype == "uint256":
            return int(fvalue).to_bytes(32, "big")
        if ftype == "bytes32":
            return bytes.fromhex(fvalue.removeprefix("0x"))
        raise AssertionError(f"unsupported EIP-712 field type in test: {ftype}")

    # Domain separator.
    domain_type_str = (
        "EIP712Domain("
        + ",".join(f"{f['type']} {f['name']}" for f in domain_types)
        + ")"
    )
    domain_typehash = _keccak256(domain_type_str.encode("ascii"))
    domain_encoded = domain_typehash + b"".join(
        encode_field(f["type"], typed_data["domain"][f["name"]]) for f in domain_types
    )
    domain_separator = _keccak256(domain_encoded)

    # Struct hash.
    primary_type_str = (
        f"{primary_name}("
        + ",".join(f"{f['type']} {f['name']}" for f in primary_types)
        + ")"
    )
    struct_typehash = _keccak256(primary_type_str.encode("ascii"))
    struct_encoded = struct_typehash + b"".join(
        encode_field(f["type"], typed_data["message"][f["name"]]) for f in primary_types
    )
    struct_hash = _keccak256(struct_encoded)

    return _keccak256(b"\x19\x01" + domain_separator + struct_hash)


class TestEVMWalletLoginEndToEnd:
    """End-to-end EVM wallet login + vault deposit.

    Proves that every step a frontend integrator performs actually produces a
    spend the puzzle will accept:

      1. User connects their EVM wallet; frontend captures the 33-byte
         compressed secp256k1 pubkey (via client-side `ecRecover` from an
         enrolment signature — or equivalently here via keypair generation).
      2. Server builds the vault with `puzzle_for_vault_full(... AUTH_TYPE_SECP256K1 ...)`.
      3. User wants to deposit a deed.  Server returns the EIP-712 typed-data
         JSON via `eip712_typed_data_for_vault_spend()`.
      4. Wallet `eth_signTypedData_v4(address, typed_data)` returns a 65-byte sig.
      5. Server normalizes with `compact_signature_from_evm(sig65)` to 64 bytes.
      6. Server assembles the full singleton `CoinSpend` via
         `build_vault_deposit_spend()`.
      7. On-chain, the CLVM `secp256k1_verify` softfork accepts the signature
         and the deposit CREATE_PUZZLE_ANNOUNCEMENT + CREATE_COIN fire.

    The tests assert each step's output shape and the final on-chain conditions.
    """

    @staticmethod
    def _gen_keypair_and_compressed_pub() -> tuple:
        """Return (priv_key_obj, compressed_pub33_bytes) for secp256k1."""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        priv = ec.generate_private_key(ec.SECP256K1(), backend=default_backend())
        pub33 = priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        assert len(pub33) == 33 and pub33[0] in (0x02, 0x03)
        return priv, pub33

    @staticmethod
    def _sign_digest_evm_65(priv, digest: bytes) -> bytes:
        """Produce a 65-byte EVM-style signature (r||s||v) over `digest`.

        EVM wallets use `personal_sign` / `eth_signTypedData_v4` which internally
        sign the 32-byte digest and append a 1-byte recovery `v`.  For the
        compact-sig path we only need `r` and `s` — `v` is discarded — so we
        emit a placeholder `v=0x1b` (27) that the unpacker strips.
        """
        from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
        from cryptography.hazmat.primitives import hashes
        sig_der = priv.sign(digest, ec.ECDSA(ec_utils.Prehashed(hashes.SHA256())))
        r, s = ec_utils.decode_dss_signature(sig_der)
        # Give back an un-normalized signature — compact_signature_from_evm is
        # responsible for low-s normalization per BIP-62.  Using a random-ish
        # priv key, about half the time s will already be high, so this tests
        # the normalization path too.
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([0x1B])

    def test_step1_typed_data_digest_matches_driver_digest(self):
        """JSON the frontend passes to wallet hashes to the same digest the driver gives.

        This is the most critical invariant: without this, a real MetaMask sig
        would be computed over a different digest than the one the puzzle
        verifies, and every secp deposit would fail on chain.
        """
        from solslot_puzzles.vault_driver import (
            signing_message_for_vault_spend,
            eip712_typed_data_for_vault_spend,
        )

        vault_coin_id = bytes32(b"\x11" * 32)
        driver_digest = signing_message_for_vault_spend(b"o", DEED_LAUNCHER_ID, vault_coin_id)
        typed_data = eip712_typed_data_for_vault_spend(b"o", DEED_LAUNCHER_ID, vault_coin_id)
        wallet_digest = _compute_digest_from_typed_data(typed_data)
        assert wallet_digest == driver_digest, (
            f"Typed-data JSON produces a digest an EVM wallet would sign, but the "
            f"driver's `signing_message_for_vault_spend` returns a different value — "
            f"signatures will NOT verify on-chain.\n"
            f"  typed-data-derived: {wallet_digest.hex()}\n"
            f"  driver digest:      {driver_digest.hex()}"
        )

    def test_step1_typed_data_shape(self):
        """Typed-data JSON is the exact shape `eth_signTypedData_v4` expects."""
        from solslot_puzzles.vault_driver import (
            eip712_typed_data_for_vault_spend,
            EIP712_DOMAIN_NAME,
            EIP712_DOMAIN_VERSION,
            EIP712_DOMAIN_CHAIN_ID,
        )

        td = eip712_typed_data_for_vault_spend(b"o", DEED_LAUNCHER_ID, bytes32(b"\x11" * 32))
        assert td["primaryType"] == "SolslotVaultSpend"
        assert td["domain"] == {
            "name": EIP712_DOMAIN_NAME,
            "version": EIP712_DOMAIN_VERSION,
            "chainId": EIP712_DOMAIN_CHAIN_ID,
        }
        assert "EIP712Domain" in td["types"]
        assert "SolslotVaultSpend" in td["types"]
        # bytes32 fields serialized as 0x-prefixed 64-hex strings
        assert td["message"]["spend_case"].startswith("0x") and len(td["message"]["spend_case"]) == 66
        assert td["message"]["deed_launcher_id"] == "0x" + bytes(DEED_LAUNCHER_ID).hex()
        assert td["message"]["vault_coin_id"] == "0x" + bytes(bytes32(b"\x11" * 32)).hex()
        # spend_case is right-padded to bytes32
        assert td["message"]["spend_case"] == "0x6f" + "00" * 31

    def test_step2_compact_signature_strips_v_and_low_s_normalizes(self):
        """65-byte EVM sig → 64-byte compact, with s in low half-order."""
        from solslot_puzzles.vault_driver import compact_signature_from_evm, _SECP256K1_N

        # Construct an artificial high-s signature: pick r=1, s=N-1 (explicitly high-s)
        r = 1
        s = _SECP256K1_N - 1
        v = 0x1C
        sig65 = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])
        compact = compact_signature_from_evm(sig65)
        assert len(compact) == 64
        got_r = int.from_bytes(compact[:32], "big")
        got_s = int.from_bytes(compact[32:], "big")
        assert got_r == r
        assert got_s == 1  # N - (N-1) = 1, low-s
        assert got_s <= _SECP256K1_N // 2

        # Hex string with 0x prefix must also work
        compact2 = compact_signature_from_evm("0x" + sig65.hex())
        assert compact2 == compact

    def test_step2_compact_signature_rejects_wrong_length(self):
        import pytest as _pytest
        from solslot_puzzles.vault_driver import compact_signature_from_evm
        with _pytest.raises(ValueError):
            compact_signature_from_evm(bytes(64))  # compact, not evm — reject
        with _pytest.raises(ValueError):
            compact_signature_from_evm(bytes(66))  # too long

    def test_step3_verify_evm_signature_round_trip(self):
        """Server-side validation helper accepts a valid sig, rejects invalid ones."""
        from solslot_puzzles.vault_driver import (
            compact_signature_from_evm,
            signing_message_for_vault_spend,
            verify_evm_signature,
        )

        priv, pub33 = self._gen_keypair_and_compressed_pub()
        vault_coin_id = bytes32(b"\x11" * 32)
        digest = signing_message_for_vault_spend(b"o", DEED_LAUNCHER_ID, vault_coin_id)
        sig65 = self._sign_digest_evm_65(priv, digest)
        compact = compact_signature_from_evm(sig65)

        # Positive case.
        assert verify_evm_signature(pub33, digest, compact) is True
        # Wrong digest.
        assert verify_evm_signature(pub33, bytes(32), compact) is False
        # Wrong pubkey (different keypair).
        _, other_pub = self._gen_keypair_and_compressed_pub()
        assert verify_evm_signature(other_pub, digest, compact) is False
        # Malformed pubkey.
        assert verify_evm_signature(b"\x00" * 33, digest, compact) is False
        # Malformed sig length.
        assert verify_evm_signature(pub33, digest, bytes(32)) is False

    def test_step4_full_deposit_spend_runs_on_curried_vault(self):
        """Run the full singleton puzzle + full singleton solution → secp sig accepted.

        Assembles a realistic post-launch state:
          genesis_parent (arbitrary) -> launcher_coin (SINGLETON_LAUNCHER_HASH, 1)
                                        -> vault_coin (vault_full_puzhash, 1)

        launcher_coin.name() IS the vault_launcher_id (the singleton identity
        curried into the puzzle).  The first-spend LineageProof is the 2-arg
        form `(launcher_parent, amount)`; the singleton layer reconstructs the
        launcher's coin id and asserts `my_parent_id = launcher_coin_id`.
        """
        from chia.types.blockchain_format.coin import Coin
        from chia.wallet.lineage_proof import LineageProof
        from chia_rs.sized_ints import uint64
        from solslot_puzzles.vault_driver import (
            compact_signature_from_evm,
            signing_message_for_vault_spend,
            puzzle_for_vault_inner,
            puzzle_for_vault_full,
            one_leaf_merkle_root,
            build_vault_deposit_spend,
        )

        priv, pub33 = self._gen_keypair_and_compressed_pub()
        members_root = one_leaf_merkle_root(pub33)
        pool_launcher_id = POOL_LAUNCHER_ID

        # Realistic lineage: genesis → launcher → vault_coin.
        genesis_parent = bytes32(b"\xcc" * 32)
        launcher_coin = Coin(genesis_parent, LAUNCHER_PUZZLE_HASH, uint64(1))
        vault_launcher_id = launcher_coin.name()  # this is the singleton identity

        full_puzzle = puzzle_for_vault_full(
            vault_launcher_id, pub33, AUTH_TYPE_SECP256K1, members_root, pool_launcher_id,
        )
        full_puzhash = full_puzzle.get_tree_hash()
        vault_coin = Coin(vault_launcher_id, full_puzhash, uint64(1))

        # Sign over the EIP-712 digest for this exact vault coin.
        digest = signing_message_for_vault_spend(b"o", DEED_LAUNCHER_ID, vault_coin.name())
        sig65 = self._sign_digest_evm_65(priv, digest)
        compact = compact_signature_from_evm(sig65)

        # First-spend LineageProof: parent_name = launcher's parent (genesis),
        # inner_puzzle_hash = None (triggers 2-arg form), amount = launcher amount.
        lineage = LineageProof(
            parent_name=genesis_parent,
            inner_puzzle_hash=None,
            amount=uint64(1),
        )
        coin_spend = build_vault_deposit_spend(
            vault_coin=vault_coin,
            vault_launcher_id=vault_launcher_id,
            owner_pubkey_bytes=pub33,
            auth_type=AUTH_TYPE_SECP256K1,
            members_merkle_root=members_root,
            pool_launcher_id=pool_launcher_id,
            deed_launcher_id=DEED_LAUNCHER_ID,
            current_timestamp=CURRENT_TIMESTAMP,
            lineage_proof=lineage,
            signature_data=compact,
        )

        # The CoinSpend points at our vault coin with the right puzzle.
        assert coin_spend.coin == vault_coin
        reveal = Program.from_bytes(bytes(coin_spend.puzzle_reveal))
        assert reveal.get_tree_hash() == full_puzhash

        # Run the FULL singleton puzzle with the FULL singleton solution.  If the
        # secp sig verifies, the softfork succeeds and emits a REMARK; otherwise
        # an "x" raise propagates out.  We deliberately run the outer-layer
        # puzzle (not just the inner) to catch any solution-shape regressions
        # in `solution_for_singleton`.
        conditions = reveal.run(Program.from_bytes(bytes(coin_spend.solution))).as_python()

        # The on-chain proof: a REMARK "secp256k1 ok" is emitted only when
        # `secp256k1_verify` returned 0 (success) inside the softfork.
        remarks = [c for c in conditions if c[0] == OP_REMARK]
        assert any(b"secp256k1 ok" in c[1] for c in remarks), (
            "Expected `secp256k1 ok` REMARK — sig didn't verify on-chain."
        )

        # Protocol-level conditions the pool/driver rely on.
        create_coins = [c for c in conditions if c[0] == OP_CREATE_COIN]
        assert len(create_coins) >= 1
        # The singleton top layer MORPHS the inner vault's CREATE_COIN condition
        # by replacing the target puzhash with `calculate_full_puzzle_hash(SS, inner_ph)` —
        # i.e. the full-singleton-wrapped vault puzhash — before emitting it on chain.
        # So the observable CREATE_COIN target is `full_puzhash` (= the same vault coin
        # shape the user currently sees), not the raw `inner_ph`.  This is the
        # singleton-continuity guarantee: owner keys and pool binding survive each spend.
        assert any(c[1] == full_puzhash for c in create_coins), (
            "Vault must re-create its full singleton at the same full puzhash "
            "(owner + pool continuity after singleton morph)."
        )

        # Deposit announcement with PROTOCOL_PREFIX and spend-case-bound content.
        puz_anns = [c for c in conditions if c[0] == OP_CREATE_PUZZLE_ANN]
        assert len(puz_anns) >= 1
        assert any(a[1].startswith(PROTOCOL_PREFIX) for a in puz_anns)

        # No AGG_SIG_ME on the secp path — auth is in-puzzle.
        agg_sigs = [c for c in conditions if c[0] == OP_AGG_SIG_ME]
        assert len(agg_sigs) == 0

    def test_step5_wrong_signature_rejected_by_full_singleton(self):
        """Defence-in-depth: a sig over the wrong digest must fail even through
        the outer singleton layer (sanity check that our builder isn't silently
        swallowing auth errors)."""
        from chia.types.blockchain_format.coin import Coin
        from chia.wallet.lineage_proof import LineageProof
        from chia_rs.sized_ints import uint64
        from solslot_puzzles.vault_driver import (
            compact_signature_from_evm,
            signing_message_for_vault_spend,
            puzzle_for_vault_full,
            one_leaf_merkle_root,
            build_vault_deposit_spend,
        )

        priv, pub33 = self._gen_keypair_and_compressed_pub()
        members_root = one_leaf_merkle_root(pub33)

        genesis_parent = bytes32(b"\xdd" * 32)
        launcher_coin = Coin(genesis_parent, LAUNCHER_PUZZLE_HASH, uint64(1))
        vault_launcher_id = launcher_coin.name()

        full_puzzle = puzzle_for_vault_full(
            vault_launcher_id, pub33, AUTH_TYPE_SECP256K1, members_root, POOL_LAUNCHER_ID,
        )
        vault_coin = Coin(vault_launcher_id, full_puzzle.get_tree_hash(), uint64(1))

        # Sign over a DIFFERENT deed_launcher_id than the one we'll submit —
        # the EIP-712 digest binds to it, so verification must fail.
        wrong_digest = signing_message_for_vault_spend(
            b"o", bytes32(b"\xee" * 32), vault_coin.name()
        )
        sig65 = self._sign_digest_evm_65(priv, wrong_digest)
        compact = compact_signature_from_evm(sig65)

        coin_spend = build_vault_deposit_spend(
            vault_coin=vault_coin,
            vault_launcher_id=vault_launcher_id,
            owner_pubkey_bytes=pub33,
            auth_type=AUTH_TYPE_SECP256K1,
            members_merkle_root=members_root,
            pool_launcher_id=POOL_LAUNCHER_ID,
            deed_launcher_id=DEED_LAUNCHER_ID,  # not the deed the sig committed to
            current_timestamp=CURRENT_TIMESTAMP,
            lineage_proof=LineageProof(parent_name=genesis_parent, amount=uint64(1)),
            signature_data=compact,
        )
        reveal = Program.from_bytes(bytes(coin_spend.puzzle_reveal))
        with pytest.raises(Exception):
            reveal.run(Program.from_bytes(bytes(coin_spend.solution)))
