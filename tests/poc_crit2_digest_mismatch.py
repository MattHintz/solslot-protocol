"""PoC: demonstrate CRITICAL-2 — secp256k1/r1 digest mismatch.

Run:
    PYTHONPATH=. .venv/bin/python tests/poc_crit2_digest_mismatch.py

Shows that the digest computed by the driver (EIP-712 compliant, binds
vault_coin_id) differs from the digest the puzzle actually verifies
(sha256tree of (spend_case, deed_launcher_id), no vault_coin_id).
Any real EVM/Coinbase/MetaMask signature produced via the driver will
therefore fail `secp256k1_verify` inside the softfork.
"""
import hashlib

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
from Crypto.Hash import keccak as _keccak


def keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


# Must match the constants in vault_singleton_inner.clsp
PREFIX_AND_DOMAIN_SEPARATOR = bytes.fromhex(
    "190167505ccc4add964dd963c6aaf178a28fa8d7d835a358261d9e03e40ca7b3f2b9"
)
TYPE_STRING = b"SolslotVaultSpend(bytes32 spend_case,bytes32 deed_launcher_id,bytes32 vault_coin_id)"
TYPEHASH = keccak256(TYPE_STRING)


def driver_digest(spend_case: bytes, deed_launcher_id: bytes, vault_coin_id: bytes) -> bytes:
    """Digest the wallet signs (EIP-712 compliant, binds vault_coin_id)."""
    spend_case_padded = spend_case.ljust(32, b"\x00")
    struct_hash = keccak256(TYPEHASH + spend_case_padded + deed_launcher_id + vault_coin_id)
    return keccak256(PREFIX_AND_DOMAIN_SEPARATOR + struct_hash)


def puzzle_digest_prefix(spend_case_byte: int, deed_launcher_id: bytes) -> bytes:
    """Digest the puzzle currently verifies (sha256tree only, no vault_coin_id)."""
    msg = Program.to([spend_case_byte, deed_launcher_id]).get_tree_hash()
    struct_hash = keccak256(TYPEHASH + msg)
    return keccak256(PREFIX_AND_DOMAIN_SEPARATOR + struct_hash)


def puzzle_digest_fix(spend_case: bytes, deed_launcher_id: bytes, vault_coin_id: bytes) -> bytes:
    """Digest the puzzle SHOULD verify after the CRIT-2 fix (binds vault_coin_id via EIP-712 concat)."""
    spend_case_padded = spend_case.ljust(32, b"\x00")
    struct_hash = keccak256(TYPEHASH + spend_case_padded + deed_launcher_id + vault_coin_id)
    return keccak256(PREFIX_AND_DOMAIN_SEPARATOR + struct_hash)


def main():
    spend_case = b"o"                              # SPEND_DEPOSIT_TO_POOL = 0x6f
    deed_launcher_id = bytes32(b"\xdd" * 32)
    vault_coin_id = bytes32(b"\x11" * 32)

    d_driver = driver_digest(spend_case, deed_launcher_id, vault_coin_id).hex()
    d_puzzle = puzzle_digest_prefix(0x6f, deed_launcher_id).hex()
    d_fix = puzzle_digest_fix(spend_case, deed_launcher_id, vault_coin_id).hex()

    print("CRITICAL-2 — secp256k1/r1 digest mismatch PoC")
    print("-" * 72)
    print(f"Driver-computed digest (what a real wallet signs):")
    print(f"  {d_driver}")
    print(f"Pre-fix puzzle-computed digest (what secp256k1_verify checks):")
    print(f"  {d_puzzle}")
    print(f"Post-fix puzzle-computed digest (after Option A applied):")
    print(f"  {d_fix}")
    print()
    if d_driver != d_puzzle:
        print("=> PRE-FIX: MISMATCH — wallet signatures will NEVER verify on-chain.")
    else:
        print("=> PRE-FIX: digests match (unexpected).")
    if d_driver == d_fix:
        print("=> POST-FIX: MATCH — wallet signatures verify after Option A fix.")
    else:
        print("=> POST-FIX: still mismatch (fix design error).")


if __name__ == "__main__":
    main()
