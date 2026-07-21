"""Generate the canonical Solslot V2 zkPassport-to-Chia enrollment fixture."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import SINGLETON_LAUNCHER_HASH
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    DEFAULT_IDENTITY_ATTEST_ROOT,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
    puzzle_for_vault_inner,
)
from solslot_puzzles.zkpassport_bridge_driver import (
    build_bridge_and_vault_update_identity_bundle,
    make_bridge_policy_hash,
)


def b32(byte: int) -> bytes32:
    return bytes32(bytes([byte]) * 32)


def hx(value: bytes | bytes32) -> str:
    return "0x" + bytes(value).hex()


VALIDATOR_PUBKEYS = [bytes([byte]) * 48 for byte in (1, 2, 3)]
THRESHOLD = 2
SIGNER_INDICES = [0, 2]
LAUNCHER_PARENT_ID = b32(0x22)
OWNER_PUBKEY = bytes([0xAA]) * 48
AUTH_TYPE = AUTH_TYPE_BLS
MEMBERS_MERKLE_ROOT = one_leaf_merkle_root(OWNER_PUBKEY)
POOL_LAUNCHER_ID = b32(0x44)
BRIDGE_PARENT_ID = b32(0x33)
BRIDGE_AMOUNT = 1
NEW_IDENTITY_ATTEST_ROOT = b32(0x55)
ATTESTATION_LEAF_HASH = b32(0x66)
SCOPED_NULLIFIER = b32(0x77)
NULLIFIER_TYPE = 1
SERVICE_SCOPE_HASH = b32(0x88)
SERVICE_SUBSCOPE_HASH = b32(0x99)
PROOF_TIMESTAMP = 1_779_120_000
CURRENT_TIMESTAMP = 1_779_123_456


def coin_dict(coin: Coin) -> dict[str, Any]:
    return {
        "parentCoinInfo": hx(coin.parent_coin_info),
        "puzzleHash": hx(coin.puzzle_hash),
        "amount": int(coin.amount),
        "coinId": hx(coin.name()),
    }


def spend_dict(spend: Any) -> dict[str, Any]:
    return {
        "coin": coin_dict(spend.coin),
        "puzzleReveal": hx(bytes(spend.puzzle_reveal)),
        "solution": hx(bytes(spend.solution)),
    }


def build_fixture() -> dict[str, Any]:
    launcher_coin = Coin(LAUNCHER_PARENT_ID, SINGLETON_LAUNCHER_HASH, uint64(1))
    vault_launcher_id = bytes32(launcher_coin.name())
    bridge_policy_hash = make_bridge_policy_hash(VALIDATOR_PUBKEYS, THRESHOLD)
    current_inner = puzzle_for_vault_inner(
        vault_launcher_id,
        OWNER_PUBKEY,
        AUTH_TYPE,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    current_full = puzzle_for_vault_full(
        vault_launcher_id,
        OWNER_PUBKEY,
        AUTH_TYPE,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=DEFAULT_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    vault_coin = Coin(vault_launcher_id, bytes32(current_full.get_tree_hash()), uint64(1))
    lineage_proof = LineageProof(
        parent_name=LAUNCHER_PARENT_ID,
        inner_puzzle_hash=None,
        amount=uint64(1),
    )
    bundle = build_bridge_and_vault_update_identity_bundle(
        bridge_parent_id=BRIDGE_PARENT_ID,
        bridge_amount=BRIDGE_AMOUNT,
        validator_pubkeys=VALIDATOR_PUBKEYS,
        threshold=THRESHOLD,
        signer_indices=SIGNER_INDICES,
        vault_coin=vault_coin,
        vault_launcher_id=vault_launcher_id,
        owner_pubkey_bytes=OWNER_PUBKEY,
        auth_type=AUTH_TYPE,
        members_merkle_root=MEMBERS_MERKLE_ROOT,
        pool_launcher_id=POOL_LAUNCHER_ID,
        new_identity_attest_root=NEW_IDENTITY_ATTEST_ROOT,
        attestation_leaf_hash=ATTESTATION_LEAF_HASH,
        scoped_nullifier=SCOPED_NULLIFIER,
        nullifier_type=NULLIFIER_TYPE,
        service_scope_hash=SERVICE_SCOPE_HASH,
        service_subscope_hash=SERVICE_SUBSCOPE_HASH,
        proof_timestamp=PROOF_TIMESTAMP,
        current_timestamp=CURRENT_TIMESTAMP,
        lineage_proof=lineage_proof,
    )
    next_inner = puzzle_for_vault_inner(
        vault_launcher_id,
        OWNER_PUBKEY,
        AUTH_TYPE,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=NEW_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    next_full = puzzle_for_vault_full(
        vault_launcher_id,
        OWNER_PUBKEY,
        AUTH_TYPE,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=NEW_IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=bridge_policy_hash,
    )
    next_coin = Coin(vault_coin.name(), bytes32(next_full.get_tree_hash()), uint64(1))
    bridge_spend = bundle.bridge.coin_spend
    vault_spend = bundle.vault_spend
    return {
        "schemaVersion": 2,
        "protocolVersion": "solslot-v2",
        "inputs": {
            "validatorPubkeys": [hx(pk) for pk in VALIDATOR_PUBKEYS],
            "threshold": THRESHOLD,
            "signerIndices": SIGNER_INDICES,
            "launcherParentId": hx(LAUNCHER_PARENT_ID),
            "vaultLauncherId": hx(vault_launcher_id),
            "ownerPubkey": hx(OWNER_PUBKEY),
            "authType": AUTH_TYPE,
            "membersMerkleRoot": hx(MEMBERS_MERKLE_ROOT),
            "poolLauncherId": hx(POOL_LAUNCHER_ID),
            "bridgeParentId": hx(BRIDGE_PARENT_ID),
            "bridgeAmount": BRIDGE_AMOUNT,
            "newIdentityAttestRoot": hx(NEW_IDENTITY_ATTEST_ROOT),
            "attestationLeafHash": hx(ATTESTATION_LEAF_HASH),
            "scopedNullifier": hx(SCOPED_NULLIFIER),
            "nullifierType": NULLIFIER_TYPE,
            "serviceScopeHash": hx(SERVICE_SCOPE_HASH),
            "serviceSubscopeHash": hx(SERVICE_SUBSCOPE_HASH),
            "proofTimestamp": PROOF_TIMESTAMP,
            "currentTimestamp": CURRENT_TIMESTAMP,
        },
        "expected": {
            "bridgePolicyHash": hx(bridge_policy_hash),
            "bridgeCoinId": hx(bridge_spend.coin.name()),
            "vaultInnerPuzzleHash": hx(current_inner.get_tree_hash()),
            "vaultFullPuzzleHash": hx(current_full.get_tree_hash()),
            "vaultCoinId": hx(vault_coin.name()),
            "expectedNextVaultInnerPuzzleHash": hx(next_inner.get_tree_hash()),
            "expectedNextVaultFullPuzzleHash": hx(next_full.get_tree_hash()),
            "expectedNextVaultCoinId": hx(next_coin.name()),
            "bridgePuzzleReveal": hx(bytes(bridge_spend.puzzle_reveal)),
            "bridgeSolution": hx(bytes(bridge_spend.solution)),
            "vaultPuzzleReveal": hx(bytes(vault_spend.puzzle_reveal)),
            "vaultSolution": hx(bytes(vault_spend.solution)),
            "coinSpends": [spend_dict(bridge_spend), spend_dict(vault_spend)],
            "bundleCoinSpendOrder": [hx(bridge_spend.coin.name()), hx(vault_spend.coin.name())],
        },
    }


def main() -> None:
    destination = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "zkpassport-vault-enrollment.fixture.json"
    )
    destination.write_text(json.dumps(build_fixture(), indent=2) + "\n")
    print(f"wrote fixture to {destination}")


if __name__ == "__main__":
    main()
