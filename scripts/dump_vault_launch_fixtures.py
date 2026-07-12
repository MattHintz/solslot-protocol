"""Generate the fixture for the portal's TS new-vault launch builder (Brick 6a).

The TS service ``vault-launch-spend.service.ts`` reproduces the vault
launch primitives from ``solslot_puzzles/vault_driver.py`` so the portal can
build a fresh vault launcher spend entirely client-side during a one-click
upgrade without an API dependency:

  * ``parseVault``            ↔ ``parse_vault_inner_puzzle`` (identity + params)
  * ``buildVaultInnerPuzzle`` ↔ ``puzzle_for_vault_inner`` (curry-order contract)
  * ``vaultFullPuzzleHash``   ↔ ``puzzle_for_vault_full``
  * ``computeLaunchOutputs``  ↔ launcher coin + eve coin + launcher announcement

This script writes a JSON fixture mapping each helper to ``(input, expected)``
cases.  The portal's Karma test reads it and asserts the TS implementation
produces byte-identical hex.

Usage::

    cd solslot-protocol
    .venv/bin/python scripts/dump_vault_launch_fixtures.py

The fixture is re-checked on every PR by ``tests/test_vault_launch_fixtures.py``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    VAULT_INNER_MOD,
    one_leaf_merkle_root,
    puzzle_for_vault_full,
    puzzle_for_vault_inner,
)
from solslot_puzzles.vault_version_registry_driver import (
    compute_canonical_params_hash,
)


def _hex(b: bytes) -> str:
    return "0x" + bytes(b).hex()


# ── Representative identity + params (distinct sentinels so a TS port that
# swaps two curried args produces a different output). ─────────────────────
OWNER_PUBKEY = b"\xb0" * 48  # 48-byte BLS pubkey (length-only validation)
AUTH_TYPE = AUTH_TYPE_BLS
MEMBERS_MERKLE_ROOT = one_leaf_merkle_root(OWNER_PUBKEY)
IDENTITY_ATTEST_ROOT = bytes32(b"\x33" * 32)
POOL_LAUNCHER_ID = bytes32(b"\x66" * 32)
BRIDGE_POLICY_HASH = bytes32(b"\xdd" * 32)

# Canonical params preimage as curried into the vault inner puzzle.
PARAMS = {
    "poolSingletonModHash": _hex(SINGLETON_MOD_HASH),
    "poolLauncherId": _hex(POOL_LAUNCHER_ID),
    "poolSingletonLauncherPuzzleHash": _hex(SINGLETON_LAUNCHER_HASH),
    "zkpassportBridgePolicyHash": _hex(BRIDGE_POLICY_HASH),
}
IDENTITY = {
    "ownerPubkey": _hex(OWNER_PUBKEY),
    "authType": AUTH_TYPE,
    "membersMerkleRoot": _hex(MEMBERS_MERKLE_ROOT),
    "identityAttestRoot": _hex(IDENTITY_ATTEST_ROOT),
}


def _vault_inner(launcher_id: bytes32) -> Program:
    return puzzle_for_vault_inner(
        launcher_id,
        OWNER_PUBKEY,
        AUTH_TYPE,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=BRIDGE_POLICY_HASH,
    )


def _vault_full(launcher_id: bytes32) -> Program:
    return puzzle_for_vault_full(
        launcher_id,
        OWNER_PUBKEY,
        AUTH_TYPE,
        MEMBERS_MERKLE_ROOT,
        POOL_LAUNCHER_ID,
        identity_attest_root=IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=BRIDGE_POLICY_HASH,
    )


def build_fixture() -> dict[str, Any]:
    canonical_params_hash = compute_canonical_params_hash(
        pool_singleton_mod_hash=bytes32(SINGLETON_MOD_HASH),
        pool_launcher_id=POOL_LAUNCHER_ID,
        pool_singleton_launcher_puzzle_hash=bytes32(SINGLETON_LAUNCHER_HASH),
        zkpassport_bridge_policy_hash=BRIDGE_POLICY_HASH,
    )

    # ── parseVault: serialize a full reveal at a fixed launcher id; the TS
    # port deserializes + uncurries it back to identity + params. ──────────
    parse_launcher = bytes32(b"\x12" * 32)
    parse_full = _vault_full(parse_launcher)
    parse_inner = _vault_inner(parse_launcher)
    parse_cases = [
        {
            "label": "bls-single-key-vault",
            "input": {"full_puzzle_reveal": _hex(bytes(parse_full))},
            "expected": {
                "identity": IDENTITY,
                "params": PARAMS,
                "vaultInnerModHash": _hex(VAULT_INNER_MOD.get_tree_hash()),
                "canonicalParamsHash": _hex(canonical_params_hash),
            },
        },
    ]

    # ── vault inner / full puzzle hash at distinct launcher ids. ───────────
    inner_cases: list[dict[str, Any]] = []
    full_cases: list[dict[str, Any]] = []
    for launcher_id, label in (
        (bytes32(b"\x11" * 32), "launcher-11"),
        (bytes32(b"\xab" * 32), "launcher-ab"),
        (bytes32(b"\x55" * 32), "launcher-55"),
    ):
        inner_cases.append(
            {
                "label": label,
                "input": {"launcher_id": _hex(launcher_id)},
                "expected": _hex(_vault_inner(launcher_id).get_tree_hash()),
            }
        )
        full_cases.append(
            {
                "label": label,
                "input": {"launcher_id": _hex(launcher_id)},
                "expected": _hex(_vault_full(launcher_id).get_tree_hash()),
            }
        )

    # ── computeLaunchOutputs: parent coin id → every deterministic output. ─
    launch_cases: list[dict[str, Any]] = []
    for parent_coin_id, label in (
        (bytes32(b"\xaa" * 32), "parent-aa"),
        (bytes32(b"\x01" * 32), "parent-01"),
    ):
        launcher_coin = Coin(parent_coin_id, SINGLETON_LAUNCHER_HASH, 1)
        launcher_id = bytes32(launcher_coin.name())
        full_puzzle = _vault_full(launcher_id)
        eve_full_ph = bytes32(full_puzzle.get_tree_hash())
        inner_ph = bytes32(_vault_inner(launcher_id).get_tree_hash())
        eve_coin = Coin(launcher_id, eve_full_ph, 1)
        launcher_solution = Program.to([eve_full_ph, 1, []])
        ann_msg = bytes32(launcher_solution.get_tree_hash())
        ann_id = hashlib.sha256(bytes(launcher_id) + bytes(ann_msg)).digest()
        launch_cases.append(
            {
                "label": label,
                "input": {"parent_coin_id": _hex(parent_coin_id)},
                "expected": {
                    "launcherId": _hex(launcher_id),
                    "launcherCoin": {
                        "parentCoinInfo": _hex(parent_coin_id),
                        "puzzleHash": _hex(SINGLETON_LAUNCHER_HASH),
                        "amount": 1,
                    },
                    "vaultInnerPuzzleHash": _hex(inner_ph),
                    "vaultFullPuzzleHash": _hex(eve_full_ph),
                    "eveCoin": {
                        "parentCoinInfo": _hex(launcher_id),
                        "puzzleHash": _hex(eve_full_ph),
                        "amount": 1,
                    },
                    "launcherAnnouncementMessage": _hex(ann_msg),
                    "launcherAnnouncementId": _hex(ann_id),
                },
            }
        )

    return {
        "constants": {
            "vault_inner_mod_hash": _hex(VAULT_INNER_MOD.get_tree_hash()),
            "singleton_mod_hash": _hex(SINGLETON_MOD_HASH),
            "singleton_launcher_hash": _hex(SINGLETON_LAUNCHER_HASH),
            "canonical_params_hash": _hex(canonical_params_hash),
        },
        "identity": IDENTITY,
        "params": PARAMS,
        "parse_vault": parse_cases,
        "vault_inner_puzzle_hash": inner_cases,
        "vault_full_puzzle_hash": full_cases,
        "launch_outputs": launch_cases,
    }


def _services_dir() -> Path:
    protocol_root = Path(__file__).resolve().parents[1]
    return protocol_root / "fixtures" / "vault"


def fixture_destination() -> Path:
    return _services_dir() / "vault-launch.fixtures.json"


def puzzle_hex_destination() -> Path:
    return _services_dir() / "vault-current-inner.puzzle-hex.ts"


def build_puzzle_hex_module() -> str:
    """Render the TS module exporting the CURRENT canonical vault inner code.

    The portal's older ``zkpassport-vault-enrollment.puzzle-hex.ts`` carries a
    pre-``migrate`` vault mod; new-vault launches (Brick 6) must use the code
    the vault-version registry publishes today, so we emit it from the live
    ``VAULT_INNER_MOD`` here and pin its tree hash in the fixture.
    """
    hex_str = "0x" + bytes(VAULT_INNER_MOD).hex()
    mod_hash = _hex(VAULT_INNER_MOD.get_tree_hash())
    return (
        "/**\n"
        " * Serialized CURRENT canonical vault inner puzzle\n"
        " * (``vault_singleton_inner.clsp``), the code the on-chain\n"
        " * vault-version registry publishes today (includes the ``migrate``\n"
        " * spend case, Brick 3).  Used by the one-click upgrade's new-vault\n"
        " * launch builder so it always launches at the canonical version.\n"
        " *\n"
        " * GENERATED by ``solslot-protocol/scripts/dump_vault_launch_fixtures.py``\n"
        " * and pinned cross-repo by ``tests/test_vault_launch_fixtures.py``.\n"
        " * DO NOT edit by hand.\n"
        " *\n"
        f" * tree hash: {mod_hash}\n"
        " */\n"
        f"export const VAULT_CURRENT_INNER_PUZZLE_HEX =\n  '{hex_str}';\n"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    hex_dest = puzzle_hex_destination()
    hex_dest.write_text(build_puzzle_hex_module())
    print(f"wrote fixture to {dest}")
    print(f"wrote vault hex module to {hex_dest}")
    print(
        f"  vault_inner_mod_hash={fixture['constants']['vault_inner_mod_hash']}, "
        f"{len(fixture['parse_vault'])} parse cases, "
        f"{len(fixture['vault_inner_puzzle_hash'])} inner-hash cases, "
        f"{len(fixture['vault_full_puzzle_hash'])} full-hash cases, "
        f"{len(fixture['launch_outputs'])} launch cases"
    )


if __name__ == "__main__":
    main()
