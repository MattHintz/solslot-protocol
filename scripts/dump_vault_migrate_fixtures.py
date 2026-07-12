"""Generate the fixture for the portal's TS deed-migrate spend builder (Brick 6b).

The TS service ``vault-migrate-spend.service.ts`` reproduces the on-chain
deed migration half of a one-click vault upgrade
(``research/POPULIS_VAULT_UPGRADE_DESIGN.md``).  A deed (an NFT singleton
whose inner puzzle is ``p2_vault`` curried to the OLD vault's launcher) is
re-bound to a NEW vault by co-spending:

  * the OLD vault with the ``m`` (migrate) case, which emits
    ``CREATE_PUZZLE_ANNOUNCEMENT(PREFIX || sha256tree(my_id deed_launcher_id
    new_p2_vault_ph))`` and recreates itself unchanged; the BLS owner signs
    ``sha256tree(SPEND_MIGRATE deed_launcher_id new_p2_vault_ph my_id)``;
  * the deed's ``p2_vault`` inner, which asserts that announcement and
    ``CREATE_COIN``s the deed to ``new_p2_vault_ph`` (identity preserved).

This script pins, against the Python source of truth in
``vault_driver.py`` + ``tests/test_vault.py::TestVaultBLSMigrate``:

  * the ``p2_vault`` mod hash + current serialized hex (emitted as a TS module);
  * ``migrate_bls_signing_tree``;
  * ``puzzle_for_p2_vault(new_launcher).get_tree_hash()`` (the migration dest);
  * the full serialized vault ``m`` CoinSpend (puzzle reveal + solution);
  * the full serialized deed ``p2_vault`` CoinSpend (puzzle reveal + solution).

Usage::

    cd populis_protocol
    .venv/bin/python scripts/dump_vault_migrate_fixtures.py

Re-checked on every PR by ``tests/test_vault_migrate_fixtures.py``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.types.coin_spend import make_spend
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.vault_driver import (
    AUTH_TYPE_BLS,
    P2_VAULT_MOD,
    SPEND_MIGRATE,
    build_vault_migrate_spend,
    migrate_bls_signing_tree,
    puzzle_for_p2_vault,
    puzzle_for_vault_full,
    puzzle_for_vault_inner,
)

# Reuse the launch fixture's identity/params so the TS migrate spec can pair
# with the same vault descriptor used by the launch builder.
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "scripts"))
import dump_vault_launch_fixtures as dvl  # noqa: E402


def _hex(b: bytes) -> str:
    return "0x" + bytes(b).hex()


# ── Representative coordinates (distinct sentinels). ───────────────────────
OLD_VAULT_LAUNCHER_ID = bytes32(b"\x12" * 32)
NEW_VAULT_LAUNCHER_ID = bytes32(b"\x55" * 32)
DEED_LAUNCHER_ID = bytes32(b"\xde" * 32)
VAULT_PARENT_ID = bytes32(b"\x99" * 32)
DEED_PARENT_ID = bytes32(b"\xed" * 32)
CURRENT_TIMESTAMP = 1_700_000_000


def _vault_inner_ph(launcher_id: bytes32) -> bytes32:
    return bytes32(
        puzzle_for_vault_inner(
            launcher_id,
            dvl.OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            dvl.MEMBERS_MERKLE_ROOT,
            dvl.POOL_LAUNCHER_ID,
            identity_attest_root=dvl.IDENTITY_ATTEST_ROOT,
            zkpassport_bridge_policy_hash=dvl.BRIDGE_POLICY_HASH,
        ).get_tree_hash()
    )


def _vault_full_ph(launcher_id: bytes32) -> bytes32:
    return bytes32(
        puzzle_for_vault_full(
            launcher_id,
            dvl.OWNER_PUBKEY,
            AUTH_TYPE_BLS,
            dvl.MEMBERS_MERKLE_ROOT,
            dvl.POOL_LAUNCHER_ID,
            identity_attest_root=dvl.IDENTITY_ATTEST_ROOT,
            zkpassport_bridge_policy_hash=dvl.BRIDGE_POLICY_HASH,
        ).get_tree_hash()
    )


def build_fixture() -> dict[str, Any]:
    spend_migrate = int(SPEND_MIGRATE)
    dest_ph = bytes32(puzzle_for_p2_vault(NEW_VAULT_LAUNCHER_ID).get_tree_hash())

    # ── vault coin (current code, which carries the 'm' case). ─────────────
    vault_full_ph = _vault_full_ph(OLD_VAULT_LAUNCHER_ID)
    vault_inner_ph = _vault_inner_ph(OLD_VAULT_LAUNCHER_ID)
    vault_coin = Coin(VAULT_PARENT_ID, vault_full_ph, 1)
    vault_coin_id = bytes32(vault_coin.name())
    # Non-eve lineage: parent was a prior state coin with the same inner ph.
    vault_lineage = LineageProof(
        parent_name=bytes32(b"\x98" * 32),
        inner_puzzle_hash=vault_inner_ph,
        amount=1,
    )

    vault_spend = build_vault_migrate_spend(
        vault_coin,
        OLD_VAULT_LAUNCHER_ID,
        dvl.OWNER_PUBKEY,
        AUTH_TYPE_BLS,
        dvl.MEMBERS_MERKLE_ROOT,
        dvl.POOL_LAUNCHER_ID,
        DEED_LAUNCHER_ID,
        NEW_VAULT_LAUNCHER_ID,
        CURRENT_TIMESTAMP,
        vault_lineage,
        identity_attest_root=dvl.IDENTITY_ATTEST_ROOT,
        zkpassport_bridge_policy_hash=dvl.BRIDGE_POLICY_HASH,
    )

    # ── deed coin (singleton wrapping p2_vault curried to the OLD vault). ──
    p2_inner = puzzle_for_p2_vault(OLD_VAULT_LAUNCHER_ID)
    p2_inner_ph = bytes32(p2_inner.get_tree_hash())
    deed_full = puzzle_for_singleton(DEED_LAUNCHER_ID, p2_inner)
    deed_full_ph = bytes32(deed_full.get_tree_hash())
    deed_coin = Coin(DEED_PARENT_ID, deed_full_ph, 1)
    deed_coin_id = bytes32(deed_coin.name())
    deed_lineage = LineageProof(
        parent_name=bytes32(b"\xec" * 32),
        inner_puzzle_hash=p2_inner_ph,
        amount=1,
    )

    # p2_vault inner solution (6 args; first three are curried):
    #   singleton_inner_puzzle_hash = OLD vault inner ph
    #   singleton_coin_id           = vault coin id (the co-spent vault)
    #   my_launcher_id              = deed launcher id
    #   my_singleton_inner_puzzle_hash = deed's own inner ph (= p2_inner ph)
    #   my_amount                   = deed amount
    #   next_puzzlehash             = destination p2_vault ph
    p2_inner_solution = Program.to([
        bytes(vault_inner_ph),
        bytes(vault_coin_id),
        bytes(DEED_LAUNCHER_ID),
        bytes(p2_inner_ph),
        1,
        bytes(dest_ph),
    ])
    deed_full_solution = solution_for_singleton(deed_lineage, 1, p2_inner_solution)
    deed_spend = make_spend(deed_coin, deed_full, deed_full_solution)

    return {
        "constants": {
            "p2_vault_mod_hash": _hex(P2_VAULT_MOD.get_tree_hash()),
            "spend_migrate": spend_migrate,
            "singleton_mod_hash": _hex(SINGLETON_MOD_HASH),
            "singleton_launcher_hash": _hex(SINGLETON_LAUNCHER_HASH),
        },
        "identity": dvl.IDENTITY,
        "params": dvl.PARAMS,
        "migrate_signing_tree": [
            {
                "label": "deed-de-dest-55-vault-coin",
                "input": {
                    "deed_launcher_id": _hex(DEED_LAUNCHER_ID),
                    "new_p2_vault_puzzlehash": _hex(dest_ph),
                    "vault_coin_id": _hex(vault_coin_id),
                },
                "expected": _hex(
                    migrate_bls_signing_tree(DEED_LAUNCHER_ID, dest_ph, vault_coin_id)
                ),
            },
        ],
        "new_p2_vault_puzzle_hash": [
            {
                "label": "new-launcher-55",
                "input": {"vault_launcher_id": _hex(NEW_VAULT_LAUNCHER_ID)},
                "expected": _hex(dest_ph),
            },
            {
                "label": "old-launcher-12",
                "input": {"vault_launcher_id": _hex(OLD_VAULT_LAUNCHER_ID)},
                "expected": _hex(p2_inner_ph),
            },
        ],
        "vault_migrate_spend": [
            {
                "label": "current-code-vault-nonceve",
                "input": {
                    "old_vault_launcher_id": _hex(OLD_VAULT_LAUNCHER_ID),
                    "vault_coin": {
                        "parentCoinInfo": _hex(VAULT_PARENT_ID),
                        "puzzleHash": _hex(vault_full_ph),
                        "amount": 1,
                    },
                    "deed_launcher_id": _hex(DEED_LAUNCHER_ID),
                    "new_vault_launcher_id": _hex(NEW_VAULT_LAUNCHER_ID),
                    "current_timestamp": CURRENT_TIMESTAMP,
                    "lineage_proof": {
                        "parentParentCoinInfo": _hex(vault_lineage.parent_name),
                        "parentInnerPuzzleHash": _hex(vault_inner_ph),
                        "parentAmount": 1,
                    },
                },
                "expected": {
                    "vaultCoinId": _hex(vault_coin_id),
                    "newP2VaultPuzzleHash": _hex(dest_ph),
                    "coin": {
                        "parentCoinInfo": _hex(VAULT_PARENT_ID),
                        "puzzleHash": _hex(vault_full_ph),
                        "amount": 1,
                    },
                    "puzzleReveal": _hex(bytes(vault_spend.puzzle_reveal)),
                    "solution": _hex(bytes(vault_spend.solution)),
                },
            },
        ],
        "deed_migrate_spend": [
            {
                "label": "deed-at-old-vault",
                "input": {
                    "old_vault_launcher_id": _hex(OLD_VAULT_LAUNCHER_ID),
                    "old_vault_inner_puzzle_hash": _hex(vault_inner_ph),
                    "vault_coin_id": _hex(vault_coin_id),
                    "deed_launcher_id": _hex(DEED_LAUNCHER_ID),
                    "deed_coin": {
                        "parentCoinInfo": _hex(DEED_PARENT_ID),
                        "puzzleHash": _hex(deed_full_ph),
                        "amount": 1,
                    },
                    "new_vault_launcher_id": _hex(NEW_VAULT_LAUNCHER_ID),
                    "deed_lineage_proof": {
                        "parentParentCoinInfo": _hex(deed_lineage.parent_name),
                        "parentInnerPuzzleHash": _hex(p2_inner_ph),
                        "parentAmount": 1,
                    },
                },
                "expected": {
                    "deedCoinId": _hex(deed_coin_id),
                    "p2VaultInnerPuzzleHash": _hex(p2_inner_ph),
                    "newP2VaultPuzzleHash": _hex(dest_ph),
                    "coin": {
                        "parentCoinInfo": _hex(DEED_PARENT_ID),
                        "puzzleHash": _hex(deed_full_ph),
                        "amount": 1,
                    },
                    "puzzleReveal": _hex(bytes(deed_spend.puzzle_reveal)),
                    "solution": _hex(bytes(deed_spend.solution)),
                },
            },
        ],
    }


def _services_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "populis_portal" / "src" / "app" / "services"


def fixture_destination() -> Path:
    return _services_dir() / "vault-migrate.fixtures.json"


def puzzle_hex_destination() -> Path:
    return _services_dir() / "p2-vault-current.puzzle-hex.ts"


def build_puzzle_hex_module() -> str:
    hex_str = "0x" + bytes(P2_VAULT_MOD).hex()
    mod_hash = _hex(P2_VAULT_MOD.get_tree_hash())
    return (
        "/**\n"
        " * Serialized ``p2_vault.clsp`` module (the puzzle that holds deed NFTs\n"
        " * for a vault).  Curried with (SINGLETON_MOD_HASH, vault_launcher_id,\n"
        " * SINGLETON_LAUNCHER_HASH) it becomes a deed's inner puzzle bound to a\n"
        " * given vault.  Used by the one-click upgrade's deed-migrate co-spend.\n"
        " *\n"
        " * GENERATED by ``populis_protocol/scripts/dump_vault_migrate_fixtures.py``\n"
        " * and pinned cross-repo by ``tests/test_vault_migrate_fixtures.py``.\n"
        " * DO NOT edit by hand.\n"
        " *\n"
        f" * tree hash: {mod_hash}\n"
        " */\n"
        f"export const P2_VAULT_CURRENT_PUZZLE_HEX =\n  '{hex_str}';\n"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    hex_dest = puzzle_hex_destination()
    hex_dest.write_text(build_puzzle_hex_module())
    print(f"wrote fixture to {dest}")
    print(f"wrote p2_vault hex module to {hex_dest}")
    print(
        f"  p2_vault_mod_hash={fixture['constants']['p2_vault_mod_hash']}, "
        f"spend_migrate={fixture['constants']['spend_migrate']}, "
        f"{len(fixture['migrate_signing_tree'])} signing-tree cases, "
        f"{len(fixture['new_p2_vault_puzzle_hash'])} p2-vault-ph cases, "
        f"{len(fixture['vault_migrate_spend'])} vault-spend cases, "
        f"{len(fixture['deed_migrate_spend'])} deed-spend cases"
    )


if __name__ == "__main__":
    main()
