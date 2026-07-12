"""Generate the fixture for the portal's TS PGT VOTE spend builder (Phase 3b).

The TS service ``pgt-vote-spend-builder.service.ts`` reproduces the canonical
PGT lock + tracker VOTE CoinSpend builders from ``solslot_puzzles.pgt_driver``
so the portal can assemble a signed VOTE bundle entirely client-side and POST
it to the populis_api ``/admin/committee/vote`` endpoint.

This script writes:

  * ``populis_portal/src/app/services/pgt-driver/pgt-vote-spend.fixtures.json``
    A single canonical fixture (deterministic inputs + expected outputs) that
    the TS Karma test reads to assert byte-equality.

  * ``populis_portal/src/app/services/pgt-driver/cat-mod.puzzle-hex.ts``
    The CAT2 (CAT v2) outer mod bytecode, bundled into the portal so the TS
    builder can curry it without round-tripping through the WASM SDK's bundled
    Constants (which we want to pin explicitly anyway).

The fixture is re-checked on every PR by ``tests/test_pgt_vote_spend_fixtures.py``.

Usage::

    cd populis_protocol
    .venv/bin/python scripts/dump_pgt_vote_spend_fixtures.py
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.wallet.cat_wallet.cat_utils import CAT_MOD, CAT_MOD_HASH
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    puzzle_for_singleton,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.pgt_driver import (
    bill_mint,
    build_pgt_lock_coin_spend,
    build_tracker_vote_coin_spend,
    cat_pgt_free_puzzle_hash,
    pgt_free_inner_mod,
    pgt_locked_inner_hash,
    pgt_locked_inner_mod,
    pgt_tail_hash,
    proposal_hash_from_bill,
    proposal_tracker_inner_puzzle,
)


# ─── Helpers ────────────────────────────────────────────────────────────────
def _hex(b: bytes | bytes32) -> str:
    return "0x" + bytes(b).hex()


def _coin_dict(coin: Coin) -> dict[str, Any]:
    return {
        "parentCoinInfo": _hex(coin.parent_coin_info),
        "puzzleHash": _hex(coin.puzzle_hash),
        "amount": int(coin.amount),
    }


# ─── Deterministic fixture inputs ───────────────────────────────────────────
# Distinct sentinels so a TS port that swaps two args produces different output.
TRACKER_LAUNCHER_ID = bytes32(b"\xb0" * 32)
TRACKER_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (TRACKER_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
POOL_LAUNCHER_ID = bytes32(b"\xc0" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
DID_PUZHASH = bytes32(b"\xd0" * 32)

# Real CAT_MOD_HASH (chia-bundled CAT v2 mod hash).
CAT_MOD_HASH_B32 = bytes32(CAT_MOD_HASH)

# Real PGT TAIL with deterministic genesis coin id.
PGT_TAIL_GENESIS_COIN_ID = bytes32(b"\xa0" * 32)
PGT_TAIL_HASH = pgt_tail_hash(PGT_TAIL_GENESIS_COIN_ID)

PGT_FREE_MOD_HASH = bytes32(pgt_free_inner_mod().get_tree_hash())
PGT_LOCKED_MOD_HASH = bytes32(pgt_locked_inner_mod().get_tree_hash())

QUORUM_BPS = 5000
VOTING_WINDOW = 300
PGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000

# Identity inner puzzle (Program.to(1)).  Solution-IS-conditions, so the
# voter's inner solution is literally the conditions list pgt_free_inner
# will read.  Test/fixture only — real wallets use p2_delegated.
IDENTITY_INNER = Program.to(1)
IDENTITY_HASH = bytes32(IDENTITY_INNER.get_tree_hash())

BILL = bill_mint(bytes32(b"\x33" * 32))
PROPOSAL_HASH = proposal_hash_from_bill(BILL)
DEADLINE = 2_000_000_000
VOTE_AMOUNT = 250_000

# PGT lock coin: deterministic parent + canonical CAT-wrapped puzhash.
PGT_PARENT_COIN_INFO = bytes32(b"\xfe" * 32)
PGT_PARENT_INNER_PH = bytes32(b"\xee" * 32)  # arbitrary; for the lineage proof
PGT_PARENT_AMOUNT = uint64(VOTE_AMOUNT)
PGT_LINEAGE_PROOF = LineageProof(
    parent_name=bytes32(b"\xdd" * 32),
    inner_puzzle_hash=PGT_PARENT_INNER_PH,
    amount=PGT_PARENT_AMOUNT,
)

# Tracker singleton coin (OPEN state with initial tally).
TRACKER_INITIAL_TALLY = 200_000
TRACKER_LINEAGE_PROOF = LineageProof(
    parent_name=bytes32(b"\xaa" * 32),
    inner_puzzle_hash=bytes32(b"\xbb" * 32),
    amount=uint64(1),
)


def _open_tracker_inner() -> Program:
    return proposal_tracker_inner_puzzle(
        TRACKER_STRUCT,
        PGT_FREE_MOD_HASH,
        PGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH_B32,
        PGT_TAIL_HASH,
        DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        PGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        proposal_hash=PROPOSAL_HASH,
        bill_operation=BILL,
        vote_tally=TRACKER_INITIAL_TALLY,
        voting_deadline=DEADLINE,
    )


def build_fixture() -> dict[str, Any]:
    # ── PGT lock spend ──
    pgt_ph = cat_pgt_free_puzzle_hash(
        TRACKER_STRUCT,
        PGT_FREE_MOD_HASH,
        PGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH_B32,
        PGT_TAIL_HASH,
        IDENTITY_HASH,
    )
    pgt_coin = Coin(PGT_PARENT_COIN_INFO, pgt_ph, uint64(VOTE_AMOUNT))
    locked_ph = pgt_locked_inner_hash(
        PGT_FREE_MOD_HASH,
        TRACKER_STRUCT,
        IDENTITY_HASH,
        PROPOSAL_HASH,
        DEADLINE,
    )
    voter_solution = Program.to([[51, locked_ph, VOTE_AMOUNT]])  # 51 = CREATE_COIN
    pgt_lock_spend = build_pgt_lock_coin_spend(
        pgt_coin=pgt_coin,
        voter_inner_puzzle=IDENTITY_INNER,
        voter_inner_solution=voter_solution,
        proposal_tracker_struct=TRACKER_STRUCT,
        pgt_tail_hash=PGT_TAIL_HASH,
        lineage_proof=PGT_LINEAGE_PROOF,
        proposal_hash=PROPOSAL_HASH,
        deadline=DEADLINE,
    )

    # ── Tracker VOTE spend ──
    tracker_inner = _open_tracker_inner()
    tracker_full_ph = bytes32(
        puzzle_for_singleton(TRACKER_LAUNCHER_ID, tracker_inner).get_tree_hash()
    )
    tracker_coin = Coin(
        bytes32(b"\x11" * 32), tracker_full_ph, uint64(1)
    )
    tracker_vote_spend = build_tracker_vote_coin_spend(
        tracker_coin=tracker_coin,
        tracker_inner_puzzle=tracker_inner,
        tracker_launcher_id=TRACKER_LAUNCHER_ID,
        lineage_proof=TRACKER_LINEAGE_PROOF,
        voter_inner_puzzle_hash=IDENTITY_HASH,
        additional_vote_amount=VOTE_AMOUNT,
    )

    return {
        "constants": {
            "cat_mod_hash": _hex(CAT_MOD_HASH_B32),
            "singleton_mod_hash": _hex(SINGLETON_MOD_HASH),
            "singleton_launcher_hash": _hex(SINGLETON_LAUNCHER_HASH),
            "pgt_free_inner_mod_hash": _hex(PGT_FREE_MOD_HASH),
            "pgt_locked_inner_mod_hash": _hex(PGT_LOCKED_MOD_HASH),
            "pgt_tail_hash": _hex(PGT_TAIL_HASH),
            "tracker_struct_hash": _hex(TRACKER_STRUCT.get_tree_hash()),
            "tracker_launcher_id": _hex(TRACKER_LAUNCHER_ID),
            "pool_struct_hash": _hex(POOL_STRUCT.get_tree_hash()),
            "did_puzhash": _hex(DID_PUZHASH),
            "quorum_bps": QUORUM_BPS,
            "voting_window_seconds": VOTING_WINDOW,
            "pgt_total_supply": PGT_TOTAL_SUPPLY,
            "min_proposal_stake": MIN_PROPOSAL_STAKE,
            "identity_inner_hash": _hex(IDENTITY_HASH),
        },
        "pgt_lock": {
            "inputs": {
                "pgt_coin": _coin_dict(pgt_coin),
                "voter_inner_puzzle_hex": _hex(bytes(IDENTITY_INNER)),
                "voter_inner_solution_hex": _hex(bytes(voter_solution)),
                "lineage_proof": {
                    "parent_name": _hex(
                        PGT_LINEAGE_PROOF.parent_name
                    )
                    if PGT_LINEAGE_PROOF.parent_name
                    else None,
                    "inner_puzzle_hash": _hex(
                        PGT_LINEAGE_PROOF.inner_puzzle_hash
                    )
                    if PGT_LINEAGE_PROOF.inner_puzzle_hash
                    else None,
                    "amount": int(PGT_LINEAGE_PROOF.amount)
                    if PGT_LINEAGE_PROOF.amount is not None
                    else None,
                },
                "proposal_hash": _hex(PROPOSAL_HASH),
                "deadline_seconds": DEADLINE,
                "expected_locked_puzhash": _hex(locked_ph),
            },
            "expected": {
                "coin": _coin_dict(pgt_lock_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(pgt_lock_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(pgt_lock_spend.solution)),
                "coin_spend_hex": _hex(bytes(pgt_lock_spend)),
            },
        },
        "tracker_vote": {
            "inputs": {
                "tracker_coin": _coin_dict(tracker_coin),
                "tracker_inner_puzzle_hex": _hex(bytes(tracker_inner)),
                "tracker_launcher_id": _hex(TRACKER_LAUNCHER_ID),
                "lineage_proof": {
                    "parent_name": _hex(
                        TRACKER_LINEAGE_PROOF.parent_name
                    ),
                    "inner_puzzle_hash": _hex(
                        TRACKER_LINEAGE_PROOF.inner_puzzle_hash
                    ),
                    "amount": int(TRACKER_LINEAGE_PROOF.amount),
                },
                "voter_inner_puzzle_hash": _hex(IDENTITY_HASH),
                "additional_vote_amount": VOTE_AMOUNT,
                "initial_vote_tally": TRACKER_INITIAL_TALLY,
                "proposal_hash": _hex(PROPOSAL_HASH),
                "deadline_seconds": DEADLINE,
            },
            "expected": {
                "coin": _coin_dict(tracker_vote_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(tracker_vote_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(tracker_vote_spend.solution)),
                "coin_spend_hex": _hex(bytes(tracker_vote_spend)),
            },
        },
    }


def _services_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "populis_portal" / "src" / "app" / "services" / "pgt-driver"


def fixture_destination() -> Path:
    return _services_dir() / "pgt-vote-spend.fixtures.json"


def cat_mod_hex_destination() -> Path:
    return _services_dir() / "cat-mod.puzzle-hex.ts"


def build_cat_mod_hex_module() -> str:
    hex_str = "0x" + bytes(CAT_MOD).hex()
    return (
        "/**\n"
        " * Serialized CAT v2 outer puzzle (``chia_puzzles_py.programs.CAT_PUZZLE``).\n"
        " * Used by the portal's PGT VOTE spend builder to construct the CAT2\n"
        " * outer of the on-chain PGT free coin.\n"
        " *\n"
        " * GENERATED by ``populis_protocol/scripts/dump_pgt_vote_spend_fixtures.py``\n"
        " * and pinned cross-repo by ``tests/test_pgt_vote_spend_fixtures.py``.\n"
        " * DO NOT edit by hand.\n"
        " *\n"
        f" * tree hash: 0x{bytes(CAT_MOD_HASH).hex()}\n"
        " */\n"
        f"export const CAT_MOD_PUZZLE_HEX =\n  '{hex_str}';\n"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    cat_hex_dest = cat_mod_hex_destination()
    cat_hex_dest.write_text(build_cat_mod_hex_module())
    print(f"wrote fixture to {dest}")
    print(f"wrote cat-mod hex module to {cat_hex_dest}")
    print(
        f"  pgt_lock.coin.puzzle_hash={fixture['pgt_lock']['expected']['coin']['puzzleHash']}\n"
        f"  pgt_lock.coin_spend_hex length={len(fixture['pgt_lock']['expected']['coin_spend_hex'])}\n"
        f"  tracker_vote.coin.puzzle_hash={fixture['tracker_vote']['expected']['coin']['puzzleHash']}"
    )


if __name__ == "__main__":
    main()
