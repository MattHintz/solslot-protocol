"""Generate the fixture for the portal's TS SGT VOTE spend builder (Phase 3b).

The TS service ``sgt-vote-spend-builder.service.ts`` reproduces the canonical
SGT lock + tracker VOTE CoinSpend builders from ``solslot_puzzles.sgt_driver``
so the portal can assemble a signed VOTE bundle entirely client-side and POST
it to the Solslot API ``/admin/committee/vote`` endpoint.

This script writes:

  * ``fixtures/sgt-driver/sgt-vote-spend.fixtures.json``
    A single canonical fixture (deterministic inputs + expected outputs) that
    the TS Karma test reads to assert byte-equality.

  * ``fixtures/sgt-driver/cat-mod.puzzle-hex.ts``
    The CAT2 (CAT v2) outer mod bytecode, bundled into the portal so the TS
    builder can curry it without round-tripping through the WASM SDK's bundled
    Constants (which we want to pin explicitly anyway).

The fixture is re-checked on every PR by ``tests/test_sgt_vote_spend_fixtures.py``.

Usage::

    cd solslot-protocol
    .venv/bin/python scripts/dump_sgt_vote_spend_fixtures.py
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

from solslot_puzzles.sgt_driver import (
    TEST_KOS_MINT_EXECUTE_PUBKEY,
    bill_mint,
    build_sgt_lock_coin_spend,
    build_tracker_vote_coin_spend,
    cat_sgt_free_puzzle_hash,
    sgt_free_inner_mod,
    sgt_locked_inner_hash,
    sgt_locked_inner_mod,
    sgt_tail_hash,
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

# Real SGT TAIL with deterministic genesis coin id.
SGT_TAIL_GENESIS_COIN_ID = bytes32(b"\xa0" * 32)
SGT_TAIL_HASH = sgt_tail_hash(SGT_TAIL_GENESIS_COIN_ID)

SGT_FREE_MOD_HASH = bytes32(sgt_free_inner_mod().get_tree_hash())
SGT_LOCKED_MOD_HASH = bytes32(sgt_locked_inner_mod().get_tree_hash())

QUORUM_BPS = 5000
VOTING_WINDOW = 300
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000

# Identity inner puzzle (Program.to(1)).  Solution-IS-conditions, so the
# voter's inner solution is literally the conditions list sgt_free_inner
# will read.  Test/fixture only — real wallets use p2_delegated.
IDENTITY_INNER = Program.to(1)
IDENTITY_HASH = bytes32(IDENTITY_INNER.get_tree_hash())

BILL = bill_mint(
    bytes32(b"\x33" * 32),
    bytes32(b"\x71" * 32),
    bytes32(b"\x72" * 32),
)
PROPOSAL_HASH = proposal_hash_from_bill(BILL)
DEADLINE = 2_000_000_000
VOTE_AMOUNT = 250_000

# SGT lock coin: deterministic parent + canonical CAT-wrapped puzhash.
SGT_PARENT_COIN_INFO = bytes32(b"\xfe" * 32)
SGT_PARENT_INNER_PH = bytes32(b"\xee" * 32)  # arbitrary; for the lineage proof
SGT_PARENT_AMOUNT = uint64(VOTE_AMOUNT)
SGT_LINEAGE_PROOF = LineageProof(
    parent_name=bytes32(b"\xdd" * 32),
    inner_puzzle_hash=SGT_PARENT_INNER_PH,
    amount=SGT_PARENT_AMOUNT,
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
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH_B32,
        SGT_TAIL_HASH,
        DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        SGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        TEST_KOS_MINT_EXECUTE_PUBKEY,
        proposal_hash=PROPOSAL_HASH,
        bill_operation=BILL,
        vote_tally=TRACKER_INITIAL_TALLY,
        voting_deadline=DEADLINE,
    )


def build_fixture() -> dict[str, Any]:
    # ── SGT lock spend ──
    sgt_ph = cat_sgt_free_puzzle_hash(
        TRACKER_STRUCT,
        SGT_FREE_MOD_HASH,
        SGT_LOCKED_MOD_HASH,
        CAT_MOD_HASH_B32,
        SGT_TAIL_HASH,
        IDENTITY_HASH,
    )
    sgt_coin = Coin(SGT_PARENT_COIN_INFO, sgt_ph, uint64(VOTE_AMOUNT))
    locked_ph = sgt_locked_inner_hash(
        SGT_FREE_MOD_HASH,
        TRACKER_STRUCT,
        IDENTITY_HASH,
        PROPOSAL_HASH,
        DEADLINE,
    )
    voter_solution = Program.to([[51, locked_ph, VOTE_AMOUNT]])  # 51 = CREATE_COIN
    sgt_lock_spend = build_sgt_lock_coin_spend(
        sgt_coin=sgt_coin,
        voter_inner_puzzle=IDENTITY_INNER,
        voter_inner_solution=voter_solution,
        proposal_tracker_struct=TRACKER_STRUCT,
        sgt_tail_hash=SGT_TAIL_HASH,
        lineage_proof=SGT_LINEAGE_PROOF,
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
            "sgt_free_inner_mod_hash": _hex(SGT_FREE_MOD_HASH),
            "sgt_locked_inner_mod_hash": _hex(SGT_LOCKED_MOD_HASH),
            "sgt_tail_hash": _hex(SGT_TAIL_HASH),
            "tracker_struct_hash": _hex(TRACKER_STRUCT.get_tree_hash()),
            "tracker_launcher_id": _hex(TRACKER_LAUNCHER_ID),
            "pool_struct_hash": _hex(POOL_STRUCT.get_tree_hash()),
            "did_puzhash": _hex(DID_PUZHASH),
            "quorum_bps": QUORUM_BPS,
            "voting_window_seconds": VOTING_WINDOW,
            "sgt_total_supply": SGT_TOTAL_SUPPLY,
            "min_proposal_stake": MIN_PROPOSAL_STAKE,
            "identity_inner_hash": _hex(IDENTITY_HASH),
        },
        "sgt_lock": {
            "inputs": {
                "sgt_coin": _coin_dict(sgt_coin),
                "voter_inner_puzzle_hex": _hex(bytes(IDENTITY_INNER)),
                "voter_inner_solution_hex": _hex(bytes(voter_solution)),
                "lineage_proof": {
                    "parent_name": _hex(
                        SGT_LINEAGE_PROOF.parent_name
                    )
                    if SGT_LINEAGE_PROOF.parent_name
                    else None,
                    "inner_puzzle_hash": _hex(
                        SGT_LINEAGE_PROOF.inner_puzzle_hash
                    )
                    if SGT_LINEAGE_PROOF.inner_puzzle_hash
                    else None,
                    "amount": int(SGT_LINEAGE_PROOF.amount)
                    if SGT_LINEAGE_PROOF.amount is not None
                    else None,
                },
                "proposal_hash": _hex(PROPOSAL_HASH),
                "deadline_seconds": DEADLINE,
                "expected_locked_puzhash": _hex(locked_ph),
            },
            "expected": {
                "coin": _coin_dict(sgt_lock_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(sgt_lock_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(sgt_lock_spend.solution)),
                "coin_spend_hex": _hex(bytes(sgt_lock_spend)),
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
    protocol_root = Path(__file__).resolve().parents[1]
    return protocol_root / "fixtures" / "sgt-driver"


def fixture_destination() -> Path:
    return _services_dir() / "sgt-vote-spend.fixtures.json"


def cat_mod_hex_destination() -> Path:
    return _services_dir() / "cat-mod.puzzle-hex.ts"


def build_cat_mod_hex_module() -> str:
    hex_str = "0x" + bytes(CAT_MOD).hex()
    return (
        "/**\n"
        " * Serialized CAT v2 outer puzzle (``chia_puzzles_py.programs.CAT_PUZZLE``).\n"
        " * Used by the portal's SGT VOTE spend builder to construct the CAT2\n"
        " * outer of the on-chain SGT free coin.\n"
        " *\n"
        " * GENERATED by ``solslot-protocol/scripts/dump_sgt_vote_spend_fixtures.py``\n"
        " * and pinned cross-repo by ``tests/test_sgt_vote_spend_fixtures.py``.\n"
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
        f"  sgt_lock.coin.puzzle_hash={fixture['sgt_lock']['expected']['coin']['puzzleHash']}\n"
        f"  sgt_lock.coin_spend_hex length={len(fixture['sgt_lock']['expected']['coin_spend_hex'])}\n"
        f"  tracker_vote.coin.puzzle_hash={fixture['tracker_vote']['expected']['coin']['puzzleHash']}"
    )


if __name__ == "__main__":
    main()
