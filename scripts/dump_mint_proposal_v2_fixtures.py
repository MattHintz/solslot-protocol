"""Generate the cross-repo fixture for the TS port of mint_proposal_v2.

Mirrors ``scripts/dump_v2_fixtures.py`` (admin authority v2) but for
the MIPS-pluggable mint-proposal puzzle introduced in Phase 9-Hermes-D.
The fixture is consumed by the portal's Karma test
(``mint-proposal-v2.service.spec.ts``) which asserts the TS port
produces byte-identical hashes for the same inputs.

Usage::

    cd solslot-protocol
    .venv/bin/python scripts/dump_mint_proposal_v2_fixtures.py

The fixture is also exported by the regression test in
``tests/test_mint_proposal_v2_fixtures.py`` so CI re-checks it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.mint_proposal_v2_driver import (
    STATE_APPROVED,
    STATE_CANCELLED,
    STATE_DRAFT,
    TRANSITION_APPROVE,
    TRANSITION_CANCEL,
    compute_binding_hash,
    compute_proposal_data_hash,
    compute_transition_message,
    make_inner_puzzle_hash,
    mint_proposal_inner_v2_mod_hash,
)


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def build_fixture() -> dict[str, Any]:
    """Compute every fixture case using the production Python helpers.

    Coverage:
      * ``mod_hash`` \u2014 pinned uncurried tree hash of the V2 puzzle.
      * ``proposal_data_hash`` \u2014 sha256tree of (property_id,
        collection_id, share_ppm, par, royalty_bps, quorum_threshold).
        Three cases varying the proposal terms.
      * ``binding_hash`` \u2014 sha256tree of (transition_case,
        new_state_version, proposal_data_hash).  Cases for each
        transition / version combination.
      * ``transition_message`` \u2014 sha256tree of (transition_case,
        new_state, new_state_version). Canonical for Solslot V2.
      * ``inner_puzzle_hash`` \u2014 tree hash of the curried inner.
        Cases vary each curry slot to catch a TS port getting the
        order wrong.

    The TS port reads this fixture and asserts byte-identical output;
    any drift means the curry order / hash construction diverged
    between Python and TS, and the test fails loudly.
    """
    # Sample admins/proposals \u2014 picked to be visually distinct so a
    # cross-curve TS bug is obvious.
    OWNER_HASH = bytes32(b"\xAA" * 32)
    GOV_HASH = bytes32(b"\xBB" * 32)
    GOVERNANCE_STRUCT = Program.to(
        (
            SINGLETON_MOD_HASH,
            (bytes32(b"\xBC" * 32), SINGLETON_LAUNCHER_HASH),
        )
    )
    GOVERNANCE_PROPOSAL_HASH = bytes32(b"\xBD" * 32)
    DEED_LAUNCHER_ID = bytes32(b"\xBE" * 32)
    DID_INNER_PUZZLE_HASH = bytes32(b"\xBF" * 32)
    DEED_FULL_PUZZLE_HASH = bytes32(b"\xC0" * 32)
    immutable_input = {
        "governance_singleton_struct_hex": _hex(bytes(GOVERNANCE_STRUCT)),
        "governance_proposal_hash": _hex(GOVERNANCE_PROPOSAL_HASH),
        "deed_launcher_id": _hex(DEED_LAUNCHER_ID),
        "did_inner_puzzle_hash": _hex(DID_INNER_PUZZLE_HASH),
        "deed_full_puzzle_hash": _hex(DEED_FULL_PUZZLE_HASH),
    }
    immutable_args = {
        "governance_singleton_struct": GOVERNANCE_STRUCT,
        "governance_proposal_hash": GOVERNANCE_PROPOSAL_HASH,
        "deed_launcher_id": DEED_LAUNCHER_ID,
        "did_inner_puzzle_hash": DID_INNER_PUZZLE_HASH,
        "deed_full_puzzle_hash": DEED_FULL_PUZZLE_HASH,
    }
    COLLECTION_A = bytes32(b"\x12" * 32)
    COLLECTION_B = bytes32(b"\x23" * 32)
    PROP_HASH_A = compute_proposal_data_hash(
        property_id_canon=bytes32(b"\x11" * 32),
        collection_id_canon=COLLECTION_A,
        share_ppm=750_000,
        par_value_mojos=100_000,
        royalty_bps=250,
        quorum_threshold=1_000_000,
    )
    PROP_HASH_B = compute_proposal_data_hash(
        property_id_canon=bytes32(b"\x22" * 32),
        collection_id_canon=COLLECTION_B,
        share_ppm=500_000,
        par_value_mojos=500_000,
        royalty_bps=500,
        quorum_threshold=2_000_000,
    )

    return {
        "constants": {
            "mod_hash": _hex(mint_proposal_inner_v2_mod_hash()),
            "state_draft": STATE_DRAFT,
            "state_approved": STATE_APPROVED,
            "state_cancelled": STATE_CANCELLED,
            "transition_approve": TRANSITION_APPROVE,
            "transition_cancel": TRANSITION_CANCEL,
        },
        "proposal_data_hash": [
            {
                "input": {
                    "property_id_canon": _hex(bytes32(b"\x11" * 32)),
                    "collection_id_canon": _hex(COLLECTION_A),
                    "share_ppm": 750_000,
                    "par_value_mojos": 100_000,
                    "royalty_bps": 250,
                    "quorum_threshold": 1_000_000,
                },
                "expected": _hex(PROP_HASH_A),
            },
            {
                "input": {
                    "property_id_canon": _hex(bytes32(b"\x22" * 32)),
                    "collection_id_canon": _hex(COLLECTION_B),
                    "share_ppm": 500_000,
                    "par_value_mojos": 500_000,
                    "royalty_bps": 500,
                    "quorum_threshold": 2_000_000,
                },
                "expected": _hex(PROP_HASH_B),
            },
            {
                "input": {
                    "property_id_canon": _hex(bytes32(b"\x33" * 32)),
                    "collection_id_canon": _hex(bytes32(b"\x34" * 32)),
                    "share_ppm": 1,
                    "par_value_mojos": 1,
                    "royalty_bps": 0,
                    "quorum_threshold": 0,
                },
                "expected": _hex(
                    compute_proposal_data_hash(
                        property_id_canon=bytes32(b"\x33" * 32),
                        collection_id_canon=bytes32(b"\x34" * 32),
                        share_ppm=1,
                        par_value_mojos=1,
                        royalty_bps=0,
                        quorum_threshold=0,
                    )
                ),
            },
        ],
        "binding_hash": [
            {
                "input": {
                    "transition_case": TRANSITION_APPROVE,
                    "new_state_version": 1,
                    "proposal_data_hash": _hex(PROP_HASH_A),
                },
                "expected": _hex(
                    compute_binding_hash(
                        transition_case=TRANSITION_APPROVE,
                        new_state_version=1,
                        proposal_data_hash=PROP_HASH_A,
                    )
                ),
            },
            {
                "input": {
                    "transition_case": TRANSITION_CANCEL,
                    "new_state_version": 1,
                    "proposal_data_hash": _hex(PROP_HASH_A),
                },
                "expected": _hex(
                    compute_binding_hash(
                        transition_case=TRANSITION_CANCEL,
                        new_state_version=1,
                        proposal_data_hash=PROP_HASH_A,
                    )
                ),
            },
            {
                "input": {
                    "transition_case": TRANSITION_APPROVE,
                    "new_state_version": 2,
                    "proposal_data_hash": _hex(PROP_HASH_A),
                },
                "expected": _hex(
                    compute_binding_hash(
                        transition_case=TRANSITION_APPROVE,
                        new_state_version=2,
                        proposal_data_hash=PROP_HASH_A,
                    )
                ),
            },
            {
                "input": {
                    "transition_case": TRANSITION_APPROVE,
                    "new_state_version": 1,
                    "proposal_data_hash": _hex(PROP_HASH_B),
                },
                "expected": _hex(
                    compute_binding_hash(
                        transition_case=TRANSITION_APPROVE,
                        new_state_version=1,
                        proposal_data_hash=PROP_HASH_B,
                    )
                ),
            },
        ],
        "transition_message": [
            {
                "input": {
                    "transition_case": TRANSITION_APPROVE,
                    "new_state": STATE_APPROVED,
                    "new_state_version": 1,
                },
                "expected": _hex(
                    compute_transition_message(
                        transition_case=TRANSITION_APPROVE,
                        new_state=STATE_APPROVED,
                        new_state_version=1,
                    )
                ),
            },
            {
                "input": {
                    "transition_case": TRANSITION_CANCEL,
                    "new_state": STATE_CANCELLED,
                    "new_state_version": 1,
                },
                "expected": _hex(
                    compute_transition_message(
                        transition_case=TRANSITION_CANCEL,
                        new_state=STATE_CANCELLED,
                        new_state_version=1,
                    )
                ),
            },
        ],
        "inner_puzzle_hash": [
            {
                "input": {
                    "owner_member_hash": _hex(OWNER_HASH),
                    "gov_member_hash": _hex(GOV_HASH),
                    "proposal_data_hash": _hex(PROP_HASH_A),
                    **immutable_input,
                    "proposal_state": STATE_DRAFT,
                    "state_version": 0,
                },
                "expected": _hex(
                    make_inner_puzzle_hash(
                        owner_member_hash=OWNER_HASH,
                        gov_member_hash=GOV_HASH,
                        proposal_data_hash=PROP_HASH_A,
                        **immutable_args,
                        proposal_state=STATE_DRAFT,
                        state_version=0,
                    )
                ),
            },
            {
                "input": {
                    "owner_member_hash": _hex(OWNER_HASH),
                    "gov_member_hash": _hex(GOV_HASH),
                    "proposal_data_hash": _hex(PROP_HASH_A),
                    **immutable_input,
                    "proposal_state": STATE_APPROVED,
                    "state_version": 1,
                },
                "expected": _hex(
                    make_inner_puzzle_hash(
                        owner_member_hash=OWNER_HASH,
                        gov_member_hash=GOV_HASH,
                        proposal_data_hash=PROP_HASH_A,
                        **immutable_args,
                        proposal_state=STATE_APPROVED,
                        state_version=1,
                    )
                ),
            },
            {
                "input": {
                    "owner_member_hash": _hex(OWNER_HASH),
                    "gov_member_hash": _hex(GOV_HASH),
                    "proposal_data_hash": _hex(PROP_HASH_A),
                    **immutable_input,
                    "proposal_state": STATE_CANCELLED,
                    "state_version": 1,
                },
                "expected": _hex(
                    make_inner_puzzle_hash(
                        owner_member_hash=OWNER_HASH,
                        gov_member_hash=GOV_HASH,
                        proposal_data_hash=PROP_HASH_A,
                        **immutable_args,
                        proposal_state=STATE_CANCELLED,
                        state_version=1,
                    )
                ),
            },
            {
                # Different proposal data \u2192 different inner hash even
                # at the same state.  Catches "did the TS port forget
                # to include proposal_data_hash in the curry?".
                "input": {
                    "owner_member_hash": _hex(OWNER_HASH),
                    "gov_member_hash": _hex(GOV_HASH),
                    "proposal_data_hash": _hex(PROP_HASH_B),
                    **immutable_input,
                    "proposal_state": STATE_DRAFT,
                    "state_version": 0,
                },
                "expected": _hex(
                    make_inner_puzzle_hash(
                        owner_member_hash=OWNER_HASH,
                        gov_member_hash=GOV_HASH,
                        proposal_data_hash=PROP_HASH_B,
                        **immutable_args,
                        proposal_state=STATE_DRAFT,
                        state_version=0,
                    )
                ),
            },
        ],
    }


def fixture_destination() -> Path:
    """Resolve the canonical destination inside the portal repo."""
    protocol_root = Path(__file__).resolve().parents[1]
    portal_root = Path(
        os.environ.get("SOLSLOT_PORTAL_ROOT", protocol_root.parent / "solslot-portal")
    )
    return (
        portal_root
        / "src"
        / "app"
        / "services"
        / "mint-proposal-v2"
        / "mint-proposal-v2.fixtures.json"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    print(f"wrote fixture to {dest}")
    print(f"  mod_hash={fixture['constants']['mod_hash']}")
    print(
        f"  cases: proposal_data_hash={len(fixture['proposal_data_hash'])}, "
        f"binding_hash={len(fixture['binding_hash'])}, "
        f"transition_message={len(fixture['transition_message'])}, "
        f"inner_puzzle_hash={len(fixture['inner_puzzle_hash'])}"
    )


if __name__ == "__main__":
    main()
