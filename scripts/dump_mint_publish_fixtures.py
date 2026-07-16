"""Generate the fixture for the portal's TS mint-publish driver (Phase 4b).

The TS service ``mint-proposal-v2.service.ts`` (sub-brick 4c) reproduces the
canonical mint-publish hash computation from
:mod:`solslot_puzzles.mint_publish_driver` so the portal can pin all four
``computed.*_puzhash`` values client-side and surface them to the admin
desk *before* the publish bundle is signed.

This script writes:

  * ``fixtures/mint-proposal-v2/mint-publish.fixtures.json``
    A single canonical fixture (deterministic inputs + expected outputs) that
    the TS Karma test reads to assert byte-equality.

The fixture is re-checked on every PR by
:mod:`tests.test_mint_publish_fixtures` (this file's currency guard).

Unlike the Phase 3 SGT VOTE fixture, mint-publish does not bundle any
puzzle-hex file: every puzzle the portal needs to re-curry
(``smart_deed_inner``, ``mint_offer_delegate``,
``singleton_launcher_with_did``, ``mint_proposal_inner_v2``) is already
part of the protocol puzzle bundle the portal loads via existing helpers.

Usage::

    cd solslot-protocol
    .venv/bin/python scripts/dump_mint_publish_fixtures.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.wallet.cat_wallet.cat_utils import CAT_MOD
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles.mint_proposal_v2_driver import (
    STATE_DRAFT,
    build_execute_coin_spend as build_proposal_execute_coin_spend,
    compute_proposal_data_hash,
    make_inner_puzzle,
)
from solslot_puzzles import load_puzzle
from solslot_puzzles.mint_publish_driver import (
    BILL_MINT_TAG,
    SINGLETON_AMOUNT,
    build_mint_publish_artifacts,
    build_sgt_first_vote_coin_spend,
    build_proposal_eve_launch_spend,
    build_tracker_propose_coin_spend,
    canonical_p2_pool_mod_hash,
)
from solslot_puzzles.sgt_driver import (
    cat_sgt_free_puzzle_hash,
    sgt_free_inner_mod,
    sgt_locked_inner_hash,
    sgt_locked_inner_mod,
    proposal_tracker_inner_puzzle,
)
from solslot_puzzles.property_registry_driver import (
    build_registration_coin_spend,
    make_inner_puzzle as make_property_registry_inner_puzzle,
    registered_ids_root,
)
from solslot_puzzles.protocol_deployment import (
    build_quorum_did_mint_coin_spend,
    quorum_did_inner_puzzle,
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


def _lineage_proof_dict(lp: LineageProof) -> dict[str, Any]:
    return {
        "parent_name": _hex(lp.parent_name) if lp.parent_name else None,
        "inner_puzzle_hash": _hex(lp.inner_puzzle_hash)
        if lp.inner_puzzle_hash
        else None,
        "amount": int(lp.amount) if lp.amount is not None else None,
    }


# ─── Deterministic fixture inputs ───────────────────────────────────────────
# Distinct sentinels so a TS port that swaps two args produces different output.
PROPERTY_ID = bytes32(b"\xa1" * 32)
COLLECTION_ID = bytes32(b"\xa8" * 32)
ROYALTY_PUZHASH = bytes32(b"\xa2" * 32)
PROTOCOL_DID_PUZHASH = bytes32(b"\xa3" * 32)
PROTOCOL_DID_INNER_PUZHASH = bytes32(b"\xa9" * 32)
P2_POOL_MOD_HASH = canonical_p2_pool_mod_hash()
P2_VAULT_MOD_HASH = bytes32(b"\xa5" * 32)
PROPERTY_REGISTRY_PUZZLE_HASH = bytes32(b"\xa7" * 32)
OWNER_MEMBER_HASH = bytes32(b"\xa6" * 32)
GOV_MEMBER_HASH = bytes32(b"\x00" * 32)  # placeholder zeros per Phase 4 alpha
DEED_LAUNCHER_PARENT = bytes32(b"\xb1" * 32)
PROPOSAL_LAUNCHER_PARENT = bytes32(b"\xb2" * 32)
DID_LAUNCHER_ID = bytes32(b"\xc2" * 32)
DID_COIN_PARENT = bytes32(b"\xc3" * 32)
DID_LINEAGE_PARENT = bytes32(b"\xc4" * 32)
DID_LINEAGE_INNER = bytes32(b"\xc5" * 32)

PROTOCOL_DID_LAUNCHER_ID = bytes32(b"\xc1" * 32)
PROTOCOL_DID_SINGLETON_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (PROTOCOL_DID_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)

PAR_VALUE = 250_000_000_000  # 250 XCH (mojos)
ASSET_CLASS = 1
SHARE_PPM = 750_000
JURISDICTION = b"US-CA"
ROYALTY_BPS = 250  # 2.5%
QUORUM_THRESHOLD = 5_000  # 50.00%

# ─── Spend-bundle synthetic inputs (4d.1) ──────────────────────────────────
# These pin the wallet-side inputs the publish runner would supply at runtime
# (XCH parent coin, current tracker singleton, proposer SGT free coin, etc).
# Deterministic sentinels so the TS port produces byte-equal CoinSpends.

# Wallet's XCH parent coin spent to spawn the Artifact A launcher.  Its
# coin id becomes the launcher coin's parent_coin_info.
XCH_PARENT_PARENT = bytes32(b"\xe0" * 32)
XCH_PARENT_PUZHASH = bytes32(b"\xe1" * 32)
XCH_PARENT_AMOUNT = 10**12  # 1 XCH

# Governance tracker singleton (currently idle).
TRACKER_LAUNCHER_ID = bytes32(b"\xb0" * 32)
TRACKER_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (TRACKER_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
TRACKER_PARENT_COIN_INFO = bytes32(b"\xb1" * 32)
TRACKER_LINEAGE_PARENT_NAME = bytes32(b"\xaa" * 32)
TRACKER_LINEAGE_INNER_PH = bytes32(b"\xbb" * 32)

# Governance curry params for the idle tracker.
GOV_DID_PUZHASH = bytes32(b"\xd0" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xc0" * 32)
POOL_STRUCT = Program.to(
    (SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))
)
QUORUM_BPS = 5_000
VOTING_WINDOW = 300
SGT_TOTAL_SUPPLY = 1_000_000
MIN_PROPOSAL_STAKE = 10_000
VOTING_DEADLINE = 2_000_000_000

# SGT first-vote coin (proposer's CAT2-wrapped SGT free coin).
SGT_TAIL_HASH = bytes32(b"\xea" * 32)
SGT_PARENT_COIN_INFO = bytes32(b"\xfe" * 32)
SGT_LINEAGE_PARENT_NAME = bytes32(b"\xdd" * 32)
SGT_LINEAGE_INNER_PH = bytes32(b"\xee" * 32)
FIRST_VOTE_AMOUNT = 10_000  # equals MIN_PROPOSAL_STAKE

# Property-registry registration co-spend.  The fixture uses a non-eve current
# registry coin so the singleton lineage proof is fully populated and replayable
# by the API's announcement scanner.
PROPERTY_REGISTRY_GOV_PUBKEY = bytes([0xF4]) * 48
PROPERTY_REGISTRY_LAUNCHER_ID = bytes32(b"\xf5" * 32)
PROPERTY_REGISTRY_PREV_PARENT = bytes32(b"\xf6" * 32)
PROPERTY_REGISTRY_PREV_INNER = Program.to([b"registry-prev"])
EXISTING_PROPERTY_ID = bytes32(b"\xf7" * 32)

# Identity-style voter inner puzzle (test/fixture only — real wallets use
# p2_delegated_puzzle_or_hidden_puzzle).
IDENTITY_INNER = Program.to(1)
IDENTITY_HASH = bytes32(IDENTITY_INNER.get_tree_hash())


def _idle_tracker_inner() -> Program:
    return proposal_tracker_inner_puzzle(
        TRACKER_STRUCT,
        bytes32(sgt_free_inner_mod().get_tree_hash()),
        bytes32(sgt_locked_inner_mod().get_tree_hash()),
        bytes32(CAT_MOD.get_tree_hash()),
        SGT_TAIL_HASH,
        GOV_DID_PUZHASH,
        POOL_STRUCT,
        QUORUM_BPS,
        VOTING_WINDOW,
        SGT_TOTAL_SUPPLY,
        MIN_PROPOSAL_STAKE,
        proposal_hash=0,
        bill_operation=0,
        vote_tally=0,
        voting_deadline=0,
    )


def build_fixture() -> dict[str, Any]:
    artifacts = build_mint_publish_artifacts(
        property_id_canon=PROPERTY_ID,
        collection_id_canon=COLLECTION_ID,
        share_ppm=SHARE_PPM,
        par_value_mojos=PAR_VALUE,
        asset_class=ASSET_CLASS,
        jurisdiction=JURISDICTION,
        royalty_puzhash=ROYALTY_PUZHASH,
        royalty_bps=ROYALTY_BPS,
        quorum_threshold=QUORUM_THRESHOLD,
        owner_member_hash=OWNER_MEMBER_HASH,
        gov_member_hash=GOV_MEMBER_HASH,
        deed_launcher_parent_coin_name=DEED_LAUNCHER_PARENT,
        proposal_launcher_parent_coin_name=PROPOSAL_LAUNCHER_PARENT,
        protocol_did_singleton_struct=PROTOCOL_DID_SINGLETON_STRUCT,
        protocol_did_puzhash=PROTOCOL_DID_PUZHASH,
        protocol_did_inner_puzhash=PROTOCOL_DID_INNER_PUZHASH,
        governance_singleton_struct=TRACKER_STRUCT,
        p2_pool_mod_hash=P2_POOL_MOD_HASH,
        p2_vault_mod_hash=P2_VAULT_MOD_HASH,
        property_registry_puzzle_hash=PROPERTY_REGISTRY_PUZZLE_HASH,
    )

    return {
        "constants": {
            "bill_mint_tag": BILL_MINT_TAG,
            "singleton_amount": SINGLETON_AMOUNT,
            "singleton_mod_hash": _hex(SINGLETON_MOD_HASH),
            "singleton_launcher_hash": _hex(SINGLETON_LAUNCHER_HASH),
            "protocol_did_singleton_struct_hex": _hex(
                bytes(PROTOCOL_DID_SINGLETON_STRUCT)
            ),
            "protocol_did_singleton_struct_hash": _hex(
                PROTOCOL_DID_SINGLETON_STRUCT.get_tree_hash()
            ),
            "protocol_did_launcher_id": _hex(PROTOCOL_DID_LAUNCHER_ID),
        },
        "inputs": {
            # Operator metadata.
            "property_id_canon": _hex(PROPERTY_ID),
            "collection_id_canon": _hex(COLLECTION_ID),
            "share_ppm": SHARE_PPM,
            "par_value_mojos": PAR_VALUE,
            "asset_class": ASSET_CLASS,
            "jurisdiction_hex": _hex(JURISDICTION),
            "royalty_puzhash": _hex(ROYALTY_PUZHASH),
            "royalty_bps": ROYALTY_BPS,
            "quorum_threshold": QUORUM_THRESHOLD,
            # Member auth.
            "owner_member_hash": _hex(OWNER_MEMBER_HASH),
            "gov_member_hash": _hex(GOV_MEMBER_HASH),
            # Parent coin ids picked by the wallet.
            "deed_launcher_parent_coin_name": _hex(DEED_LAUNCHER_PARENT),
            "proposal_launcher_parent_coin_name": _hex(
                PROPOSAL_LAUNCHER_PARENT
            ),
            # Protocol deployment context.
            "protocol_did_puzhash": _hex(PROTOCOL_DID_PUZHASH),
            "protocol_did_inner_puzhash": _hex(PROTOCOL_DID_INNER_PUZHASH),
            "governance_singleton_struct_hex": _hex(bytes(TRACKER_STRUCT)),
            "p2_pool_mod_hash": _hex(P2_POOL_MOD_HASH),
            "p2_vault_mod_hash": _hex(P2_VAULT_MOD_HASH),
            "property_registry_puzzle_hash": _hex(PROPERTY_REGISTRY_PUZZLE_HASH),
        },
        "expected": {
            # ── computed.*_puzhash row (admin desk data model) ──
            "smart_deed_inner_puzhash": _hex(artifacts.smart_deed_inner_puzhash),
            "eve_inner_puzhash": _hex(artifacts.eve_inner_puzhash),
            "deed_full_puzhash": _hex(artifacts.deed_full_puzhash),
            "proposal_hash": _hex(artifacts.proposal_hash),
            # ── Launcher-coin identities ──
            "deed_launcher_id": _hex(artifacts.deed_launcher_id),
            "proposal_singleton_launcher_id": _hex(
                artifacts.proposal_singleton_launcher_id
            ),
            # ── Artifact A binding hash (audit log) ──
            "proposal_data_hash": _hex(artifacts.proposal_data_hash),
            # ── Auxiliary programs (serialized) ──
            "bill_op_program_hex": _hex(bytes(artifacts.bill_op_program)),
            "bill_op_program_hash": _hex(
                artifacts.bill_op_program.get_tree_hash()
            ),
            "deed_singleton_struct_program_hex": _hex(
                bytes(artifacts.deed_singleton_struct_program)
            ),
            "deed_singleton_struct_program_hash": _hex(
                artifacts.deed_singleton_struct_program.get_tree_hash()
            ),
            "proposal_singleton_struct_program_hex": _hex(
                bytes(artifacts.proposal_singleton_struct_program)
            ),
            "proposal_singleton_struct_program_hash": _hex(
                artifacts.proposal_singleton_struct_program.get_tree_hash()
            ),
        },
        **_build_spend_sections(artifacts),
    }


def _build_spend_sections(artifacts: Any) -> dict[str, Any]:
    """Compute the spend-builder sections that 4d.2's TS port reads.

    Returns four top-level keys: ``proposal_eve_launch``, ``tracker_propose``,
    ``sgt_first_vote``, and ``property_registry_registration``.  Each follows
    Phase 3's ``sgt_lock`` / ``tracker_vote`` shape (``{inputs, expected}``) so
    the TS Karma spec can iterate over them uniformly.
    """
    # ── 1. proposal_eve_launch (Artifact A) ──
    xch_parent = Coin(XCH_PARENT_PARENT, XCH_PARENT_PUZHASH, uint64(XCH_PARENT_AMOUNT))
    proposal_data_hash = compute_proposal_data_hash(
        property_id_canon=PROPERTY_ID,
        collection_id_canon=COLLECTION_ID,
        share_ppm=SHARE_PPM,
        par_value_mojos=PAR_VALUE,
        royalty_bps=ROYALTY_BPS,
        quorum_threshold=QUORUM_THRESHOLD,
    )
    eve_inner = make_inner_puzzle(
        owner_member_hash=OWNER_MEMBER_HASH,
        gov_member_hash=GOV_MEMBER_HASH,
        proposal_data_hash=proposal_data_hash,
        governance_singleton_struct=TRACKER_STRUCT,
        governance_proposal_hash=artifacts.proposal_hash,
        deed_launcher_id=artifacts.deed_launcher_id,
        did_inner_puzzle_hash=PROTOCOL_DID_INNER_PUZHASH,
        deed_full_puzzle_hash=artifacts.deed_full_puzhash,
        proposal_state=STATE_DRAFT,
        state_version=0,
    )
    eve_launch = build_proposal_eve_launch_spend(
        parent_coin=xch_parent, eve_inner_puzzle=eve_inner
    )
    launcher_spend = eve_launch.launcher_coin_spend

    # ── 2. tracker_propose (Artifact B) ──
    tracker_inner = _idle_tracker_inner()
    tracker_full_ph = bytes32(
        puzzle_for_singleton(TRACKER_LAUNCHER_ID, tracker_inner).get_tree_hash()
    )
    tracker_coin = Coin(TRACKER_PARENT_COIN_INFO, tracker_full_ph, uint64(1))
    tracker_lineage_proof = LineageProof(
        parent_name=TRACKER_LINEAGE_PARENT_NAME,
        inner_puzzle_hash=TRACKER_LINEAGE_INNER_PH,
        amount=uint64(1),
    )
    tracker_propose_spend = build_tracker_propose_coin_spend(
        tracker_coin=tracker_coin,
        tracker_inner_puzzle=tracker_inner,
        tracker_launcher_id=TRACKER_LAUNCHER_ID,
        lineage_proof=tracker_lineage_proof,
        proposal_hash=artifacts.proposal_hash,
        bill_operation=artifacts.bill_op_program,
        voter_inner_puzzle_hash=IDENTITY_HASH,
        first_vote_amount=FIRST_VOTE_AMOUNT,
        voting_deadline=VOTING_DEADLINE,
    )

    # ── 3. sgt_first_vote (proposer's SGT lock) ──
    sgt_free_mod_h = bytes32(sgt_free_inner_mod().get_tree_hash())
    sgt_locked_mod_h = bytes32(sgt_locked_inner_mod().get_tree_hash())
    cat_mod_hash_b32 = bytes32(CAT_MOD.get_tree_hash())
    sgt_ph = cat_sgt_free_puzzle_hash(
        TRACKER_STRUCT,
        sgt_free_mod_h,
        sgt_locked_mod_h,
        cat_mod_hash_b32,
        SGT_TAIL_HASH,
        IDENTITY_HASH,
    )
    sgt_coin = Coin(SGT_PARENT_COIN_INFO, sgt_ph, uint64(FIRST_VOTE_AMOUNT))
    locked_ph = sgt_locked_inner_hash(
        sgt_free_mod_h,
        TRACKER_STRUCT,
        IDENTITY_HASH,
        artifacts.proposal_hash,
        VOTING_DEADLINE,
    )
    voter_inner_solution = Program.to([[51, locked_ph, FIRST_VOTE_AMOUNT]])
    sgt_lineage_proof = LineageProof(
        parent_name=SGT_LINEAGE_PARENT_NAME,
        inner_puzzle_hash=SGT_LINEAGE_INNER_PH,
        amount=uint64(FIRST_VOTE_AMOUNT),
    )
    sgt_lock_spend = build_sgt_first_vote_coin_spend(
        sgt_coin=sgt_coin,
        voter_inner_puzzle=IDENTITY_INNER,
        voter_inner_solution=voter_inner_solution,
        proposal_tracker_struct=TRACKER_STRUCT,
        sgt_tail_hash=SGT_TAIL_HASH,
        lineage_proof=sgt_lineage_proof,
        proposal_hash=artifacts.proposal_hash,
        voting_deadline=VOTING_DEADLINE,
    )

    # ── 4. property_registry_registration (A4 co-spend) ──
    registry_registered_ids = [EXISTING_PROPERTY_ID]
    registry_inner = make_property_registry_inner_puzzle(
        gov_pubkey=PROPERTY_REGISTRY_GOV_PUBKEY,
        registered_ids_root=registered_ids_root(registry_registered_ids),
        registry_version=len(registry_registered_ids),
    )
    registry_full_ph = bytes32(
        puzzle_for_singleton(
            PROPERTY_REGISTRY_LAUNCHER_ID, registry_inner
        ).get_tree_hash()
    )
    registry_prev_full_ph = bytes32(
        puzzle_for_singleton(
            PROPERTY_REGISTRY_LAUNCHER_ID, PROPERTY_REGISTRY_PREV_INNER
        ).get_tree_hash()
    )
    registry_prev_coin = Coin(
        PROPERTY_REGISTRY_PREV_PARENT, registry_prev_full_ph, uint64(1)
    )
    registry_lineage_proof = LineageProof(
        parent_name=PROPERTY_REGISTRY_PREV_PARENT,
        inner_puzzle_hash=bytes32(PROPERTY_REGISTRY_PREV_INNER.get_tree_hash()),
        amount=uint64(1),
    )
    registry_coin = Coin(
        bytes32(registry_prev_coin.name()), registry_full_ph, uint64(1)
    )
    registry_registration = build_registration_coin_spend(
        registry_coin=registry_coin,
        registry_inner_puzzle=registry_inner,
        registry_launcher_id=PROPERTY_REGISTRY_LAUNCHER_ID,
        lineage_proof=registry_lineage_proof,
        property_id_canon=PROPERTY_ID,
        registered_ids=registry_registered_ids,
    )

    # ── 5. quorum-authorized execution co-spends ──
    governance_inner_puzzle_hash = bytes32(tracker_inner.get_tree_hash())
    proposal_lineage_proof = LineageProof(
        parent_name=PROPOSAL_LAUNCHER_PARENT,
        amount=uint64(1),
    )
    proposal_execute_coin = Coin(
        artifacts.proposal_singleton_launcher_id,
        bytes32(
            puzzle_for_singleton(
                artifacts.proposal_singleton_launcher_id, eve_inner
            ).get_tree_hash()
        ),
        uint64(1),
    )
    proposal_execute_spend = build_proposal_execute_coin_spend(
        proposal_coin=proposal_execute_coin,
        proposal_inner_puzzle=eve_inner,
        proposal_launcher_id=artifacts.proposal_singleton_launcher_id,
        lineage_proof=proposal_lineage_proof,
        governance_inner_puzzle_hash=governance_inner_puzzle_hash,
    )
    did_inner = quorum_did_inner_puzzle(TRACKER_LAUNCHER_ID)
    did_coin = Coin(
        DID_COIN_PARENT,
        bytes32(puzzle_for_singleton(DID_LAUNCHER_ID, did_inner).get_tree_hash()),
        uint64(1),
    )
    did_lineage_proof = LineageProof(
        parent_name=DID_LINEAGE_PARENT,
        inner_puzzle_hash=DID_LINEAGE_INNER,
        amount=uint64(1),
    )
    did_execute_spend = build_quorum_did_mint_coin_spend(
        did_coin=did_coin,
        did_inner_puzzle=did_inner,
        did_launcher_id=DID_LAUNCHER_ID,
        lineage_proof=did_lineage_proof,
        deed_full_puzzle_hash=artifacts.deed_full_puzhash,
        governance_inner_puzzle_hash=governance_inner_puzzle_hash,
    )
    custom_deed_launcher = load_puzzle("singleton_launcher_with_did.clsp").curry(
        PROTOCOL_DID_SINGLETON_STRUCT
    )
    deed_launcher_coin = Coin(
        DEED_LAUNCHER_PARENT,
        bytes32(custom_deed_launcher.get_tree_hash()),
        uint64(1),
    )
    assert bytes32(deed_launcher_coin.name()) == artifacts.deed_launcher_id
    deed_launcher_solution = Program.to(
        [
            PROTOCOL_DID_INNER_PUZHASH,
            artifacts.deed_full_puzhash,
            1,
            [],
        ]
    )
    deed_launcher_spend = make_spend(
        deed_launcher_coin,
        custom_deed_launcher,
        deed_launcher_solution,
    )

    return {
        "proposal_eve_launch": {
            "inputs": {
                "xch_parent_coin": _coin_dict(xch_parent),
                "eve_inner_puzzle_hex": _hex(bytes(eve_inner)),
                "amount": SINGLETON_AMOUNT,
            },
            "expected": {
                # Parent-XCH-spend conditions (the TS port must produce
                # the same list).
                "parent_conditions_hex": [
                    _hex(bytes(c)) for c in eve_launch.parent_conditions
                ],
                # Launcher coin + its CoinSpend.
                "launcher_coin": _coin_dict(launcher_spend.coin),
                "launcher_puzzle_reveal_hex": _hex(
                    bytes(launcher_spend.puzzle_reveal)
                ),
                "launcher_solution_hex": _hex(bytes(launcher_spend.solution)),
                "launcher_coin_spend_hex": _hex(bytes(launcher_spend)),
                # Computed eve coin + its full puzzle hash.
                "eve_coin": _coin_dict(eve_launch.eve_coin),
                "eve_full_puzzle_hash": _hex(eve_launch.eve_full_puzzle_hash),
            },
        },
        "tracker_propose": {
            "inputs": {
                "tracker_coin": _coin_dict(tracker_coin),
                "tracker_inner_puzzle_hex": _hex(bytes(tracker_inner)),
                "tracker_launcher_id": _hex(TRACKER_LAUNCHER_ID),
                "lineage_proof": _lineage_proof_dict(tracker_lineage_proof),
                "proposal_hash": _hex(artifacts.proposal_hash),
                "bill_operation_hex": _hex(bytes(artifacts.bill_op_program)),
                "voter_inner_puzzle_hash": _hex(IDENTITY_HASH),
                "first_vote_amount": FIRST_VOTE_AMOUNT,
                "voting_deadline": VOTING_DEADLINE,
            },
            "expected": {
                "coin": _coin_dict(tracker_propose_spend.coin),
                "puzzle_reveal_hex": _hex(
                    bytes(tracker_propose_spend.puzzle_reveal)
                ),
                "solution_hex": _hex(bytes(tracker_propose_spend.solution)),
                "coin_spend_hex": _hex(bytes(tracker_propose_spend)),
            },
        },
        "sgt_first_vote": {
            "inputs": {
                "sgt_coin": _coin_dict(sgt_coin),
                "voter_inner_puzzle_hex": _hex(bytes(IDENTITY_INNER)),
                "voter_inner_solution_hex": _hex(bytes(voter_inner_solution)),
                "proposal_tracker_struct_hex": _hex(bytes(TRACKER_STRUCT)),
                "sgt_tail_hash": _hex(SGT_TAIL_HASH),
                "lineage_proof": _lineage_proof_dict(sgt_lineage_proof),
                "proposal_hash": _hex(artifacts.proposal_hash),
                "voting_deadline": VOTING_DEADLINE,
                "expected_locked_puzhash": _hex(locked_ph),
            },
            "expected": {
                "coin": _coin_dict(sgt_lock_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(sgt_lock_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(sgt_lock_spend.solution)),
                "coin_spend_hex": _hex(bytes(sgt_lock_spend)),
            },
        },
        "property_registry_registration": {
            "inputs": {
                "registry_coin": _coin_dict(registry_coin),
                "gov_pubkey": _hex(PROPERTY_REGISTRY_GOV_PUBKEY),
                "registry_inner_puzzle_hex": _hex(bytes(registry_inner)),
                "registry_launcher_id": _hex(PROPERTY_REGISTRY_LAUNCHER_ID),
                "lineage_proof": _lineage_proof_dict(registry_lineage_proof),
                "property_id_canon": _hex(PROPERTY_ID),
                "registered_ids": [_hex(pid) for pid in registry_registered_ids],
            },
            "expected": {
                "coin": _coin_dict(registry_registration.coin_spend.coin),
                "puzzle_reveal_hex": _hex(
                    bytes(registry_registration.coin_spend.puzzle_reveal)
                ),
                "solution_hex": _hex(
                    bytes(registry_registration.coin_spend.solution)
                ),
                "coin_spend_hex": _hex(bytes(registry_registration.coin_spend)),
                "announcement_id": _hex(registry_registration.announcement_id),
                "new_inner_puzzle_hash": _hex(
                    registry_registration.inner.new_inner_puzzle_hash
                ),
                "new_registered_ids_root": _hex(
                    registry_registration.inner.new_registered_ids_root
                ),
                "agg_sig_me_message": _hex(
                    registry_registration.inner.agg_sig_me_message
                ),
            },
        },
        "did_mint_execute": {
            "inputs": {
                "did_coin": _coin_dict(did_coin),
                "lineage_proof": _lineage_proof_dict(did_lineage_proof),
                "protocol_did_singleton_struct_hex": _hex(
                    bytes(Program.to((SINGLETON_MOD_HASH, (DID_LAUNCHER_ID, SINGLETON_LAUNCHER_HASH))))
                ),
                "governance_singleton_struct_hex": _hex(bytes(TRACKER_STRUCT)),
                "governance_inner_puzzle_hash": _hex(governance_inner_puzzle_hash),
                "deed_full_puzzle_hash": _hex(artifacts.deed_full_puzhash),
            },
            "expected": {
                "coin": _coin_dict(did_execute_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(did_execute_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(did_execute_spend.solution)),
                "coin_spend_hex": _hex(bytes(did_execute_spend)),
            },
        },
        "proposal_mint_execute": {
            "inputs": {
                "proposal_coin": _coin_dict(proposal_execute_coin),
                "lineage_proof": _lineage_proof_dict(proposal_lineage_proof),
                "proposal_launcher_id": _hex(artifacts.proposal_singleton_launcher_id),
                "owner_member_hash": _hex(OWNER_MEMBER_HASH),
                "gov_member_hash": _hex(GOV_MEMBER_HASH),
                "proposal_data_hash": _hex(proposal_data_hash),
                "governance_singleton_struct_hex": _hex(bytes(TRACKER_STRUCT)),
                "governance_proposal_hash": _hex(artifacts.proposal_hash),
                "deed_launcher_id": _hex(artifacts.deed_launcher_id),
                "did_inner_puzzle_hash": _hex(PROTOCOL_DID_INNER_PUZHASH),
                "deed_full_puzzle_hash": _hex(artifacts.deed_full_puzhash),
                "governance_inner_puzzle_hash": _hex(governance_inner_puzzle_hash),
            },
            "expected": {
                "coin": _coin_dict(proposal_execute_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(proposal_execute_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(proposal_execute_spend.solution)),
                "coin_spend_hex": _hex(bytes(proposal_execute_spend)),
            },
        },
        "deed_launcher_execute": {
            "inputs": {
                "deed_launcher_coin": _coin_dict(deed_launcher_coin),
                "protocol_did_singleton_struct_hex": _hex(
                    bytes(PROTOCOL_DID_SINGLETON_STRUCT)
                ),
                "did_inner_puzzle_hash": _hex(PROTOCOL_DID_INNER_PUZHASH),
                "deed_full_puzzle_hash": _hex(artifacts.deed_full_puzhash),
            },
            "expected": {
                "coin": _coin_dict(deed_launcher_spend.coin),
                "puzzle_reveal_hex": _hex(bytes(deed_launcher_spend.puzzle_reveal)),
                "solution_hex": _hex(bytes(deed_launcher_spend.solution)),
                "coin_spend_hex": _hex(bytes(deed_launcher_spend)),
            },
        },
    }


def _services_dir() -> Path:
    protocol_root = Path(__file__).resolve().parents[1]
    return protocol_root / "fixtures" / "mint-proposal-v2"


def fixture_destination() -> Path:
    return _services_dir() / "mint-publish.fixtures.json"


def portal_fixture_destination() -> Path:
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
        / "mint-publish.fixtures.json"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(fixture, indent=2, sort_keys=False) + "\n"
    dest.write_text(rendered)
    portal_dest = portal_fixture_destination()
    portal_dest.parent.mkdir(parents=True, exist_ok=True)
    portal_dest.write_text(rendered)
    print(f"wrote fixture to {dest}")
    print(f"wrote portal fixture to {portal_dest}")
    print(
        f"  smart_deed_inner_puzhash={fixture['expected']['smart_deed_inner_puzhash']}\n"
        f"  eve_inner_puzhash={fixture['expected']['eve_inner_puzhash']}\n"
        f"  deed_full_puzhash={fixture['expected']['deed_full_puzhash']}\n"
        f"  proposal_hash={fixture['expected']['proposal_hash']}\n"
        f"  deed_launcher_id={fixture['expected']['deed_launcher_id']}\n"
        f"  proposal_singleton_launcher_id="
        f"{fixture['expected']['proposal_singleton_launcher_id']}"
    )


if __name__ == "__main__":
    main()
