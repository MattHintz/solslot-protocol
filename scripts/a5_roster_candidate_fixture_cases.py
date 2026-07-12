from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.load_clvm import load_clvm
from chia.wallet.puzzles.singleton_top_layer_v1_1 import puzzle_for_singleton, solution_for_singleton
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v2_driver import (
    SPEND_ADMIN_ROSTER_UPDATE,
    AdminRecord,
    PendingOp,
    build_admin_roster_update_solution,
    compute_admins_hash,
    compute_pending_ops_hash,
    compute_roster_update_binding_hash,
    compute_state_hash,
    compute_launch_outputs,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    singleton_full_puzzle_hash,
)

MAX_COST = 11_000_000_000
REAL_BLS_PUBKEY = bytes(b"\x42" * 48)


def hex_prefixed(value: bytes) -> str:
    return "0x" + value.hex()


def program_hex(program: Program) -> str:
    return hex_prefixed(bytes(program))


def coin_id(parent_coin_info: bytes32, puzzle_hash: bytes32, amount: int) -> bytes32:
    from chia.types.blockchain_format.coin import Coin

    return bytes32(Coin(parent_coin_info, puzzle_hash, amount).name())


def admin_record_json(record: AdminRecord) -> dict[str, Any]:
    return {
        "admin_idx": record.admin_idx,
        "m_within": record.m_within,
        "leaves": [{"leaf_hash": hex_prefixed(leaf)} for leaf in record.leaves],
    }


def pending_op_json(op: PendingOp) -> dict[str, Any]:
    return {
        "admin_idx": op.admin_idx,
        "op_kind": op.op_kind,
        "target_hash": hex_prefixed(op.target_hash),
        "activates_at": op.activates_at,
    }


def condition_opcode(condition: Program) -> int:
    return int(condition.first().as_int())


def condition_atom(condition: Program, index: int) -> bytes:
    value = condition
    for _ in range(index + 1):
        value = value.rest()
    atom = value.first().atom
    if atom is None:
        raise ValueError("condition argument is not an atom")
    return bytes(atom)


def condition_int(condition: Program, index: int) -> int:
    value = condition
    for _ in range(index + 1):
        value = value.rest()
    return int(value.first().as_int())


def bls_member_fixture() -> Program:
    return load_clvm(
        "test_fixture_bls_member.clsp",
        package_or_requirement="solslot_puzzles",
        recompile=True,
    )


def trivial_mips_reveal() -> Program:
    return Program.to((1, [[1, b"\xCA\xFE"]]))


def real_bls_mips_reveal() -> Program:
    return bls_member_fixture().curry(REAL_BLS_PUBKEY)


def decoded_report(cost: int, conditions: list[Program]) -> dict[str, Any]:
    create_announcements = []
    create_coins = []
    agg_sig_me = []
    asserted_amounts = []
    for condition in conditions:
        opcode = condition_opcode(condition)
        if opcode == 62:
            create_announcements.append(hex_prefixed(condition_atom(condition, 0)))
        elif opcode == 51:
            create_coins.append(
                {
                    "puzzle_hash": hex_prefixed(condition_atom(condition, 0)),
                    "amount": condition_int(condition, 1),
                }
            )
        elif opcode == 50:
            agg_sig_me.append(
                {
                    "public_key": hex_prefixed(condition_atom(condition, 0)),
                    "message": hex_prefixed(condition_atom(condition, 1)),
                }
            )
        elif opcode == 73:
            asserted_amounts.append(condition_int(condition, 0))
    return {
        "cost": str(cost),
        "opcodes": [condition_opcode(condition) for condition in conditions],
        "create_puzzle_announcements": create_announcements,
        "create_coins": create_coins,
        "agg_sig_me_conditions": agg_sig_me,
        "asserted_my_amount": asserted_amounts,
    }


def build_case(
    *,
    label: str,
    current_mips_reveal: Program,
    current_mips_solution: Program,
    new_mips_root_hash: bytes32,
    new_admin_leaf_hash: bytes32,
    launcher_parent_coin_id: bytes32,
) -> dict[str, Any]:
    current_mips_root_hash = bytes32(current_mips_reveal.get_tree_hash())
    current_mips_solution_hash = bytes32(current_mips_solution.get_tree_hash())
    current_admins = (
        AdminRecord(admin_idx=0, leaves=(current_mips_root_hash,), m_within=1),
    )
    current_pending_ops: tuple[PendingOp, ...] = ()
    new_admin = AdminRecord(admin_idx=1, leaves=(new_admin_leaf_hash,), m_within=1)
    current_authority_version = 1
    new_authority_version = 2
    current_admins_hash = compute_admins_hash(current_admins)
    current_pending_ops_hash = compute_pending_ops_hash(current_pending_ops)
    new_admins = current_admins + (new_admin,)
    new_admins_hash = compute_admins_hash(new_admins)
    new_pending_ops_hash = compute_pending_ops_hash(current_pending_ops)
    current_state_hash = compute_state_hash(
        current_mips_root_hash,
        current_admins_hash,
        current_pending_ops_hash,
        current_authority_version,
    )
    new_state_hash = compute_state_hash(
        new_mips_root_hash,
        new_admins_hash,
        new_pending_ops_hash,
        new_authority_version,
    )
    roster_update_binding_hash = compute_roster_update_binding_hash(
        current_mips_root_hash=current_mips_root_hash,
        current_admins_hash=current_admins_hash,
        current_pending_ops_hash=current_pending_ops_hash,
        current_authority_version=current_authority_version,
        new_admins_hash=new_admins_hash,
        new_mips_root_hash=new_mips_root_hash,
        new_authority_version=new_authority_version,
    )
    current_inner_puzzle = make_inner_puzzle(
        mips_root_hash=current_mips_root_hash,
        admins_hash=current_admins_hash,
        pending_ops_hash=current_pending_ops_hash,
        authority_version=current_authority_version,
    )
    current_inner_puzzle_hash = bytes32(current_inner_puzzle.get_tree_hash())
    next_inner_puzzle_hash = make_inner_puzzle_hash(
        mips_root_hash=new_mips_root_hash,
        admins_hash=new_admins_hash,
        pending_ops_hash=new_pending_ops_hash,
        authority_version=new_authority_version,
    )
    launch = compute_launch_outputs(
        parent_coin_id=launcher_parent_coin_id,
        eve_inner_puzzle_hash=current_inner_puzzle_hash,
        eve_amount=1,
    )
    live_coin_id = coin_id(launch.launcher_id, launch.eve_full_puzzle_hash, 1)
    next_full_puzzle_hash = singleton_full_puzzle_hash(launch.launcher_id, next_inner_puzzle_hash)
    inner_solution = build_admin_roster_update_solution(
        my_amount=1,
        current_authority_version=current_authority_version,
        new_authority_version=new_authority_version,
        current_admins=current_admins,
        current_pending_ops=current_pending_ops,
        current_mips_reveal=current_mips_reveal,
        current_mips_solution=current_mips_solution,
        new_admin=new_admin,
        new_mips_root_hash=new_mips_root_hash,
    )
    lineage_proof = LineageProof(parent_name=launcher_parent_coin_id, amount=1)
    full_puzzle = puzzle_for_singleton(launch.launcher_id, current_inner_puzzle)
    full_solution = solution_for_singleton(lineage_proof, 1, inner_solution)
    cost, conditions_program = current_inner_puzzle.run_with_cost(MAX_COST, inner_solution)
    conditions = list(conditions_program.as_iter())
    live_coin = {
        "coin_id": hex_prefixed(live_coin_id),
        "parent_coin_info": hex_prefixed(launch.launcher_id),
        "puzzle_hash": hex_prefixed(launch.eve_full_puzzle_hash),
        "amount": 1,
    }
    intake = {
        "kind": "admin_authority_v2_roster_update_spend_builder_verified_intake",
        "boundary": "normalize_and_reverify_inputs_without_spend_construction",
        "result": "verified_intake_only_no_signed_bundle",
        "singleton_coin": live_coin,
        "roster_transition": {
            "launcher_id": hex_prefixed(launch.launcher_id),
            "spend_tag": SPEND_ADMIN_ROSTER_UPDATE,
            "spend_name": "ADMIN_ROSTER_UPDATE",
            "current_authority_version": current_authority_version,
            "new_authority_version": new_authority_version,
            "current_state_hash": hex_prefixed(current_state_hash),
            "new_state_hash": hex_prefixed(new_state_hash),
            "roster_update_binding_hash": hex_prefixed(roster_update_binding_hash),
            "current_mips_root_hash": hex_prefixed(current_mips_root_hash),
            "new_mips_root_hash": hex_prefixed(new_mips_root_hash),
            "current_admins_hash": hex_prefixed(current_admins_hash),
            "new_admins_hash": hex_prefixed(new_admins_hash),
            "current_pending_ops_hash": hex_prefixed(current_pending_ops_hash),
            "new_pending_ops_hash": hex_prefixed(new_pending_ops_hash),
        },
        "deterministic_commitment_summary": {
            "current_mips_puzzle_reveal_tree_hash": hex_prefixed(current_mips_root_hash),
            "current_mips_quorum_solution_tree_hash": hex_prefixed(current_mips_solution_hash),
            "current_admin_authority_v2_inner_puzzle_reveal_tree_hash": hex_prefixed(current_inner_puzzle_hash),
            "computed_current_inner_puzzle_hash": hex_prefixed(current_inner_puzzle_hash),
            "computed_current_state_hash": hex_prefixed(current_state_hash),
            "computed_singleton_full_puzzle_hash": hex_prefixed(launch.eve_full_puzzle_hash),
            "computed_live_singleton_coin_id": hex_prefixed(live_coin_id),
        },
    }
    plan = {
        "kind": "admin_authority_v2_roster_update_unsigned_clvm_construction_plan",
        "boundary": "derive_unsigned_clvm_construction_plan_without_coin_spend_serialization",
        "result": "unsigned_clvm_construction_plan_only_no_coin_spends",
        "source_intake": {
            "kind": "admin_authority_v2_roster_update_spend_builder_verified_intake",
            "result": "verified_intake_only_no_signed_bundle",
            "singleton_coin_id": hex_prefixed(live_coin_id),
            "launcher_id": hex_prefixed(launch.launcher_id),
            "roster_update_binding_hash": hex_prefixed(roster_update_binding_hash),
        },
        "unsigned_admin_authority_v2_spend_shape": {
            "coin": live_coin,
            "singleton_launcher_id": hex_prefixed(launch.launcher_id),
            "current_singleton_full_puzzle_hash": hex_prefixed(launch.eve_full_puzzle_hash),
            "current_inner_puzzle_hash": hex_prefixed(current_inner_puzzle_hash),
            "new_inner_puzzle_hash": hex_prefixed(next_inner_puzzle_hash),
            "new_singleton_full_puzzle_hash": hex_prefixed(next_full_puzzle_hash),
            "spend_tag": SPEND_ADMIN_ROSTER_UPDATE,
            "spend_name": "ADMIN_ROSTER_UPDATE",
            "current_state_hash": hex_prefixed(current_state_hash),
            "new_state_hash": hex_prefixed(new_state_hash),
            "roster_update_binding_hash": hex_prefixed(roster_update_binding_hash),
            "puzzle_reveal_status": "derived_from_verified_singleton_wrapper_and_inner_reveal_hash_not_serialized",
            "solution_status": "planned_only_not_serialized_as_coin_spend",
        },
        "unsigned_mips_spend_shape": {
            "puzzle_reveal_tree_hash": hex_prefixed(current_mips_root_hash),
            "quorum_solution_tree_hash": hex_prefixed(current_mips_solution_hash),
            "authorization_scope": "current_admin_authority_v2_mips_quorum",
            "execution_status": "not_executed",
            "solution_status": "hash_verified_not_executed_not_serialized_as_coin_spend",
        },
        "expected_conditions_summary": {
            "state_announcement": {
                "body_shape": "protocol_prefix_spend_tag_state_hash",
                "spend_tag": SPEND_ADMIN_ROSTER_UPDATE,
                "state_hash": hex_prefixed(new_state_hash),
            },
            "singleton_continuation": {
                "launcher_id": hex_prefixed(launch.launcher_id),
                "next_inner_puzzle_hash": hex_prefixed(next_inner_puzzle_hash),
                "next_full_puzzle_hash": hex_prefixed(next_full_puzzle_hash),
                "amount": 1,
            },
        },
        "deterministic_unsigned_construction_summary": {
            "current_mips_puzzle_reveal_tree_hash": hex_prefixed(current_mips_root_hash),
            "current_mips_quorum_solution_tree_hash": hex_prefixed(current_mips_solution_hash),
            "current_admin_authority_v2_inner_puzzle_reveal_tree_hash": hex_prefixed(current_inner_puzzle_hash),
            "current_singleton_full_puzzle_hash": hex_prefixed(launch.eve_full_puzzle_hash),
            "current_state_hash": hex_prefixed(current_state_hash),
            "new_admin_authority_v2_inner_puzzle_hash": hex_prefixed(next_inner_puzzle_hash),
            "new_singleton_full_puzzle_hash": hex_prefixed(next_full_puzzle_hash),
            "new_state_hash": hex_prefixed(new_state_hash),
            "roster_update_binding_hash": hex_prefixed(roster_update_binding_hash),
        },
    }
    roster_material = {
        "current_admin_records": [admin_record_json(record) for record in current_admins],
        "current_pending_ops": [pending_op_json(op) for op in current_pending_ops],
        "new_admin_record": admin_record_json(new_admin),
        "singleton_lineage_proof": {
            "parent_parent_coin_info": hex_prefixed(launcher_parent_coin_id),
            "parent_inner_puzzle_hash": None,
            "parent_amount": 1,
        },
    }
    return {
        "case": label,
        "request": {
            "unsignedClvmConstructionPlan": plan,
            "verifiedSpendBuilderIntake": intake,
            "rawCurrentMipsPuzzleReveal": program_hex(current_mips_reveal),
            "rawCurrentMipsQuorumSolution": program_hex(current_mips_solution),
            "rawCurrentAdminAuthorityV2InnerPuzzleReveal": program_hex(current_inner_puzzle),
            "liveSingletonCoinMetadata": live_coin,
            "rosterUpdateMaterial": roster_material,
            "maxCost": str(MAX_COST),
        },
        "expected": {
            "coin_spend": {
                "coin": {
                    "parentCoinInfo": hex_prefixed(launch.launcher_id),
                    "puzzleHash": hex_prefixed(launch.eve_full_puzzle_hash),
                    "amount": 1,
                },
                "puzzleReveal": program_hex(full_puzzle),
                "solution": program_hex(full_solution),
            },
            "bounded_mips_execution_report": decoded_report(int(cost), conditions),
            "review": {
                "singleton_coin_id": hex_prefixed(live_coin_id),
                "current_singleton_full_puzzle_hash": hex_prefixed(launch.eve_full_puzzle_hash),
                "next_singleton_full_puzzle_hash": hex_prefixed(next_full_puzzle_hash),
                "new_state_hash": hex_prefixed(new_state_hash),
                "roster_update_binding_hash": hex_prefixed(roster_update_binding_hash),
            },
        },
    }


def build_fixture() -> dict[str, Any]:
    return {
        "schema": "admin_roster_mips_execution_coin_spend_fixture_v2",
        "cases": [
            build_case(
                label="eve_roster_update_with_trivial_mips_authorization",
                current_mips_reveal=trivial_mips_reveal(),
                current_mips_solution=Program.to([]),
                new_mips_root_hash=bytes32(b"\xB0" * 32),
                new_admin_leaf_hash=bytes32(b"\x21" * 32),
                launcher_parent_coin_id=bytes32(b"\xA5" * 32),
            ),
            build_case(
                label="eve_roster_update_with_real_bls_agg_sig_me_authorization",
                current_mips_reveal=real_bls_mips_reveal(),
                current_mips_solution=Program.to([bytes32(b"\x99" * 32)]),
                new_mips_root_hash=bytes32(b"\xC0" * 32),
                new_admin_leaf_hash=bytes32(b"\x31" * 32),
                launcher_parent_coin_id=bytes32(b"\xB5" * 32),
            ),
        ],
    }


def fixture_destination() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "populis_portal" / "src" / "app" / "services" / "admin-authority-v2" / "admin-roster-mips-execution-coin-spend.fixture.json"


def write_fixture() -> Path:
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(build_fixture(), indent=2, sort_keys=False) + "\n")
    return dest
