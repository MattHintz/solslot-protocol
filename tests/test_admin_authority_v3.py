from __future__ import annotations

import hashlib

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.custody.custody_architecture import (
    DelegatedPuzzleAndSolution,
    ProvenSpend,
)
from chia_rs import AugSchemeMPL
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.admin_authority_v3_driver import (
    ADMIN_AUTHORITY_FUNDING_AMOUNT,
    IDENTITY_LAUNCHER_AMOUNTS,
    LOST_KEY_DELAY_SECONDS,
    PENDING_LOST,
    PENDING_ROUTINE,
    ROUTINE_DELAY_SECONDS,
    SPEND_CANCEL,
    SPEND_COMPLETE,
    SPEND_OPERATIONAL,
    AdminAuthorityV3State,
    authority_v3_launcher_ids,
    build_cancel_solution,
    build_complete_solution,
    build_genesis_admin_authority_v3,
    build_identity_finish_solution,
    build_identity_vault_transition,
    build_lost_recovery_identity_solution,
    build_operational_solution,
    build_prepare_solution,
    compute_completion_message,
    compute_prepare_binding_hash,
    make_inner_puzzle,
    parse_inner_puzzle,
)


SOURCE_MANIFEST_HASH = bytes32(b"\x90" * 32)
IDENTITY_LAUNCHERS = (
    bytes32(b"\x10" * 32),
    bytes32(b"\x11" * 32),
    bytes32(b"\x12" * 32),
)
AUTHORITY_VERSION = 1
AUTHORITY_AMOUNT = 1


def _constant_conditions(conditions: list[list[object]]) -> Program:
    return Program.to((1, conditions))


def _first_condition(result: Program, opcode: int) -> Program:
    for condition in result.as_iter():
        if condition.first().as_int() == opcode:
            return condition
    raise AssertionError(f"condition {opcode} not found")


def _empty_inner(
    *,
    state: AdminAuthorityV3State | None = None,
) -> tuple[Program, Program, tuple[Program, Program, Program]]:
    operational = _constant_conditions([[1, b"operational"]])
    recoveries = tuple(
        _constant_conditions([[1, f"recovery-{slot}".encode("ascii")]])
        for slot in range(3)
    )
    inner = make_inner_puzzle(
        operational_root_hash=bytes32(operational.get_tree_hash()),
        lost_recovery_root_hashes=tuple(
            bytes32(recovery.get_tree_hash())
            for recovery in recoveries
        ),
        identity_launcher_ids=IDENTITY_LAUNCHERS,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
        state=state,
    )
    return inner, operational, recoveries  # type: ignore[return-value]


def test_genesis_builds_fixed_owner_plus_one_and_three_of_three_recovery() -> None:
    daily_private_keys = [
        bytes.fromhex("02" + "11" * 32),
        bytes.fromhex("03" + "22" * 32),
        bytes.fromhex("02" + "33" * 32),
    ]
    recovery_public_keys = tuple(
        bytes(
            AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1()
        )
        for index in (1, 2, 3)
    )
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=bytes32(b"\x44" * 32),
        network="testnet11",
        daily_compressed_pubkeys=daily_private_keys,
        recovery_bls_pubkeys=recovery_public_keys,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )

    assert authority.operational_policy.m == 2
    assert len(authority.operational_policy.members) == 2
    coadmin_choice = authority.operational_policy.members[1].puzzle
    assert coadmin_choice.m == 1
    assert len(coadmin_choice.members) == 2
    assert len(authority.lost_recovery_policies) == 3
    for slot, policy in enumerate(authority.lost_recovery_policies):
        assert policy.m == 2
        assert len(policy.members) == 2
        assert all(
            member.puzzle.launcher_id
            != authority.identity_vaults[slot].launcher_id
            for member in policy.members
        )
    assert [
        identity.daily_compressed_pubkey
        for identity in authority.identity_vaults
    ] == daily_private_keys

    assert [identity.launcher_amount for identity in authority.identity_vaults] == [
        3,
        5,
        7,
    ]
    for identity in authority.identity_vaults:
        assert identity.custody_policy.m == 1
        daily_path = identity.custody_policy.members[0].puzzle
        assert daily_path.m == 2
        assert not isinstance(identity.custody_policy.members[1].puzzle, type(daily_path))


def test_authority_root_executes_the_signed_delegated_action() -> None:
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=bytes32(b"\x44" * 32),
        network="testnet11",
        daily_compressed_pubkeys=[
            bytes.fromhex("02" + "11" * 32),
            bytes.fromhex("03" + "22" * 32),
            bytes.fromhex("02" + "33" * 32),
        ],
        recovery_bls_pubkeys=[
            bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
            for index in (1, 2, 3)
        ],
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )

    owner = authority.operational_policy.members[0]
    coadmin_branch = authority.operational_policy.members[1]
    coadmin = coadmin_branch.puzzle.members[0]
    singleton_solution = Program.to([bytes32(b"\x45" * 32), 3])

    owner_solution = owner.solve([], [], singleton_solution)
    coadmin_solution = coadmin.solve([], [], singleton_solution)
    coadmin_policy_solution = coadmin_branch.puzzle.solve(
        {
            coadmin.puzzle_hash(_top_level=False): ProvenSpend(
                puzzle_reveal=coadmin.puzzle_reveal(_top_level=False),
                solution=coadmin_solution,
            )
        }
    )
    coadmin_branch_solution = coadmin_branch.solve(
        [],
        [],
        coadmin_policy_solution,
    )
    operational_solution = authority.operational_policy.solve(
        {
            owner.puzzle_hash(_top_level=False): ProvenSpend(
                puzzle_reveal=owner.puzzle_reveal(_top_level=False),
                solution=owner_solution,
            ),
            coadmin_branch.puzzle_hash(_top_level=False): ProvenSpend(
                puzzle_reveal=coadmin_branch.puzzle_reveal(_top_level=False),
                solution=coadmin_branch_solution,
            ),
        }
    )
    delegated = DelegatedPuzzleAndSolution(
        puzzle=Program.to((1, [[1, b"delegated authority action"]])),
        solution=Program.to(None),
    )
    root_solution = authority.operational_root.solve(
        [],
        [],
        operational_solution,
        delegated,
    )

    conditions = [
        condition.as_python()
        for condition in authority.operational_reveal.run(
            root_solution
        ).as_iter()
    ]
    assert [b"\x01", b"delegated authority action"] in conditions
    assert sum(condition[0] == b"C" for condition in conditions) == 2
    assert authority.operational_reveal != authority.operational_policy.puzzle(0)


def test_identity_custody_and_recovery_roots_use_top_level_mips() -> None:
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=bytes32(b"\x46" * 32),
        network="testnet11",
        daily_compressed_pubkeys=[
            bytes.fromhex("02" + "11" * 32),
            bytes.fromhex("03" + "22" * 32),
            bytes.fromhex("02" + "33" * 32),
        ],
        recovery_bls_pubkeys=[
            bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
            for index in (1, 2, 3)
        ],
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )

    assert authority.operational_reveal == authority.operational_root.puzzle_reveal()
    assert authority.lost_recovery_reveals == tuple(
        root.puzzle_reveal() for root in authority.lost_recovery_roots
    )
    for identity in authority.identity_vaults:
        assert identity.custody_reveal == identity.custody_root.puzzle_reveal()
        assert identity.custody_reveal != identity.custody_policy.puzzle(0)
        recovery_key = identity.custody_policy.members[1]
        assert len(recovery_key.restrictions) == 1
        wrapper_stack = recovery_key.restrictions[0]
        assert len(wrapper_stack.required_wrappers) == 6


def test_parse_inner_puzzle_round_trips_frozen_configuration() -> None:
    inner, operational, recoveries = _empty_inner()
    parsed = parse_inner_puzzle(inner)

    assert parsed.operational_root_hash == bytes32(operational.get_tree_hash())
    assert parsed.lost_recovery_root_hashes == (
        *(
            bytes32(recovery.get_tree_hash())
            for recovery in recoveries
        ),
    )
    assert parsed.identity_launcher_ids == IDENTITY_LAUNCHERS
    assert parsed.source_manifest_hash == SOURCE_MANIFEST_HASH
    assert parsed.state == AdminAuthorityV3State()


def test_authority_launchers_are_unique_and_use_exact_16_mojos() -> None:
    launcher_ids = authority_v3_launcher_ids(bytes32(b"\x55" * 32))
    assert len(set(launcher_ids)) == 4
    assert IDENTITY_LAUNCHER_AMOUNTS == (3, 5, 7)
    assert ADMIN_AUTHORITY_FUNDING_AMOUNT == 16


def test_operational_spend_succeeds_only_without_pending_change() -> None:
    inner, operational, _ = _empty_inner()
    result = inner.run(
        build_operational_solution(
            my_amount=AUTHORITY_AMOUNT,
            new_authority_version=2,
            mips_reveal=operational,
            mips_solution=Program.to(None),
        )
    )
    _first_condition(result, 51)
    _first_condition(result, 62)

    pending = AdminAuthorityV3State(
        authority_version=2,
        pending_kind=PENDING_ROUTINE,
        pending_slot=1,
        pending_intent_hash=bytes32(b"\x21" * 32),
        pending_identity_coin_id=bytes32(b"\x22" * 32),
        pending_replacement_custody_hash=bytes32(b"\x23" * 32),
        pending_replacement_member_hash=bytes32(b"\x24" * 32),
        pending_delay_seconds=ROUTINE_DELAY_SECONDS,
    )
    frozen, operational, _ = _empty_inner(state=pending)
    with pytest.raises(Exception):
        frozen.run(
            build_operational_solution(
                my_amount=AUTHORITY_AMOUNT,
                new_authority_version=3,
                mips_reveal=operational,
                mips_solution=Program.to(None),
            )
        )


@pytest.mark.parametrize(
    ("lost_key", "kind", "expected_delay"),
    (
        (False, PENDING_ROUTINE, ROUTINE_DELAY_SECONDS),
        (True, PENDING_LOST, LOST_KEY_DELAY_SECONDS),
    ),
)
def test_prepare_binds_intent_replacement_and_delay(
    lost_key: bool,
    kind: int,
    expected_delay: int,
) -> None:
    inner, operational, recoveries = _empty_inner()
    intent_hash = bytes32(b"\x31" * 32)
    identity_coin_id = bytes32(b"\x32" * 32)
    intermediate_identity_coin_id = bytes32(b"\x35" * 32)
    replacement_custody_hash = bytes32(b"\x33" * 32)
    replacement = _constant_conditions([[1, b"replacement accepted"]])
    replacement_member_hash = bytes32(replacement.get_tree_hash())
    binding = compute_prepare_binding_hash(
        pending_kind=kind,
        slot=2,
        intent_hash=intent_hash,
        current_identity_coin_id=identity_coin_id,
        intermediate_identity_coin_id=intermediate_identity_coin_id,
        replacement_custody_hash=replacement_custody_hash,
        replacement_member_hash=replacement_member_hash,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
        current_authority_version=AUTHORITY_VERSION,
        new_authority_version=2,
        identity_launcher_id=IDENTITY_LAUNCHERS[2],
    )
    auth = _constant_conditions([[62, binding]])
    selected_root = recoveries[2] if lost_key else operational
    # The root hash is curried, so use a reveal with the exact expected hash.
    inner = make_inner_puzzle(
        operational_root_hash=(
            bytes32(auth.get_tree_hash())
            if not lost_key
            else bytes32(operational.get_tree_hash())
        ),
        lost_recovery_root_hashes=tuple(
            bytes32(auth.get_tree_hash())
            if lost_key and slot == 2
            else bytes32(recovery.get_tree_hash())
            for slot, recovery in enumerate(recoveries)
        ),
        identity_launcher_ids=IDENTITY_LAUNCHERS,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    result = inner.run(
        build_prepare_solution(
            lost_key=lost_key,
            my_amount=AUTHORITY_AMOUNT,
            new_authority_version=2,
            mips_reveal=auth,
            mips_solution=Program.to(None),
            replacement_member_reveal=replacement,
            replacement_member_solution=Program.to(None),
            slot=2,
            intent_hash=intent_hash,
            current_identity_coin_id=identity_coin_id,
            intermediate_identity_coin_id=intermediate_identity_coin_id,
            replacement_custody_hash=replacement_custody_hash,
            replacement_member_hash=replacement_member_hash,
        )
    )
    _first_condition(result, 51)
    announcement = _first_condition(result, 62)
    assert announcement is not None
    assert expected_delay in (ROUTINE_DELAY_SECONDS, LOST_KEY_DELAY_SECONDS)
    assert selected_root is not None

    forged_auth = _constant_conditions([[62, bytes32(b"\x99" * 32)]])
    forged_inner = make_inner_puzzle(
        operational_root_hash=(
            bytes32(forged_auth.get_tree_hash())
            if not lost_key
            else bytes32(operational.get_tree_hash())
        ),
        lost_recovery_root_hashes=tuple(
            bytes32(forged_auth.get_tree_hash())
            if lost_key and slot == 2
            else bytes32(recovery.get_tree_hash())
            for slot, recovery in enumerate(recoveries)
        ),
        identity_launcher_ids=IDENTITY_LAUNCHERS,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    with pytest.raises(Exception):
        forged_inner.run(
            build_prepare_solution(
                lost_key=lost_key,
                my_amount=AUTHORITY_AMOUNT,
                new_authority_version=2,
                mips_reveal=forged_auth,
                mips_solution=Program.to(None),
                replacement_member_reveal=replacement,
                replacement_member_solution=Program.to(None),
                slot=2,
                intent_hash=intent_hash,
                current_identity_coin_id=identity_coin_id,
                intermediate_identity_coin_id=intermediate_identity_coin_id,
                replacement_custody_hash=replacement_custody_hash,
                replacement_member_hash=replacement_member_hash,
            )
        )


def test_completion_is_delayed_and_bound_to_identity_coin_announcement() -> None:
    state = AdminAuthorityV3State(
        authority_version=4,
        pending_kind=PENDING_LOST,
        pending_slot=0,
        pending_intent_hash=bytes32(b"\x41" * 32),
        pending_identity_coin_id=bytes32(b"\x42" * 32),
        pending_replacement_custody_hash=bytes32(b"\x43" * 32),
        pending_replacement_member_hash=bytes32(b"\x44" * 32),
        pending_delay_seconds=LOST_KEY_DELAY_SECONDS,
    )
    inner, _, _ = _empty_inner(state=state)
    result = inner.run(
        build_complete_solution(
            my_amount=AUTHORITY_AMOUNT,
            new_authority_version=5,
        )
    )
    seconds = _first_condition(result, 80)
    assert seconds.rest().first().as_int() == LOST_KEY_DELAY_SECONDS
    announcement = _first_condition(result, 61)
    expected = hashlib.sha256(
        state.pending_identity_coin_id
        + compute_completion_message(
            state=state,
            source_manifest_hash=SOURCE_MANIFEST_HASH,
        )
    ).digest()
    assert announcement.rest().first().as_atom() == expected


def test_old_operational_quorum_can_cancel_exact_pending_intent() -> None:
    state = AdminAuthorityV3State(
        authority_version=7,
        pending_kind=PENDING_ROUTINE,
        pending_slot=1,
        pending_intent_hash=bytes32(b"\x51" * 32),
        pending_identity_coin_id=bytes32(b"\x52" * 32),
        pending_replacement_custody_hash=bytes32(b"\x53" * 32),
        pending_replacement_member_hash=bytes32(b"\x54" * 32),
        pending_delay_seconds=ROUTINE_DELAY_SECONDS,
    )
    placeholder, _, recoveries = _empty_inner(state=state)
    cancel_binding = bytes32(
        Program.to(
            [
                SPEND_CANCEL,
                state.pending_kind,
                state.pending_slot,
                state.pending_intent_hash,
                state.pending_identity_coin_id,
                state.pending_replacement_custody_hash,
                state.pending_replacement_member_hash,
                SOURCE_MANIFEST_HASH,
                state.authority_version,
                state.authority_version + 1,
            ]
        ).get_tree_hash()
    )
    operational = _constant_conditions([[62, cancel_binding]])
    inner = make_inner_puzzle(
        operational_root_hash=bytes32(operational.get_tree_hash()),
        lost_recovery_root_hashes=tuple(
            bytes32(recovery.get_tree_hash())
            for recovery in recoveries
        ),
        identity_launcher_ids=IDENTITY_LAUNCHERS,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
        state=state,
    )
    result = inner.run(
        build_cancel_solution(
            my_amount=AUTHORITY_AMOUNT,
            new_authority_version=8,
            mips_reveal=operational,
            mips_solution=Program.to(None),
        )
    )
    _first_condition(result, 51)
    _first_condition(result, 62)
    assert placeholder is not None


def test_state_rejects_noncanonical_empty_and_wrong_delays() -> None:
    with pytest.raises(ValueError, match="canonical"):
        AdminAuthorityV3State(pending_slot=1).validate()
    with pytest.raises(ValueError, match="delay"):
        AdminAuthorityV3State(
            pending_kind=PENDING_LOST,
            pending_slot=0,
            pending_intent_hash=bytes32(b"\x61" * 32),
            pending_identity_coin_id=bytes32(b"\x62" * 32),
            pending_replacement_custody_hash=bytes32(b"\x63" * 32),
            pending_replacement_member_hash=bytes32(b"\x64" * 32),
            pending_delay_seconds=ROUTINE_DELAY_SECONDS,
        ).validate()


def test_lost_key_identity_prepare_and_permissionless_finish_execute() -> None:
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=bytes32(b"\x71" * 32),
        network="testnet11",
        daily_compressed_pubkeys=[
            bytes.fromhex("02" + "11" * 32),
            bytes.fromhex("03" + "22" * 32),
            bytes.fromhex("02" + "33" * 32),
        ],
        recovery_bls_pubkeys=[
            bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
            for index in (1, 2, 3)
        ],
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    identity = authority.identity_vaults[1]
    transition = build_identity_vault_transition(
        identity=identity,
        authority_launcher_id=authority.authority_launcher_id,
        authority_current_full_puzzle_hash=authority.full_puzzle_hash,
        network="testnet11",
        kind=PENDING_LOST,
        intent_hash=bytes32(b"\x72" * 32),
        current_identity_coin_id=bytes32(b"\x73" * 32),
        replacement_daily_compressed_pubkey=bytes.fromhex(
            "03" + "44" * 32
        ),
        source_manifest_hash=SOURCE_MANIFEST_HASH,
        current_authority_version=1,
    )

    prepare_result = identity.custody_reveal.run(
        build_lost_recovery_identity_solution(
            identity=identity,
            transition=transition,
        )
    )
    prepare_create = _first_condition(prepare_result, 51)
    assert prepare_create.rest().first().as_atom() == (
        transition.intermediate_custody_hash
    )
    assert prepare_create.rest().rest().first().as_int() == (
        identity.launcher_amount
    )
    _first_condition(prepare_result, 63)
    _first_condition(prepare_result, 70)
    _first_condition(prepare_result, 73)

    finish_result = transition.intermediate_custody_reveal.run(
        build_identity_finish_solution(transition)
    )
    finish_create = _first_condition(finish_result, 51)
    assert finish_create.rest().first().as_atom() == (
        transition.final_custody_hash
    )
    assert finish_create.rest().rest().first().as_int() == (
        identity.launcher_amount
    )
    assert (
        _first_condition(finish_result, 60).rest().first().as_atom()
        == transition.completion_message
    )
    assert (
        _first_condition(finish_result, 80).rest().first().as_int()
        == LOST_KEY_DELAY_SECONDS
    )


def test_finish_member_commits_exact_delay_and_replacement() -> None:
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=bytes32(b"\x81" * 32),
        network="testnet11",
        daily_compressed_pubkeys=[
            bytes.fromhex("02" + "11" * 32),
            bytes.fromhex("03" + "22" * 32),
            bytes.fromhex("02" + "33" * 32),
        ],
        recovery_bls_pubkeys=[
            bytes(AugSchemeMPL.key_gen(bytes([index]) * 32).get_g1())
            for index in (1, 2, 3)
        ],
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    identity = authority.identity_vaults[0]
    transition = build_identity_vault_transition(
        identity=identity,
        authority_launcher_id=authority.authority_launcher_id,
        authority_current_full_puzzle_hash=authority.full_puzzle_hash,
        network="testnet11",
        kind=PENDING_ROUTINE,
        intent_hash=bytes32(b"\x82" * 32),
        current_identity_coin_id=bytes32(b"\x83" * 32),
        replacement_daily_compressed_pubkey=bytes.fromhex(
            "03" + "55" * 32
        ),
        source_manifest_hash=SOURCE_MANIFEST_HASH,
        current_authority_version=1,
    )

    conditions = transition.finish_delegated_puzzle.run(Program.to(None))
    assert (
        _first_condition(conditions, 80).rest().first().as_int()
        == ROUTINE_DELAY_SECONDS
    )
    assert (
        _first_condition(conditions, 51).rest().first().as_atom()
        == transition.final_custody_hash
    )
