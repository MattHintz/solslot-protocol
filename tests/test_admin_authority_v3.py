from __future__ import annotations

from dataclasses import dataclass
import hashlib

import chia_rs
from chia._tests.util.spend_sim import SimClient, SpendSim
from chia.consensus.default_constants import DEFAULT_CONSTANTS
from chia.types.blockchain_format.program import Program
from chia.types.coin_spend import CoinSpend, make_spend
from chia.types.mempool_inclusion_status import MempoolInclusionStatus
from chia.wallet.puzzles.custody.custody_architecture import ProvenSpend
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    launch_conditions_and_coinsol,
    lineage_proof_for_coinsol,
    puzzle_for_singleton,
    solution_for_singleton,
)
from chia.wallet.util.compute_additions import compute_additions
from chia_rs import AugSchemeMPL, G2Element, PrivateKey, SpendBundle
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64
from eth_keys import keys
import pytest

from solslot_puzzles.admin_authority_v3_driver import (
    ADMIN_AUTHORITY_FUNDING_AMOUNT,
    AUTHORITY_LAUNCHER_AMOUNT,
    IDENTITY_LAUNCHER_AMOUNTS,
    LOST_KEY_DELAY_SECONDS,
    PENDING_LOST,
    PENDING_RECOVERY_KIT,
    PENDING_ROUTINE,
    ROUTINE_DELAY_SECONDS,
    SPEND_CANCEL,
    SPEND_OPERATIONAL,
    AdminAuthorityV3State,
    GenesisAdminAuthorityV3,
    IdentityVaultTransition,
    admin_identity_prepare_announcement_v1_mod,
    authority_v3_launcher_ids,
    build_admin_identity_vault,
    build_authority_prepare_mips_spend,
    build_cancel_solution,
    build_complete_solution,
    build_genesis_admin_authority_v3,
    build_identity_action_puzzle,
    build_identity_approval_action,
    build_identity_approval_solution,
    build_identity_cancel_solution,
    build_identity_finish_solution,
    build_identity_vault_transition,
    build_lost_recovery_identity_solution,
    build_operational_solution,
    build_prepare_solution,
    build_routine_identity_prepare_solution,
    compute_cancel_message,
    compute_completion_message,
    parse_inner_puzzle,
)
from solslot_puzzles.eip712_helpers import (
    TESTNET11_GENESIS_CHALLENGE,
    eip712_hash_to_sign,
    eip712_prefix_and_domain_separator,
)


SOURCE_MANIFEST_HASH = bytes32(b"\x90" * 32)
RUN_FLAGS = (
    chia_rs.MEMPOOL_MODE
    | chia_rs.ENABLE_SECP_OPS
    | chia_rs.ENABLE_KECCAK_OPS_OUTSIDE_GUARD
)


@dataclass(frozen=True)
class AuthorityFixture:
    authority: GenesisAdminAuthorityV3
    daily_private_keys: tuple[
        keys.PrivateKey,
        keys.PrivateKey,
        keys.PrivateKey,
    ]
    recovery_private_keys: tuple[PrivateKey, PrivateKey, PrivateKey]
    identity_coin_ids: tuple[bytes32, bytes32, bytes32]
    authority_coin_id: bytes32


def _compressed_pubkey(private_key: keys.PrivateKey) -> bytes:
    raw = private_key.public_key.to_bytes()
    prefix = b"\x02" if int.from_bytes(raw[32:], "big") % 2 == 0 else b"\x03"
    return prefix + raw[:32]


def _fixture() -> AuthorityFixture:
    daily_private_keys = tuple(
        keys.PrivateKey(bytes([value]) * 32) for value in (0x11, 0x22, 0x33)
    )
    recovery_private_keys = tuple(
        AugSchemeMPL.key_gen(bytes([value]) * 32)
        for value in (0x41, 0x42, 0x43)
    )
    authority = build_genesis_admin_authority_v3(
        parent_coin_id=bytes32(b"\x44" * 32),
        network="testnet11",
        daily_compressed_pubkeys=tuple(
            _compressed_pubkey(value) for value in daily_private_keys
        ),
        recovery_bls_pubkeys=tuple(
            bytes(value.get_g1()) for value in recovery_private_keys
        ),
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    )
    return AuthorityFixture(
        authority=authority,
        daily_private_keys=daily_private_keys,  # type: ignore[arg-type]
        recovery_private_keys=recovery_private_keys,  # type: ignore[arg-type]
        identity_coin_ids=tuple(  # type: ignore[arg-type]
            bytes32(bytes([0x51 + slot]) * 32) for slot in range(3)
        ),
        authority_coin_id=bytes32(b"\x61" * 32),
    )


def test_current_identity_constructor_matches_genesis_identity() -> None:
    fixture = _fixture()
    for identity in fixture.authority.identity_vaults:
        rebuilt = build_admin_identity_vault(
            slot=identity.slot,
            launcher_id=identity.launcher_id,
            authority_launcher_id=fixture.authority.authority_launcher_id,
            network="testnet11",
            daily_compressed_pubkey=identity.daily_compressed_pubkey,
            recovery_bls_pubkey=identity.recovery_bls_pubkey,
        )
        assert rebuilt.custody_hash == identity.custody_hash
        assert rebuilt.custody_reveal == identity.custody_reveal
        assert rebuilt.full_puzzle_hash == identity.full_puzzle_hash


def _eip_member_solution(
    private_key: keys.PrivateKey,
    coin_id: bytes32,
    delegated_puzzle_hash: bytes32,
) -> Program:
    prefix = eip712_prefix_and_domain_separator(
        TESTNET11_GENESIS_CHALLENGE
    )
    digest = eip712_hash_to_sign(
        prefix,
        coin_id,
        delegated_puzzle_hash,
    )
    signature = private_key.sign_msg_hash(digest).to_bytes()[:64]
    return Program.to([coin_id, digest, signature])


def _conditions(result: Program) -> list[Program]:
    return list(result.as_iter())


def _condition(result: Program, opcode: int) -> Program:
    for condition in result.as_iter():
        if condition.first().as_int() == opcode:
            return condition
    raise AssertionError(f"condition {opcode} not found")


def _condition_values(result: Program, opcode: int) -> list[list[bytes]]:
    return [
        condition.as_python()
        for condition in result.as_iter()
        if condition.first().as_int() == opcode
    ]


def _transition(
    fixture: AuthorityFixture,
    *,
    slot: int,
    kind: int,
    replacement_daily_key: keys.PrivateKey | None = None,
    replacement_recovery_key: PrivateKey | None = None,
) -> tuple[IdentityVaultTransition, keys.PrivateKey]:
    current_daily = fixture.daily_private_keys[slot]
    resolved_daily = replacement_daily_key or keys.PrivateKey(
        bytes([0x71 + slot]) * 32
    )
    if kind == PENDING_RECOVERY_KIT:
        resolved_daily = current_daily
        if replacement_recovery_key is None:
            replacement_recovery_key = AugSchemeMPL.key_gen(
                bytes([0x75 + slot]) * 32
            )
    transition = build_identity_vault_transition(
        identity=fixture.authority.identity_vaults[slot],
        authority_current_inner_puzzle=fixture.authority.inner_puzzle,
        network="testnet11",
        kind=kind,
        intent_hash=bytes32(bytes([0x81 + slot + kind]) * 32),
        current_identity_coin_id=fixture.identity_coin_ids[slot],
        replacement_daily_compressed_pubkey=_compressed_pubkey(
            resolved_daily
        ),
        replacement_recovery_bls_pubkey=(
            bytes(replacement_recovery_key.get_g1())
            if replacement_recovery_key is not None
            else None
        ),
    )
    return transition, resolved_daily


def _run_approval_identity(
    fixture: AuthorityFixture,
    transition: IdentityVaultTransition,
    slot: int,
) -> Program:
    identity = fixture.authority.identity_vaults[slot]
    action = build_identity_approval_action(
        identity=identity,
        transition=transition,
    )
    solution = build_identity_approval_solution(
        identity=identity,
        transition=transition,
        current_identity_coin_id=fixture.identity_coin_ids[slot],
        daily_member_solution=_eip_member_solution(
            fixture.daily_private_keys[slot],
            fixture.identity_coin_ids[slot],
            bytes32(action.get_tree_hash()),
        ),
    )
    return identity.custody_reveal.run(solution, flags=RUN_FLAGS)


def _run_authority_prepare(
    fixture: AuthorityFixture,
    transition: IdentityVaultTransition,
    replacement_private_key: keys.PrivateKey,
    *,
    coadmin_slot: int | None = None,
) -> tuple[Program, tuple[int, int]]:
    mips = build_authority_prepare_mips_spend(
        authority=fixture.authority,
        transition=transition,
        current_identities=fixture.authority.identity_vaults,
        current_identity_coin_ids=fixture.identity_coin_ids,
        coadmin_slot=coadmin_slot,
    )
    replacement_solution = _eip_member_solution(
        replacement_private_key,
        fixture.authority_coin_id,
        transition.prepare_binding_hash,
    )
    solution = build_prepare_solution(
        transition=transition,
        my_amount=AUTHORITY_LAUNCHER_AMOUNT,
        new_authority_version=2,
        mips_reveal=mips.reveal,
        mips_solution=mips.solution,
        replacement_member_solution=replacement_solution,
        identity_records=mips.identity_records,
    )
    return (
        fixture.authority.inner_puzzle.run(solution, flags=RUN_FLAGS),
        mips.selected_slots,
    )


def _singleton_spend(
    *,
    coin,
    launcher_id: bytes32,
    inner_puzzle: Program,
    launcher_spend: CoinSpend,
    amount: int,
    inner_solution: Program,
) -> CoinSpend:
    return make_spend(
        coin,
        puzzle_for_singleton(launcher_id, inner_puzzle),
        solution_for_singleton(
            lineage_proof_for_coinsol(launcher_spend),
            uint64(amount),
            inner_solution,
        ),
    )


@pytest.mark.asyncio
async def test_routine_rotation_bundle_requires_exact_authority_and_identities() -> None:
    daily_private_keys = tuple(
        keys.PrivateKey(bytes([value]) * 32)
        for value in (0x11, 0x22, 0x33)
    )
    recovery_private_keys = tuple(
        AugSchemeMPL.key_gen(bytes([value]) * 32)
        for value in (0x41, 0x42, 0x43)
    )

    async with SpendSim.managed(None, defaults=DEFAULT_CONSTANTS) as sim:
        client = SimClient(sim)
        acs = Program.to(1)
        acs_hash = bytes32(acs.get_tree_hash())
        await sim.farm_block(acs_hash)
        records = await client.get_coin_records_by_puzzle_hash(
            acs_hash,
            include_spent_coins=False,
        )
        parent = records[0].coin
        authority = build_genesis_admin_authority_v3(
            parent_coin_id=bytes32(parent.name()),
            network="testnet11",
            daily_compressed_pubkeys=tuple(
                _compressed_pubkey(value) for value in daily_private_keys
            ),
            recovery_bls_pubkeys=tuple(
                bytes(value.get_g1()) for value in recovery_private_keys
            ),
            source_manifest_hash=SOURCE_MANIFEST_HASH,
        )
        launch_targets = (
            (
                authority.authority_launcher_id,
                authority.inner_puzzle,
                AUTHORITY_LAUNCHER_AMOUNT,
            ),
            *(
                (
                    identity.launcher_id,
                    identity.custody_reveal,
                    identity.launcher_amount,
                )
                for identity in authority.identity_vaults
            ),
        )
        parent_conditions: list[Program] = []
        launcher_spends: list[CoinSpend] = []
        for launcher_id, inner, amount in launch_targets:
            conditions, launcher_spend = launch_conditions_and_coinsol(
                parent,
                inner,
                [],
                uint64(amount),
            )
            assert bytes32(launcher_spend.coin.name()) == launcher_id
            parent_conditions.extend(conditions)
            launcher_spends.append(launcher_spend)
        parent_conditions.append(
            Program.to(
                [
                    51,
                    acs_hash,
                    int(parent.amount) - ADMIN_AUTHORITY_FUNDING_AMOUNT,
                ]
            )
        )
        launch_bundle = SpendBundle(
            [
                make_spend(parent, acs, Program.to(parent_conditions)),
                *launcher_spends,
            ],
            G2Element(),
        )
        launch_status, launch_error = await client.push_tx(launch_bundle)
        assert launch_error is None
        assert launch_status == MempoolInclusionStatus.SUCCESS
        await sim.farm_block()

        authority_coin = compute_additions(launcher_spends[0])[0]
        identity_coins = tuple(
            compute_additions(spend)[0]
            for spend in launcher_spends[1:]
        )
        fixture = AuthorityFixture(
            authority=authority,
            daily_private_keys=daily_private_keys,  # type: ignore[arg-type]
            recovery_private_keys=recovery_private_keys,  # type: ignore[arg-type]
            identity_coin_ids=tuple(  # type: ignore[arg-type]
                bytes32(coin.name()) for coin in identity_coins
            ),
            authority_coin_id=bytes32(authority_coin.name()),
        )
        transition, replacement_key = _transition(
            fixture,
            slot=1,
            kind=PENDING_ROUTINE,
        )
        mips = build_authority_prepare_mips_spend(
            authority=authority,
            transition=transition,
            current_identities=authority.identity_vaults,
            current_identity_coin_ids=fixture.identity_coin_ids,
        )
        authority_inner_solution = build_prepare_solution(
            transition=transition,
            my_amount=AUTHORITY_LAUNCHER_AMOUNT,
            new_authority_version=2,
            mips_reveal=mips.reveal,
            mips_solution=mips.solution,
            replacement_member_solution=_eip_member_solution(
                replacement_key,
                fixture.authority_coin_id,
                transition.prepare_binding_hash,
            ),
            identity_records=mips.identity_records,
        )
        owner_identity = authority.identity_vaults[0]
        owner_action = build_identity_approval_action(
            identity=owner_identity,
            transition=transition,
        )
        owner_inner_solution = build_identity_approval_solution(
            identity=owner_identity,
            transition=transition,
            current_identity_coin_id=fixture.identity_coin_ids[0],
            daily_member_solution=_eip_member_solution(
                daily_private_keys[0],
                fixture.identity_coin_ids[0],
                bytes32(owner_action.get_tree_hash()),
            ),
        )
        target_identity = authority.identity_vaults[1]
        target_inner_solution = build_routine_identity_prepare_solution(
            identity=target_identity,
            transition=transition,
            daily_member_solution=_eip_member_solution(
                daily_private_keys[1],
                fixture.identity_coin_ids[1],
                bytes32(transition.prepare_delegated_puzzle.get_tree_hash()),
            ),
        )

        authority_spend = _singleton_spend(
            coin=authority_coin,
            launcher_id=authority.authority_launcher_id,
            inner_puzzle=authority.inner_puzzle,
            launcher_spend=launcher_spends[0],
            amount=AUTHORITY_LAUNCHER_AMOUNT,
            inner_solution=authority_inner_solution,
        )
        owner_spend = _singleton_spend(
            coin=identity_coins[0],
            launcher_id=owner_identity.launcher_id,
            inner_puzzle=owner_identity.custody_reveal,
            launcher_spend=launcher_spends[1],
            amount=owner_identity.launcher_amount,
            inner_solution=owner_inner_solution,
        )
        target_spend = _singleton_spend(
            coin=identity_coins[1],
            launcher_id=target_identity.launcher_id,
            inner_puzzle=target_identity.custody_reveal,
            launcher_spend=launcher_spends[2],
            amount=target_identity.launcher_amount,
            inner_solution=target_inner_solution,
        )

        no_authority_status, no_authority_error = await client.push_tx(
            SpendBundle([owner_spend, target_spend], G2Element())
        )
        assert no_authority_status != MempoolInclusionStatus.SUCCESS
        assert no_authority_error is not None

        no_owner_status, no_owner_error = await client.push_tx(
            SpendBundle([authority_spend, target_spend], G2Element())
        )
        assert no_owner_status != MempoolInclusionStatus.SUCCESS
        assert no_owner_error is not None

        complete_status, complete_error = await client.push_tx(
            SpendBundle(
                [authority_spend, owner_spend, target_spend],
                G2Element(),
            )
        )
        assert complete_error is None, (
            f"valid Authority V3 rotation rejected: {complete_error}"
        )
        assert complete_status == MempoolInclusionStatus.SUCCESS


def test_genesis_fixes_owner_plus_one_and_exact_launcher_funding() -> None:
    fixture = _fixture()
    authority = fixture.authority

    assert ADMIN_AUTHORITY_FUNDING_AMOUNT == 16
    assert AUTHORITY_LAUNCHER_AMOUNT == 1
    assert IDENTITY_LAUNCHER_AMOUNTS == (3, 5, 7)
    assert len(set(authority_v3_launcher_ids(bytes32(b"\x99" * 32)))) == 4
    assert authority.operational_policy.m == 2
    assert len(authority.operational_policy.members) == 2
    assert authority.operational_policy.members[1].puzzle.m == 1
    assert len(authority.operational_policy.members[1].puzzle.members) == 2

    for slot, policy in enumerate(authority.lost_recovery_policies):
        assert policy.m == 2
        assert len(policy.members) == 2
        assert all(
            member.puzzle.launcher_id
            != authority.identity_vaults[slot].launcher_id
            for member in policy.members
        )


def test_inner_parser_round_trips_identity_custody_and_manifest() -> None:
    fixture = _fixture()
    parsed = parse_inner_puzzle(fixture.authority.inner_puzzle)

    assert parsed.authority_launcher_id == (
        fixture.authority.authority_launcher_id
    )
    assert parsed.operational_root_hash == (
        fixture.authority.operational_root_hash
    )
    assert parsed.lost_recovery_root_hashes == (
        fixture.authority.lost_recovery_root_hashes
    )
    assert parsed.identity_launcher_ids == tuple(
        identity.launcher_id
        for identity in fixture.authority.identity_vaults
    )
    assert parsed.state.current_identity_custody_hashes == tuple(
        identity.custody_hash
        for identity in fixture.authority.identity_vaults
    )
    assert parsed.source_manifest_hash == SOURCE_MANIFEST_HASH
    assert parsed.state.pending_kind == 0


def test_routine_rotation_executes_owner_target_and_replacement_acceptance() -> None:
    fixture = _fixture()
    transition, replacement_key = _transition(
        fixture,
        slot=1,
        kind=PENDING_ROUTINE,
    )
    authority_result, selected_slots = _run_authority_prepare(
        fixture,
        transition,
        replacement_key,
    )

    assert selected_slots == (0, 1)
    assert _condition(authority_result, 51).rest().first().as_atom() == (
        bytes32(transition.authority_pending_inner_puzzle.get_tree_hash())
    )
    assert len(_condition_values(authority_result, 66)) == 2
    assert len(_condition_values(authority_result, 64)) >= 2

    owner_result = _run_approval_identity(fixture, transition, 0)
    target = fixture.authority.identity_vaults[1]
    target_solution = build_routine_identity_prepare_solution(
        identity=target,
        transition=transition,
        daily_member_solution=_eip_member_solution(
            fixture.daily_private_keys[1],
            fixture.identity_coin_ids[1],
            bytes32(transition.prepare_delegated_puzzle.get_tree_hash()),
        ),
    )
    target_result = target.custody_reveal.run(
        target_solution,
        flags=RUN_FLAGS,
    )

    assert _condition(owner_result, 51).rest().first().as_atom() == (
        fixture.authority.identity_vaults[0].custody_hash
    )
    assert _condition(target_result, 51).rest().first().as_atom() == (
        transition.intermediate_custody_hash
    )
    authority_sends = _condition_values(authority_result, 66)
    identity_receives = (
        _condition_values(owner_result, 67)
        + _condition_values(target_result, 67)
    )
    assert sorted(value[2] for value in authority_sends) == sorted(
        value[2] for value in identity_receives
    )


def test_lost_key_prepare_requires_both_other_identities_and_exact_output() -> None:
    fixture = _fixture()
    transition, replacement_key = _transition(
        fixture,
        slot=1,
        kind=PENDING_LOST,
    )
    authority_result, selected_slots = _run_authority_prepare(
        fixture,
        transition,
        replacement_key,
    )

    assert selected_slots == (0, 2)
    owner_result = _run_approval_identity(fixture, transition, 0)
    coadmin_result = _run_approval_identity(fixture, transition, 2)
    target = fixture.authority.identity_vaults[1]
    target_result = target.custody_reveal.run(
        build_lost_recovery_identity_solution(
            identity=target,
            transition=transition,
        ),
        flags=RUN_FLAGS,
    )

    create = _condition(target_result, 51)
    assert create.rest().first().as_atom() == (
        transition.intermediate_custody_hash
    )
    assert create.rest().rest().first().as_int() == target.launcher_amount
    assert _condition(target_result, 60).rest().first().as_atom() == (
        transition.target_prepare_message
    )
    assert len(_condition_values(authority_result, 66)) == 2
    assert _condition_values(owner_result, 67)
    assert _condition_values(coadmin_result, 67)


def test_lost_key_announcement_wrapper_rejects_mismatch_and_duplicates() -> None:
    output_hash = bytes32(b"\xa1" * 32)
    amount = 5
    expected_message = bytes32(
        Program.to([3, output_hash, amount]).get_tree_hash()
    )
    wrapper = admin_identity_prepare_announcement_v1_mod()
    valid = Program.to(
        [[51, output_hash, amount], [60, expected_message], [70, b"x" * 32]]
    )
    assert wrapper.run(Program.to([valid]))

    with pytest.raises(Exception):
        wrapper.run(
            Program.to(
                [
                    Program.to(
                        [
                            [51, output_hash, amount],
                            [60, bytes32(b"\xff" * 32)],
                        ]
                    )
                ]
            )
        )
    with pytest.raises(Exception):
        wrapper.run(
            Program.to(
                [
                    Program.to(
                        [
                            [51, output_hash, amount],
                            [60, expected_message],
                            [60, expected_message],
                        ]
                    )
                ]
            )
        )


def test_old_daily_key_can_veto_only_exact_pending_replacement() -> None:
    fixture = _fixture()
    transition, _ = _transition(
        fixture,
        slot=1,
        kind=PENDING_ROUTINE,
    )
    authority_result = transition.authority_pending_inner_puzzle.run(
        build_cancel_solution(
            my_amount=AUTHORITY_LAUNCHER_AMOUNT,
            new_authority_version=3,
        ),
        flags=RUN_FLAGS,
    )
    old_daily_solution = _eip_member_solution(
        fixture.daily_private_keys[1],
        transition.intermediate_identity_coin_id,
        transition.cancel_identity_action_hash,
    )
    identity_result = transition.intermediate_custody_reveal.run(
        build_identity_cancel_solution(
            identity=fixture.authority.identity_vaults[1],
            transition=transition,
            daily_member_solution=old_daily_solution,
        ),
        flags=RUN_FLAGS,
    )

    assert _condition(identity_result, 51).rest().first().as_atom() == (
        transition.original_custody_hash
    )
    assert _condition(identity_result, 60).rest().first().as_atom() == (
        transition.cancel_message
    )
    authority_send = _condition(authority_result, 66).as_python()
    identity_receive = _condition(identity_result, 67).as_python()
    identity_send = _condition(identity_result, 66).as_python()
    authority_receive = _condition(authority_result, 67).as_python()
    assert authority_send[1:3] == identity_receive[1:3]
    assert authority_send[3] == transition.intermediate_full_puzzle_hash
    assert (
        identity_receive[3]
        == transition.authority_pending_full_puzzle_hash
    )
    assert identity_send[1:3] == authority_receive[1:3]
    assert identity_send[3] == transition.authority_pending_full_puzzle_hash
    assert authority_receive[3] == transition.intermediate_full_puzzle_hash

    forged = build_identity_action_puzzle(
        action_tag=4,
        output_custody_hash=transition.final_custody_hash,
        authority_full_puzzle_hash=(
            transition.authority_pending_full_puzzle_hash
        ),
        authority_delegated_puzzle_hash=(
            transition.authority_cancel_action_hash
        ),
        authority_announcement_message=None,
        coin_announcement_message=transition.cancel_message,
        identity_full_puzzle_hash=(
            transition.intermediate_full_puzzle_hash
        ),
        amount=fixture.authority.identity_vaults[1].launcher_amount,
    )
    assert bytes32(forged.get_tree_hash()) != transition.cancel_identity_action_hash
    assert authority_send[2] == transition.cancel_identity_action_hash


@pytest.mark.parametrize(
    ("kind", "expected_delay"),
    (
        (PENDING_ROUTINE, ROUTINE_DELAY_SECONDS),
        (PENDING_LOST, LOST_KEY_DELAY_SECONDS),
    ),
)
def test_completion_is_permissionless_delayed_and_exact(
    kind: int,
    expected_delay: int,
) -> None:
    fixture = _fixture()
    transition, _ = _transition(fixture, slot=0, kind=kind)
    identity_result = transition.intermediate_custody_reveal.run(
        build_identity_finish_solution(transition),
        flags=RUN_FLAGS,
    )
    authority_result = transition.authority_pending_inner_puzzle.run(
        build_complete_solution(
            my_amount=AUTHORITY_LAUNCHER_AMOUNT,
            new_authority_version=3,
        ),
        flags=RUN_FLAGS,
    )

    assert _condition(identity_result, 51).rest().first().as_atom() == (
        transition.final_custody_hash
    )
    assert _condition(identity_result, 80).rest().first().as_int() == (
        expected_delay
    )
    assert _condition(authority_result, 80).rest().first().as_int() == (
        expected_delay
    )
    expected_announcement_id = hashlib.sha256(
        transition.intermediate_identity_coin_id
        + transition.completion_message
    ).digest()
    assert _condition(authority_result, 61).rest().first().as_atom() == (
        expected_announcement_id
    )


def test_pending_change_freezes_operational_spends_and_second_prepare() -> None:
    fixture = _fixture()
    transition, _ = _transition(
        fixture,
        slot=2,
        kind=PENDING_ROUTINE,
    )
    dummy = Program.to((1, [[1, b"not reached"]]))
    with pytest.raises(Exception):
        transition.authority_pending_inner_puzzle.run(
            build_operational_solution(
                my_amount=AUTHORITY_LAUNCHER_AMOUNT,
                new_authority_version=3,
                mips_reveal=dummy,
                mips_solution=Program.to(None),
                authority_delegated_puzzle=dummy,
                identity_records=(
                    (0, fixture.identity_coin_ids[0]),
                    (2, transition.intermediate_identity_coin_id),
                ),
            ),
            flags=RUN_FLAGS,
        )
    with pytest.raises(ValueError, match="already pending"):
        build_identity_vault_transition(
            identity=fixture.authority.identity_vaults[0],
            authority_current_inner_puzzle=(
                transition.authority_pending_inner_puzzle
            ),
            network="testnet11",
            kind=PENDING_ROUTINE,
            intent_hash=bytes32(b"\xcc" * 32),
            current_identity_coin_id=fixture.identity_coin_ids[0],
            replacement_daily_compressed_pubkey=_compressed_pubkey(
                keys.PrivateKey(b"\xdd" * 32)
            ),
        )


def test_recovery_kit_rotation_keeps_daily_key_and_uses_24_hour_delay() -> None:
    fixture = _fixture()
    transition, current_daily = _transition(
        fixture,
        slot=2,
        kind=PENDING_RECOVERY_KIT,
    )

    assert transition.replacement_daily_compressed_pubkey == (
        _compressed_pubkey(current_daily)
    )
    assert transition.replacement_recovery_bls_pubkey != (
        fixture.authority.identity_vaults[2].recovery_bls_pubkey
    )
    assert transition.delay_seconds == ROUTINE_DELAY_SECONDS
    assert transition.authority_pending_state.pending_kind == (
        PENDING_RECOVERY_KIT
    )

    with pytest.raises(ValueError, match="requires a replacement"):
        build_identity_vault_transition(
            identity=fixture.authority.identity_vaults[2],
            authority_current_inner_puzzle=fixture.authority.inner_puzzle,
            network="testnet11",
            kind=PENDING_RECOVERY_KIT,
            intent_hash=bytes32(b"\xee" * 32),
            current_identity_coin_id=fixture.identity_coin_ids[2],
            replacement_daily_compressed_pubkey=_compressed_pubkey(
                current_daily
            ),
        )


def test_cancel_and_completion_messages_bind_manifest_and_replacement() -> None:
    fixture = _fixture()
    transition, _ = _transition(
        fixture,
        slot=0,
        kind=PENDING_LOST,
    )
    state = transition.authority_pending_state

    assert compute_cancel_message(
        state=state,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    ) == transition.cancel_message
    assert compute_completion_message(
        state=state,
        source_manifest_hash=SOURCE_MANIFEST_HASH,
    ) == transition.completion_message
    assert compute_cancel_message(
        state=state,
        source_manifest_hash=bytes32(b"\xff" * 32),
    ) != transition.cancel_message


def test_both_coadmins_without_owner_cannot_satisfy_operational_root() -> None:
    fixture = _fixture()
    policy = fixture.authority.operational_policy
    coadmin_container = policy.members[1]
    coadmin_policy = coadmin_container.puzzle
    proven: dict[bytes32, ProvenSpend] = {}
    for branch, slot in zip(coadmin_policy.members, (1, 2), strict=True):
        solution = branch.solve(
            [],
            [],
            Program.to(
                [
                    fixture.authority.identity_vaults[slot].custody_hash,
                    fixture.authority.identity_vaults[slot].launcher_amount,
                ]
            ),
        )
        proven[branch.puzzle_hash(_top_level=False)] = ProvenSpend(
            puzzle_reveal=branch.puzzle_reveal(_top_level=False),
            solution=solution,
        )

    with pytest.raises((AssertionError, KeyError)):
        policy.solve(proven)


def test_state_rejects_missing_custody_and_noncanonical_pending_values() -> None:
    with pytest.raises(ValueError, match="three nonzero"):
        AdminAuthorityV3State().validate()

    fixture = _fixture()
    custodies = tuple(
        identity.custody_hash
        for identity in fixture.authority.identity_vaults
    )
    with pytest.raises(ValueError, match="canonical"):
        AdminAuthorityV3State(
            current_identity_custody_hashes=custodies,  # type: ignore[arg-type]
            pending_slot=1,
        ).validate()
    with pytest.raises(ValueError, match="delay"):
        AdminAuthorityV3State(
            current_identity_custody_hashes=custodies,  # type: ignore[arg-type]
            pending_kind=PENDING_LOST,
            pending_slot=0,
            pending_intent_hash=bytes32(b"\xd1" * 32),
            pending_identity_coin_id=bytes32(b"\xd2" * 32),
            pending_original_custody_hash=custodies[0],
            pending_replacement_custody_hash=bytes32(b"\xd3" * 32),
            pending_replacement_member_hash=bytes32(b"\xd4" * 32),
            pending_delay_seconds=ROUTINE_DELAY_SECONDS,
        ).validate()
