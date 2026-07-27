from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_puzzles.protocol_statutes_driver import (
    build_evidence_spend,
    build_governance_evidence_spend,
    build_sols_evidence_spend,
    build_update_spend,
    make_inner_puzzle,
    protocol_statutes_inner_mod,
)
from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    MutationKind,
    ParameterIndex,
    PermanentRules,
    ProtocolParameters,
    ScopedPause,
    build_parameter_mutation,
    build_record_mutation,
    initial_state,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


STATUTES_SINGLETON_STRUCT = Program.to(
    (
        SINGLETON_MOD_HASH,
        (b32(0xA0), SINGLETON_LAUNCHER_HASH),
    )
)
GOVERNANCE_SINGLETON_STRUCT = Program.to(
    (
        SINGLETON_MOD_HASH,
        (b32(0xB0), SINGLETON_LAUNCHER_HASH),
    )
)


@pytest.fixture
def permanent() -> PermanentRules:
    return PermanentRules(
        sgt_tail_hash=b32(0x11),
        sgt_total_supply=1_000_000,
        sols_tail_hash=b32(0x22),
        zkpassport_policy_hash=b32(0x33),
        protocol_treasury_puzzle_hash=b32(0x44),
        network_id=b32(0x55),
    )


def _condition(
    conditions: list[Program],
    opcode: int,
) -> Program:
    return next(
        condition
        for condition in conditions
        if condition.first().as_int() == opcode
    )


def test_statutes_module_compiles() -> None:
    assert len(protocol_statutes_inner_mod().as_bin()) > 0


def test_parameter_update_driver_matches_clvm(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    mutation, _, next_state = build_parameter_mutation(
        state=state,
        current=parameters,
        index=ParameterIndex.NAV_VALIDITY_SECONDS,
        value=172_800,
        permanent_rules=permanent,
    )
    current_inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    artifacts = build_update_spend(
        my_id=b32(0xC0),
        my_inner_puzzle_hash=bytes32(current_inner.get_tree_hash()),
        my_amount=1,
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        current_state=state,
        next_state=next_state,
        mutation=mutation,
        current_entries=parameters,
        governance_inner_puzzle_hash=b32(0xD0),
    )
    conditions = list(current_inner.run(artifacts.inner_solution).as_iter())
    assert len(conditions) == 6

    create_coin = _condition(conditions, 51)
    assert bytes32(create_coin.rest().first().as_atom()) == (
        artifacts.next_inner_puzzle_hash
    )

    receive_message = _condition(conditions, 67)
    assert receive_message.rest().rest().first().as_atom() == (
        artifacts.governance_message_body
    )
    assert artifacts.governance_message_body == mutation.governance_message_body


def test_collection_evidence_driver_matches_clvm(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    initial = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    collection = CollectionStatute(
        collection_id=b32(0xE1),
        nav_micro_usd=390_000_000_000,
        allocation_ceiling_micro_usd=400_000_000_000,
        nav_version=1,
        valid_after=1_700_000_000,
        valid_until=1_700_086_400,
        status=1,
    )
    _, collections, state = build_record_mutation(
        state=initial,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=collection,
    )
    current_inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    artifacts = build_evidence_spend(
        my_id=b32(0xC0),
        my_inner_puzzle_hash=bytes32(current_inner.get_tree_hash()),
        my_amount=1,
        state=state,
        kind=MutationKind.COLLECTION,
        key=collection.collection_id,
        entries=collections,
        value=collection,
    )
    conditions = list(current_inner.run(artifacts.inner_solution).as_iter())
    assert len(conditions) == 5
    announcement = _condition(conditions, 62)
    assert announcement.rest().first().as_atom() == (
        artifacts.expected_evidence_message
    )


def test_governance_evidence_driver_matches_clvm(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    artifacts = build_governance_evidence_spend(
        my_id=b32(0xC0),
        my_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        my_amount=1,
        parameters=parameters,
    )

    conditions = list(inner.run(artifacts.inner_solution).as_iter())
    announcement = _condition(conditions, 62)
    assert announcement.rest().first().as_atom() == (
        artifacts.expected_evidence_message
    )
    create_coin = _condition(conditions, 51)
    assert bytes32(create_coin.rest().first().as_atom()) == inner.get_tree_hash()


def test_sols_batch_evidence_binds_consumer_collection_parameters_and_pause(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    initial = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    collection = CollectionStatute(
        collection_id=b32(0xE1),
        nav_micro_usd=390_000_000_000,
        allocation_ceiling_micro_usd=400_000_000_000,
        nav_version=1,
        valid_after=1_700_000_000,
        valid_until=1_700_086_400,
        status=1,
    )
    _, collections, with_collection = build_record_mutation(
        state=initial,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=collection,
    )
    pause = ScopedPause(
        scope_id=collection.collection_id,
        paused=0,
        expires_at=0,
        reason_hash=b32(0xE2),
    )
    _, pauses, state = build_record_mutation(
        state=with_collection,
        kind=MutationKind.PAUSE,
        current=(),
        replacement=pause,
    )
    inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    artifacts = build_sols_evidence_spend(
        my_id=b32(0xC0),
        my_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        my_amount=1,
        consumer_coin_id=b32(0xC1),
        collection_id=collection.collection_id,
        parameters=parameters,
        collections=collections,
        pauses=pauses,
        state=state,
    )

    conditions = list(inner.run(artifacts.inner_solution).as_iter())
    announcement = _condition(conditions, 62)
    assert announcement.rest().first().as_atom() == (
        artifacts.expected_evidence_message
    )
    assert artifacts.collection == collection
    assert artifacts.pause == pause


def test_sols_batch_evidence_proves_pause_absence(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    initial = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    collection = CollectionStatute(
        collection_id=b32(0xE1),
        nav_micro_usd=100,
        allocation_ceiling_micro_usd=200,
        nav_version=1,
        valid_after=10,
        valid_until=20,
        status=1,
    )
    _, collections, state = build_record_mutation(
        state=initial,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=collection,
    )
    inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    artifacts = build_sols_evidence_spend(
        my_id=b32(0xC0),
        my_inner_puzzle_hash=bytes32(inner.get_tree_hash()),
        my_amount=1,
        consumer_coin_id=b32(0xC1),
        collection_id=collection.collection_id,
        parameters=parameters,
        collections=collections,
        pauses=(),
        state=state,
    )
    conditions = list(inner.run(artifacts.inner_solution).as_iter())
    announcement = _condition(conditions, 62)
    assert announcement.rest().first().as_atom() == (
        artifacts.expected_evidence_message
    )
    assert artifacts.pause is None


def test_clvm_rejects_parameter_fee_above_permanent_cap(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    malicious_solution = Program.to(
        [
            b32(0xC0),
            bytes32(inner.get_tree_hash()),
            1,
            2,
            [
                int(MutationKind.PARAMETER),
                int(ParameterIndex.EXCHANGE_FEE_BPS),
                101,
                list(parameters.as_tuple()),
                2,
                b32(0xD0),
            ],
        ]
    )
    with pytest.raises(Exception):
        inner.run(malicious_solution)


def test_clvm_rejects_multi_entry_collection_rewrite(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    initial = initial_state(
        parameters=parameters,
        permanent_rules=permanent,
    )
    first = CollectionStatute(
        collection_id=b32(0xE1),
        nav_micro_usd=100,
        allocation_ceiling_micro_usd=200,
        nav_version=1,
        valid_after=10,
        valid_until=20,
        status=1,
    )
    _, collections, state = build_record_mutation(
        state=initial,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=first,
    )
    second = CollectionStatute(
        collection_id=b32(0xE2),
        nav_micro_usd=100,
        allocation_ceiling_micro_usd=200,
        nav_version=1,
        valid_after=10,
        valid_until=20,
        status=1,
    )
    mutation, _, next_state = build_record_mutation(
        state=state,
        kind=MutationKind.COLLECTION,
        current=collections,
        replacement=second,
    )
    inner = make_inner_puzzle(
        singleton_struct=STATUTES_SINGLETON_STRUCT,
        governance_singleton_struct=GOVERNANCE_SINGLETON_STRUCT,
        permanent_rules=permanent,
        state=state,
    )
    tampered_current = [
        [
            first.collection_id,
            101,
            first.allocation_ceiling_micro_usd,
            first.nav_version,
            first.valid_after,
            first.valid_until,
            first.status,
        ]
    ]
    malicious_solution = Program.to(
        [
            b32(0xC0),
            bytes32(inner.get_tree_hash()),
            1,
            2,
            [
                int(MutationKind.COLLECTION),
                mutation.key,
                mutation.value_program(),
                tampered_current,
                next_state.registry_version,
                b32(0xD0),
            ],
        ]
    )
    with pytest.raises(Exception):
        inner.run(malicious_solution)
