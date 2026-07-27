from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32
import pytest

from solslot_puzzles.protocol_statutes_v1 import (
    MAX_EXCHANGE_FEE_BPS,
    BillTag,
    BridgeRoute,
    CollectionStatute,
    MutationKind,
    OracleRound,
    ParameterIndex,
    PermanentRules,
    ProtocolParameters,
    ScopedPause,
    build_parameter_mutation,
    build_record_mutation,
    initial_state,
    keyed_root,
)


def b32(seed: int) -> bytes32:
    return bytes32(bytes([seed]) * 32)


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


def test_permanent_commitment_includes_non_mutable_protocol_rules(
    permanent: PermanentRules,
) -> None:
    values = list(permanent.as_program().as_iter())
    assert len(values) == 15
    assert values[6].as_int() == MAX_EXCHANGE_FEE_BPS
    assert values[7].as_int() == 86_400
    assert [value.as_int() for value in values[8:14]] == [1, 1, 1, 1, 1, 1]
    assert values[14].as_int() == 0
    assert permanent.commitment_hash == permanent.as_program().get_tree_hash()


def test_initial_state_uses_one_registry_and_empty_typed_roots(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(parameters=parameters, permanent_rules=permanent)
    empty_root = Program.to([]).get_tree_hash()
    assert state.parameters_root == Program.to(
        list(parameters.as_tuple())
    ).get_tree_hash()
    assert state.collections_root == empty_root
    assert state.oracle_root == empty_root
    assert state.routes_root == empty_root
    assert state.pauses_root == empty_root
    assert state.registry_version == 1
    assert state.permanent_rules_hash == permanent.commitment_hash


def test_parameter_bill_mutates_exactly_one_index(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(parameters=parameters, permanent_rules=permanent)
    mutation, updated, next_state = build_parameter_mutation(
        state=state,
        current=parameters,
        index=ParameterIndex.NAV_VALIDITY_SECONDS,
        value=172_800,
        permanent_rules=permanent,
    )
    changed = [
        index
        for index, (before, after) in enumerate(
            zip(parameters.as_tuple(), updated.as_tuple(), strict=True)
        )
        if before != after
    ]
    assert changed == [ParameterIndex.NAV_VALIDITY_SECONDS]
    assert mutation.kind == MutationKind.PARAMETER
    assert mutation.bill_tag == BillTag.PARAMETER
    assert mutation.old_state_hash == state.content_hash
    assert mutation.new_state_hash == next_state.content_hash
    assert mutation.new_version == mutation.old_version + 1
    assert mutation.proposal_hash == mutation.bill_program().get_tree_hash()
    assert mutation.governance_message_body.startswith(b"S")
    assert len(mutation.governance_message_body) == 33


@pytest.mark.parametrize(
    ("index", "value", "message"),
    [
        (ParameterIndex.VOTING_WINDOW_SECONDS, 59, "voting_window"),
        (ParameterIndex.QUORUM_BPS, 10_001, "quorum_bps"),
        (ParameterIndex.MIN_PROPOSAL_STAKE, 1_000_001, "fixed SGT supply"),
        (ParameterIndex.NAV_VALIDITY_SECONDS, 31 * 86_400, "nav_validity"),
        (ParameterIndex.ORACLE_MAX_AGE_SECONDS, 3_601, "oracle_max_age"),
        (ParameterIndex.EXCHANGE_FEE_BPS, 101, "1% cap"),
        (ParameterIndex.REWARD_EPOCH_SECONDS, 59, "reward_epoch"),
    ],
)
def test_parameter_hard_bounds_cannot_be_governed_away(
    permanent: PermanentRules,
    index: ParameterIndex,
    value: int,
    message: str,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(parameters=parameters, permanent_rules=permanent)
    with pytest.raises(ValueError, match=message):
        build_parameter_mutation(
            state=state,
            current=parameters,
            index=index,
            value=value,
            permanent_rules=permanent,
        )


def test_fee_split_is_one_inseparable_parameter_group(
    permanent: PermanentRules,
) -> None:
    parameters = ProtocolParameters()
    state = initial_state(parameters=parameters, permanent_rules=permanent)
    with pytest.raises(ValueError, match="fee split"):
        build_parameter_mutation(
            state=state,
            current=parameters,
            index=ParameterIndex.PROTOCOL_FEE_BPS,
            value=40,
            permanent_rules=permanent,
        )


def test_collection_bill_binds_nav_ceiling_and_validity(
    permanent: PermanentRules,
) -> None:
    state = initial_state(
        parameters=ProtocolParameters(),
        permanent_rules=permanent,
    )
    collection = CollectionStatute(
        collection_id=b32(0xA1),
        nav_micro_usd=390_000_000_000,
        allocation_ceiling_micro_usd=400_000_000_000,
        nav_version=1,
        valid_after=1_700_000_000,
        valid_until=1_700_086_400,
        status=1,
    )
    mutation, updated, next_state = build_record_mutation(
        state=state,
        kind=MutationKind.COLLECTION,
        current=(),
        replacement=collection,
    )
    assert updated == (collection,)
    assert next_state.collections_root == keyed_root(updated)
    assert mutation.bill_tag == BillTag.COLLECTION
    assert mutation.key == collection.collection_id
    assert mutation.value == collection


def test_collection_cannot_exceed_governed_allocation_ceiling() -> None:
    with pytest.raises(ValueError, match="allocation ceiling"):
        CollectionStatute(
            collection_id=b32(0xA1),
            nav_micro_usd=401,
            allocation_ceiling_micro_usd=400,
            nav_version=1,
            valid_after=10,
            valid_until=20,
            status=1,
        ).validate()


def test_oracle_bill_requires_two_sources_and_supports_stablecoin_band(
    permanent: PermanentRules,
) -> None:
    state = initial_state(
        parameters=ProtocolParameters(),
        permanent_rules=permanent,
    )
    round_one = OracleRound(
        asset_id=b32(0xB1),
        price_micro_usd=1_000_000,
        observed_at=1_700_000_000,
        valid_until=1_700_000_600,
        round_id=1,
        source_root=b32(0xB2),
        source_count=2,
        haircut_bps=0,
        stable_min_bps=9_800,
        stable_max_bps=10_200,
    )
    mutation, updated, next_state = build_record_mutation(
        state=state,
        kind=MutationKind.ORACLE,
        current=(),
        replacement=round_one,
    )
    assert mutation.bill_tag == BillTag.ORACLE
    assert next_state.oracle_root == keyed_root(updated)
    with pytest.raises(ValueError, match="at least two"):
        OracleRound(
            **{**round_one.__dict__, "source_count": 1}
        ).validate()


def test_route_activation_is_typed_and_exact(
    permanent: PermanentRules,
) -> None:
    state = initial_state(
        parameters=ProtocolParameters(),
        permanent_rules=permanent,
    )
    route = BridgeRoute(
        route_id=b32(0xC1),
        source_chain_id=b32(0xC2),
        destination_chain_id=b32(0xC3),
        asset_id=permanent.sols_tail_hash,
        remote_asset_id=b32(0xC4),
        decimals=3,
        active=0,
    )
    mutation, _, _ = build_record_mutation(
        state=state,
        kind=MutationKind.ROUTE,
        current=(),
        replacement=route,
    )
    assert mutation.bill_tag == BillTag.ROUTE
    assert mutation.value == route


def test_active_pause_must_expire_automatically(
    permanent: PermanentRules,
) -> None:
    state = initial_state(
        parameters=ProtocolParameters(),
        permanent_rules=permanent,
    )
    pause = ScopedPause(
        scope_id=b32(0xD1),
        paused=1,
        expires_at=1_700_003_600,
        reason_hash=b32(0xD2),
    )
    mutation, _, _ = build_record_mutation(
        state=state,
        kind=MutationKind.PAUSE,
        current=(),
        replacement=pause,
    )
    assert mutation.bill_tag == BillTag.PAUSE
    with pytest.raises(ValueError, match="expire"):
        ScopedPause(
            scope_id=b32(0xD1),
            paused=1,
            expires_at=0,
            reason_hash=b32(0xD2),
        ).validate()


def test_witness_roots_and_record_types_fail_closed(
    permanent: PermanentRules,
) -> None:
    state = initial_state(
        parameters=ProtocolParameters(),
        permanent_rules=permanent,
    )
    collection = CollectionStatute(
        collection_id=b32(0xA1),
        nav_micro_usd=1,
        allocation_ceiling_micro_usd=1,
        nav_version=1,
        valid_after=10,
        valid_until=20,
        status=1,
    )
    wrong_state = state.__class__(
        **{**state.__dict__, "collections_root": b32(0xFE)}
    )
    with pytest.raises(ValueError, match="witness"):
        build_record_mutation(
            state=wrong_state,
            kind=MutationKind.COLLECTION,
            current=(),
            replacement=collection,
        )
    with pytest.raises(ValueError, match="record type"):
        build_record_mutation(
            state=state,
            kind=MutationKind.ROUTE,
            current=(),
            replacement=collection,
        )


def test_duplicate_registry_keys_are_rejected() -> None:
    collection = CollectionStatute(
        collection_id=b32(0xA1),
        nav_micro_usd=1,
        allocation_ceiling_micro_usd=1,
        nav_version=1,
        valid_after=10,
        valid_until=20,
        status=1,
    )
    with pytest.raises(ValueError, match="unique"):
        keyed_root((collection, collection))
