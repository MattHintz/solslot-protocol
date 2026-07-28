"""Driver for :mod:`protocol_statutes_inner_v1.clsp`."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles import load_puzzle
from solslot_puzzles.protocol_statutes_v1 import (
    BridgeRoute,
    CollectionStatute,
    LiquidityVenue,
    MutationKind,
    OracleRound,
    PermanentRules,
    ProtocolParameters,
    ScopedPause,
    StatuteMutation,
    StatutesState,
    keyed_root,
)


_MOD: Program | None = None


def protocol_statutes_inner_mod() -> Program:
    global _MOD
    if _MOD is None:
        _MOD = load_puzzle("protocol_statutes_inner_v1.clsp")
    return _MOD


def protocol_statutes_inner_mod_hash() -> bytes32:
    return bytes32(protocol_statutes_inner_mod().get_tree_hash())


def make_inner_puzzle(
    *,
    singleton_struct: Program,
    governance_singleton_struct: Program,
    permanent_rules: PermanentRules,
    state: StatutesState,
) -> Program:
    permanent_rules.validate()
    state.validate()
    if state.permanent_rules_hash != permanent_rules.commitment_hash:
        raise ValueError("state does not match the permanent rules")
    return protocol_statutes_inner_mod().curry(
        protocol_statutes_inner_mod_hash(),
        singleton_struct,
        governance_singleton_struct,
        permanent_rules.sgt_tail_hash,
        permanent_rules.sgt_total_supply,
        permanent_rules.sols_tail_hash,
        permanent_rules.zkpassport_policy_hash,
        permanent_rules.protocol_treasury_puzzle_hash,
        permanent_rules.network_id,
        state.parameters_root,
        state.collections_root,
        state.oracle_root,
        state.routes_root,
        state.liquidity_root,
        state.pauses_root,
        state.registry_version,
    )


def make_inner_puzzle_hash(
    *,
    singleton_struct: Program,
    governance_singleton_struct: Program,
    permanent_rules: PermanentRules,
    state: StatutesState,
) -> bytes32:
    return bytes32(
        make_inner_puzzle(
            singleton_struct=singleton_struct,
            governance_singleton_struct=governance_singleton_struct,
            permanent_rules=permanent_rules,
            state=state,
        ).get_tree_hash()
    )


def _entry_program_values(
    entries: ProtocolParameters
    | Sequence[CollectionStatute]
    | Sequence[OracleRound]
    | Sequence[BridgeRoute]
    | Sequence[LiquidityVenue]
    | Sequence[ScopedPause],
) -> list[object]:
    if isinstance(entries, ProtocolParameters):
        return list(entries.as_tuple())
    return [entry.as_program_value() for entry in entries]


def _value_program_value(
    value: int
    | CollectionStatute
    | OracleRound
    | BridgeRoute
    | LiquidityVenue
    | ScopedPause,
) -> object:
    return value if isinstance(value, int) else value.as_program_value()


@dataclass(frozen=True)
class EvidenceSpend:
    inner_solution: Program
    expected_evidence_message: bytes


@dataclass(frozen=True)
class UpdateSpend:
    inner_solution: Program
    next_inner_puzzle_hash: bytes32
    governance_message_body: bytes


@dataclass(frozen=True)
class SolsEvidenceSpend:
    inner_solution: Program
    collection: CollectionStatute
    pause: ScopedPause | None
    expected_evidence_message: bytes


@dataclass(frozen=True)
class GovernanceEvidenceSpend:
    inner_solution: Program
    expected_evidence_message: bytes


def evidence_message(
    *,
    kind: MutationKind,
    key: int | bytes32,
    value: object,
    root: bytes32,
    state: StatutesState,
) -> bytes:
    message_hash = Program.to(
        [
            b"STEV",
            int(kind),
            key,
            value,
            root,
            state.registry_version,
            state.permanent_rules_hash,
        ]
    ).get_tree_hash()
    return b"S" + bytes(message_hash)


def governance_evidence_message(parameters: ProtocolParameters) -> bytes:
    parameters.validate()
    return b"S" + bytes(
        Program.to([b"GOVE", list(parameters.as_tuple())]).get_tree_hash()
    )


def build_governance_evidence_spend(
    *,
    my_id: bytes32,
    my_inner_puzzle_hash: bytes32,
    my_amount: int,
    parameters: ProtocolParameters,
) -> GovernanceEvidenceSpend:
    parameters.validate()
    if my_amount <= 0 or my_amount % 2 == 0:
        raise ValueError("statutes singleton amount must be a positive odd integer")
    return GovernanceEvidenceSpend(
        inner_solution=Program.to(
            [
                my_id,
                my_inner_puzzle_hash,
                my_amount,
                4,
                [list(parameters.as_tuple())],
            ]
        ),
        expected_evidence_message=governance_evidence_message(parameters),
    )


def build_evidence_spend(
    *,
    my_id: bytes32,
    my_inner_puzzle_hash: bytes32,
    my_amount: int,
    state: StatutesState,
    kind: MutationKind,
    key: int | bytes32,
    entries: ProtocolParameters
    | Sequence[CollectionStatute]
    | Sequence[OracleRound]
    | Sequence[BridgeRoute]
    | Sequence[LiquidityVenue]
    | Sequence[ScopedPause],
    value: int
    | CollectionStatute
    | OracleRound
    | BridgeRoute
    | LiquidityVenue
    | ScopedPause,
) -> EvidenceSpend:
    if my_amount <= 0 or my_amount % 2 == 0:
        raise ValueError("statutes singleton amount must be a positive odd integer")
    root = {
        MutationKind.PARAMETER: state.parameters_root,
        MutationKind.COLLECTION: state.collections_root,
        MutationKind.ORACLE: state.oracle_root,
        MutationKind.ROUTE: state.routes_root,
        MutationKind.LIQUIDITY: state.liquidity_root,
        MutationKind.PAUSE: state.pauses_root,
    }[kind]
    value_program = _value_program_value(value)
    return EvidenceSpend(
        inner_solution=Program.to(
            [
                my_id,
                my_inner_puzzle_hash,
                my_amount,
                1,
                [int(kind), key, _entry_program_values(entries)],
            ]
        ),
        expected_evidence_message=evidence_message(
            kind=kind,
            key=key,
            value=value_program,
            root=root,
            state=state,
        ),
    )


def sols_evidence_message(
    *,
    consumer_coin_id: bytes32,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    parameters: ProtocolParameters,
    state: StatutesState,
) -> bytes:
    pause_result: list[object] = (
        [1, pause.as_program_value()]
        if pause is not None
        else [0, []]
    )
    return b"S" + bytes(
        Program.to(
            [
                b"SOLV",
                consumer_coin_id,
                collection.collection_id,
                list(parameters.as_tuple()),
                collection.as_program_value(),
                pause_result,
                state.parameters_root,
                state.collections_root,
                state.oracle_root,
                state.routes_root,
                state.liquidity_root,
                state.pauses_root,
                state.registry_version,
                state.permanent_rules_hash,
            ]
        ).get_tree_hash()
    )


def build_sols_evidence_spend(
    *,
    my_id: bytes32,
    my_inner_puzzle_hash: bytes32,
    my_amount: int,
    consumer_coin_id: bytes32,
    collection_id: bytes32,
    parameters: ProtocolParameters,
    collections: Sequence[CollectionStatute],
    pauses: Sequence[ScopedPause],
    state: StatutesState,
) -> SolsEvidenceSpend:
    if my_amount <= 0 or my_amount % 2 == 0:
        raise ValueError("statutes singleton amount must be a positive odd integer")
    parameters.validate()
    if bytes32(Program.to(list(parameters.as_tuple())).get_tree_hash()) != (
        state.parameters_root
    ):
        raise ValueError("parameter witness does not match statutes state")
    if keyed_root(collections) != state.collections_root:
        raise ValueError("collection witness does not match statutes state")
    if keyed_root(pauses) != state.pauses_root:
        raise ValueError("pause witness does not match statutes state")

    matching_collections = [
        collection
        for collection in collections
        if collection.collection_id == collection_id
    ]
    if len(matching_collections) != 1:
        raise ValueError("collection must exist exactly once")
    matching_pauses = [
        pause for pause in pauses if pause.scope_id == collection_id
    ]
    if len(matching_pauses) > 1:
        raise ValueError("collection pause must not be duplicated")
    collection = matching_collections[0]
    pause = matching_pauses[0] if matching_pauses else None
    message = sols_evidence_message(
        consumer_coin_id=consumer_coin_id,
        collection=collection,
        pause=pause,
        parameters=parameters,
        state=state,
    )
    return SolsEvidenceSpend(
        inner_solution=Program.to(
            [
                my_id,
                my_inner_puzzle_hash,
                my_amount,
                3,
                [
                    consumer_coin_id,
                    collection_id,
                    list(parameters.as_tuple()),
                    [
                        item.as_program_value()
                        for item in collections
                    ],
                    [item.as_program_value() for item in pauses],
                ],
            ]
        ),
        collection=collection,
        pause=pause,
        expected_evidence_message=message,
    )


def build_update_spend(
    *,
    my_id: bytes32,
    my_inner_puzzle_hash: bytes32,
    my_amount: int,
    singleton_struct: Program,
    governance_singleton_struct: Program,
    permanent_rules: PermanentRules,
    current_state: StatutesState,
    next_state: StatutesState,
    mutation: StatuteMutation,
    current_entries: ProtocolParameters
    | Sequence[CollectionStatute]
    | Sequence[OracleRound]
    | Sequence[BridgeRoute]
    | Sequence[LiquidityVenue]
    | Sequence[ScopedPause],
    governance_inner_puzzle_hash: bytes32,
) -> UpdateSpend:
    if my_amount <= 0 or my_amount % 2 == 0:
        raise ValueError("statutes singleton amount must be a positive odd integer")
    if mutation.old_state_hash != current_state.content_hash:
        raise ValueError("mutation does not bind the current statutes state")
    if mutation.new_state_hash != next_state.content_hash:
        raise ValueError("mutation does not bind the next statutes state")
    if mutation.old_version != current_state.registry_version:
        raise ValueError("mutation old version does not match current state")
    if mutation.new_version != next_state.registry_version:
        raise ValueError("mutation new version does not match next state")
    if next_state.registry_version != current_state.registry_version + 1:
        raise ValueError("statutes version must advance exactly one step")

    return UpdateSpend(
        inner_solution=Program.to(
            [
                my_id,
                my_inner_puzzle_hash,
                my_amount,
                2,
                [
                    int(mutation.kind),
                    mutation.key,
                    mutation.value_program(),
                    _entry_program_values(current_entries),
                    mutation.new_version,
                    governance_inner_puzzle_hash,
                ],
            ]
        ),
        next_inner_puzzle_hash=make_inner_puzzle_hash(
            singleton_struct=singleton_struct,
            governance_singleton_struct=governance_singleton_struct,
            permanent_rules=permanent_rules,
            state=next_state,
        ),
        governance_message_body=mutation.governance_message_body,
    )


__all__ = [
    "EvidenceSpend",
    "GovernanceEvidenceSpend",
    "SolsEvidenceSpend",
    "UpdateSpend",
    "protocol_statutes_inner_mod",
    "protocol_statutes_inner_mod_hash",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "evidence_message",
    "governance_evidence_message",
    "build_evidence_spend",
    "build_governance_evidence_spend",
    "sols_evidence_message",
    "build_sols_evidence_spend",
    "build_update_spend",
]
