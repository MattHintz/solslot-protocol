"""Typed state and governance bills for the Solslot statutes registry.

The statutes registry is the single governed source for mutable protocol
parameters, collection NAV, oracle rounds, bridge routes, and scoped pauses.
Permanent protocol rules remain curried into the on-chain puzzle and are not
represented as mutable entries.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Generic, Iterable, Sequence, TypeVar

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32


MAX_BPS = 10_000
MAX_EXCHANGE_FEE_BPS = 100
MIN_ORACLE_SOURCES = 2
UPGRADE_DELAY_SECONDS = 86_400


class ParameterIndex(IntEnum):
    VOTING_WINDOW_SECONDS = 0
    QUORUM_BPS = 1
    MIN_PROPOSAL_STAKE = 2
    NAV_VALIDITY_SECONDS = 3
    ORACLE_MAX_AGE_SECONDS = 4
    EXCHANGE_FEE_BPS = 5
    PROTOCOL_FEE_BPS = 6
    SGT_REWARDS_FEE_BPS = 7
    REWARD_EPOCH_SECONDS = 8


class MutationKind(IntEnum):
    PARAMETER = 1
    COLLECTION = 2
    ORACLE = 3
    ROUTE = 4
    PAUSE = 5


class BillTag(IntEnum):
    PARAMETER = 0x50  # P
    COLLECTION = 0x4E  # N
    ORACLE = 0x4F  # O
    ROUTE = 0x52  # R
    PAUSE = 0x55  # U


BILL_TAG_FOR_KIND = {
    MutationKind.PARAMETER: BillTag.PARAMETER,
    MutationKind.COLLECTION: BillTag.COLLECTION,
    MutationKind.ORACLE: BillTag.ORACLE,
    MutationKind.ROUTE: BillTag.ROUTE,
    MutationKind.PAUSE: BillTag.PAUSE,
}


def _require_bytes32(label: str, value: bytes | bytes32) -> bytes32:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes")
    return bytes32(raw)


def _require_uint64(label: str, value: int, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum or value >= 2**64:
        qualifier = "positive " if positive else ""
        raise ValueError(f"{label} must be a {qualifier}uint64")
    return value


@dataclass(frozen=True)
class PermanentRules:
    sgt_tail_hash: bytes32
    sgt_total_supply: int
    sols_tail_hash: bytes32
    zkpassport_policy_hash: bytes32
    protocol_treasury_puzzle_hash: bytes32
    network_id: bytes32

    def validate(self) -> "PermanentRules":
        _require_bytes32("sgt_tail_hash", self.sgt_tail_hash)
        _require_uint64(
            "sgt_total_supply",
            self.sgt_total_supply,
            positive=True,
        )
        _require_bytes32("sols_tail_hash", self.sols_tail_hash)
        _require_bytes32(
            "zkpassport_policy_hash",
            self.zkpassport_policy_hash,
        )
        _require_bytes32(
            "protocol_treasury_puzzle_hash",
            self.protocol_treasury_puzzle_hash,
        )
        _require_bytes32("network_id", self.network_id)
        return self

    def as_program(self) -> Program:
        self.validate()
        return Program.to(
            [
                self.sgt_tail_hash,
                self.sgt_total_supply,
                self.sols_tail_hash,
                self.zkpassport_policy_hash,
                self.protocol_treasury_puzzle_hash,
                self.network_id,
                MAX_EXCHANGE_FEE_BPS,
                UPGRADE_DELAY_SECONDS,
                1,  # vote conservation
                1,  # replay protection
                1,  # treasury non-withdrawal
                1,  # protocol-only SmartDeed/Sols exchange
                1,  # SmartDeed purchase/redemption requires zkPassport
                1,  # Sols supply is never melted
                0,  # Sols cannot purchase primary SmartDeeds
            ]
        )

    @property
    def commitment_hash(self) -> bytes32:
        return bytes32(self.as_program().get_tree_hash())


@dataclass(frozen=True)
class ProtocolParameters:
    voting_window_seconds: int = 300
    quorum_bps: int = 5_000
    min_proposal_stake: int = 10_000
    nav_validity_seconds: int = 86_400
    oracle_max_age_seconds: int = 600
    exchange_fee_bps: int = 100
    protocol_fee_bps: int = 30
    sgt_rewards_fee_bps: int = 70
    reward_epoch_seconds: int = 86_400

    def validate(
        self,
        *,
        sgt_total_supply: int | None = None,
    ) -> "ProtocolParameters":
        for label, value in zip(
            (
                "voting_window_seconds",
                "quorum_bps",
                "min_proposal_stake",
                "nav_validity_seconds",
                "oracle_max_age_seconds",
                "exchange_fee_bps",
                "protocol_fee_bps",
                "sgt_rewards_fee_bps",
                "reward_epoch_seconds",
            ),
            self.as_tuple(),
            strict=True,
        ):
            _require_uint64(label, value)
        if not 60 <= self.voting_window_seconds <= 30 * 86_400:
            raise ValueError("voting_window_seconds is outside the hard bounds")
        if not 1 <= self.quorum_bps <= MAX_BPS:
            raise ValueError("quorum_bps must be between 1 and 10,000")
        if self.min_proposal_stake <= 0:
            raise ValueError("min_proposal_stake must be positive")
        if (
            sgt_total_supply is not None
            and self.min_proposal_stake > sgt_total_supply
        ):
            raise ValueError("min_proposal_stake exceeds fixed SGT supply")
        if not 60 <= self.nav_validity_seconds <= 30 * 86_400:
            raise ValueError("nav_validity_seconds is outside the hard bounds")
        if not 30 <= self.oracle_max_age_seconds <= 3_600:
            raise ValueError("oracle_max_age_seconds is outside the hard bounds")
        if not 0 <= self.exchange_fee_bps <= MAX_EXCHANGE_FEE_BPS:
            raise ValueError("exchange_fee_bps exceeds the permanent 1% cap")
        if self.protocol_fee_bps + self.sgt_rewards_fee_bps != self.exchange_fee_bps:
            raise ValueError("fee split must equal exchange_fee_bps")
        if not 60 <= self.reward_epoch_seconds <= 30 * 86_400:
            raise ValueError("reward_epoch_seconds is outside the hard bounds")
        return self

    def as_tuple(self) -> tuple[int, ...]:
        return (
            self.voting_window_seconds,
            self.quorum_bps,
            self.min_proposal_stake,
            self.nav_validity_seconds,
            self.oracle_max_age_seconds,
            self.exchange_fee_bps,
            self.protocol_fee_bps,
            self.sgt_rewards_fee_bps,
            self.reward_epoch_seconds,
        )

    @classmethod
    def from_sequence(cls, values: Sequence[int]) -> "ProtocolParameters":
        if len(values) != len(ParameterIndex):
            raise ValueError(
                f"protocol parameters require {len(ParameterIndex)} values"
            )
        return cls(*[int(value) for value in values])

    def mutate(
        self,
        index: ParameterIndex | int,
        value: int,
        *,
        sgt_total_supply: int | None = None,
    ) -> "ProtocolParameters":
        parameter_index = ParameterIndex(index)
        values = list(self.as_tuple())
        values[parameter_index] = _require_uint64("parameter value", value)
        return ProtocolParameters.from_sequence(values).validate(
            sgt_total_supply=sgt_total_supply
        )


@dataclass(frozen=True)
class CollectionStatute:
    collection_id: bytes32
    nav_micro_usd: int
    allocation_ceiling_micro_usd: int
    nav_version: int
    valid_after: int
    valid_until: int
    status: int

    def validate(self) -> "CollectionStatute":
        _require_bytes32("collection_id", self.collection_id)
        _require_uint64("nav_micro_usd", self.nav_micro_usd, positive=True)
        _require_uint64(
            "allocation_ceiling_micro_usd",
            self.allocation_ceiling_micro_usd,
            positive=True,
        )
        if self.nav_micro_usd > self.allocation_ceiling_micro_usd:
            raise ValueError("collection NAV exceeds its allocation ceiling")
        _require_uint64("nav_version", self.nav_version, positive=True)
        _require_uint64("valid_after", self.valid_after)
        _require_uint64("valid_until", self.valid_until, positive=True)
        if self.valid_until <= self.valid_after:
            raise ValueError("collection NAV validity window is empty")
        if self.status not in (1, 2, 3):
            raise ValueError("collection status must be active, paused, or settled")
        return self

    def as_program_value(self) -> list[object]:
        self.validate()
        return [
            self.collection_id,
            self.nav_micro_usd,
            self.allocation_ceiling_micro_usd,
            self.nav_version,
            self.valid_after,
            self.valid_until,
            self.status,
        ]


@dataclass(frozen=True)
class OracleRound:
    asset_id: bytes32
    price_micro_usd: int
    observed_at: int
    valid_until: int
    round_id: int
    source_root: bytes32
    source_count: int
    haircut_bps: int
    stable_min_bps: int
    stable_max_bps: int

    def validate(self) -> "OracleRound":
        _require_bytes32("asset_id", self.asset_id)
        _require_uint64("price_micro_usd", self.price_micro_usd, positive=True)
        _require_uint64("observed_at", self.observed_at)
        _require_uint64("valid_until", self.valid_until, positive=True)
        if self.valid_until <= self.observed_at:
            raise ValueError("oracle validity window is empty")
        _require_uint64("round_id", self.round_id, positive=True)
        _require_bytes32("source_root", self.source_root)
        if self.source_count < MIN_ORACLE_SOURCES:
            raise ValueError("oracle round requires at least two sources")
        _require_uint64("source_count", self.source_count, positive=True)
        if not 0 <= self.haircut_bps <= MAX_BPS:
            raise ValueError("haircut_bps must be between 0 and 10,000")
        if self.stable_min_bps == 0 and self.stable_max_bps == 0:
            return self
        if not 1 <= self.stable_min_bps <= self.stable_max_bps <= 20_000:
            raise ValueError("stablecoin price band is invalid")
        return self

    def as_program_value(self) -> list[object]:
        self.validate()
        return [
            self.asset_id,
            self.price_micro_usd,
            self.observed_at,
            self.valid_until,
            self.round_id,
            self.source_root,
            self.source_count,
            self.haircut_bps,
            self.stable_min_bps,
            self.stable_max_bps,
        ]


@dataclass(frozen=True)
class BridgeRoute:
    route_id: bytes32
    source_chain_id: bytes32
    destination_chain_id: bytes32
    asset_id: bytes32
    remote_asset_id: bytes32
    decimals: int
    active: int

    def validate(self) -> "BridgeRoute":
        for label, value in (
            ("route_id", self.route_id),
            ("source_chain_id", self.source_chain_id),
            ("destination_chain_id", self.destination_chain_id),
            ("asset_id", self.asset_id),
            ("remote_asset_id", self.remote_asset_id),
        ):
            _require_bytes32(label, value)
        if not 0 <= self.decimals <= 18:
            raise ValueError("route decimals must be between 0 and 18")
        if self.active not in (0, 1):
            raise ValueError("route active must be 0 or 1")
        return self

    def as_program_value(self) -> list[object]:
        self.validate()
        return [
            self.route_id,
            self.source_chain_id,
            self.destination_chain_id,
            self.asset_id,
            self.remote_asset_id,
            self.decimals,
            self.active,
        ]


@dataclass(frozen=True)
class ScopedPause:
    scope_id: bytes32
    paused: int
    expires_at: int
    reason_hash: bytes32

    def validate(self) -> "ScopedPause":
        _require_bytes32("scope_id", self.scope_id)
        if self.paused not in (0, 1):
            raise ValueError("paused must be 0 or 1")
        _require_uint64("expires_at", self.expires_at)
        _require_bytes32("reason_hash", self.reason_hash)
        if self.paused == 1 and self.expires_at == 0:
            raise ValueError("an active pause must expire automatically")
        return self

    def as_program_value(self) -> list[object]:
        self.validate()
        return [
            self.scope_id,
            self.paused,
            self.expires_at,
            self.reason_hash,
        ]


KeyedRecord = CollectionStatute | OracleRound | BridgeRoute | ScopedPause
TRecord = TypeVar("TRecord", bound=KeyedRecord)


def _record_key(record: KeyedRecord) -> bytes32:
    if isinstance(record, CollectionStatute):
        return record.collection_id
    if isinstance(record, OracleRound):
        return record.asset_id
    if isinstance(record, BridgeRoute):
        return record.route_id
    return record.scope_id


def _record_program_value(record: KeyedRecord) -> list[object]:
    return record.as_program_value()


def keyed_root(records: Sequence[KeyedRecord]) -> bytes32:
    keys = [_record_key(record) for record in records]
    if len(keys) != len(set(keys)):
        raise ValueError("registry keys must be unique")
    return bytes32(
        Program.to([_record_program_value(record) for record in records]).get_tree_hash()
    )


def upsert_record(
    records: Sequence[TRecord],
    replacement: TRecord,
) -> tuple[TRecord, ...]:
    replacement.validate()
    replacement_key = _record_key(replacement)
    seen = False
    updated: list[TRecord] = []
    for record in records:
        record.validate()
        if _record_key(record) == replacement_key:
            updated.append(replacement)
            seen = True
        else:
            updated.append(record)
    if not seen:
        updated.append(replacement)
    keyed_root(updated)
    return tuple(updated)


@dataclass(frozen=True)
class StatutesState:
    parameters_root: bytes32
    collections_root: bytes32
    oracle_root: bytes32
    routes_root: bytes32
    pauses_root: bytes32
    registry_version: int
    permanent_rules_hash: bytes32

    def validate(self) -> "StatutesState":
        for label, value in (
            ("parameters_root", self.parameters_root),
            ("collections_root", self.collections_root),
            ("oracle_root", self.oracle_root),
            ("routes_root", self.routes_root),
            ("pauses_root", self.pauses_root),
            ("permanent_rules_hash", self.permanent_rules_hash),
        ):
            _require_bytes32(label, value)
        _require_uint64(
            "registry_version",
            self.registry_version,
            positive=True,
        )
        return self

    @property
    def content_hash(self) -> bytes32:
        self.validate()
        return bytes32(
            Program.to(
                [
                    self.parameters_root,
                    self.collections_root,
                    self.oracle_root,
                    self.routes_root,
                    self.pauses_root,
                    self.registry_version,
                    self.permanent_rules_hash,
                ]
            ).get_tree_hash()
        )


@dataclass(frozen=True)
class StatuteMutation(Generic[TRecord]):
    kind: MutationKind
    key: int | bytes32
    value: int | TRecord
    old_root: bytes32
    new_root: bytes32
    old_version: int
    new_version: int
    old_state_hash: bytes32
    new_state_hash: bytes32

    @property
    def bill_tag(self) -> BillTag:
        return BILL_TAG_FOR_KIND[self.kind]

    def value_program(self) -> object:
        if isinstance(self.value, int):
            return self.value
        return _record_program_value(self.value)

    def bill_program(self) -> Program:
        return Program.to(
            [
                int(self.bill_tag),
                self.key,
                self.value_program(),
                self.old_root,
                self.new_root,
                self.old_version,
                self.new_version,
                self.old_state_hash,
                self.new_state_hash,
            ]
        )

    @property
    def proposal_hash(self) -> bytes32:
        return bytes32(self.bill_program().get_tree_hash())

    @property
    def governance_message_hash(self) -> bytes32:
        return bytes32(
            Program.to(
                [
                    b"STAT",
                    int(self.bill_tag),
                    self.key,
                    self.value_program(),
                    self.old_root,
                    self.new_root,
                    self.old_version,
                    self.new_version,
                    self.old_state_hash,
                    self.new_state_hash,
                ]
            ).get_tree_hash()
        )

    @property
    def governance_message_body(self) -> bytes:
        return b"S" + bytes(self.governance_message_hash)


def initial_state(
    *,
    parameters: ProtocolParameters,
    permanent_rules: PermanentRules,
) -> StatutesState:
    permanent_rules.validate()
    parameters.validate(sgt_total_supply=permanent_rules.sgt_total_supply)
    empty_root = bytes32(Program.to([]).get_tree_hash())
    return StatutesState(
        parameters_root=bytes32(
            Program.to(list(parameters.as_tuple())).get_tree_hash()
        ),
        collections_root=empty_root,
        oracle_root=empty_root,
        routes_root=empty_root,
        pauses_root=empty_root,
        registry_version=1,
        permanent_rules_hash=permanent_rules.commitment_hash,
    ).validate()


def _state_with_root(
    state: StatutesState,
    kind: MutationKind,
    root: bytes32,
) -> StatutesState:
    field = {
        MutationKind.PARAMETER: "parameters_root",
        MutationKind.COLLECTION: "collections_root",
        MutationKind.ORACLE: "oracle_root",
        MutationKind.ROUTE: "routes_root",
        MutationKind.PAUSE: "pauses_root",
    }[kind]
    return replace(
        state,
        **{field: root},
        registry_version=state.registry_version + 1,
    ).validate()


def build_parameter_mutation(
    *,
    state: StatutesState,
    current: ProtocolParameters,
    index: ParameterIndex | int,
    value: int,
    permanent_rules: PermanentRules,
) -> tuple[StatuteMutation[KeyedRecord], ProtocolParameters, StatutesState]:
    state.validate()
    permanent_rules.validate()
    if state.permanent_rules_hash != permanent_rules.commitment_hash:
        raise ValueError("permanent rules do not match the statutes state")
    current.validate(sgt_total_supply=permanent_rules.sgt_total_supply)
    old_root = bytes32(Program.to(list(current.as_tuple())).get_tree_hash())
    if old_root != state.parameters_root:
        raise ValueError("parameter witness does not match the current root")
    parameter_index = ParameterIndex(index)
    updated = current.mutate(
        parameter_index,
        value,
        sgt_total_supply=permanent_rules.sgt_total_supply,
    )
    new_root = bytes32(Program.to(list(updated.as_tuple())).get_tree_hash())
    next_state = _state_with_root(state, MutationKind.PARAMETER, new_root)
    mutation: StatuteMutation[KeyedRecord] = StatuteMutation(
        kind=MutationKind.PARAMETER,
        key=int(parameter_index),
        value=value,
        old_root=old_root,
        new_root=new_root,
        old_version=state.registry_version,
        new_version=next_state.registry_version,
        old_state_hash=state.content_hash,
        new_state_hash=next_state.content_hash,
    )
    return mutation, updated, next_state


def build_record_mutation(
    *,
    state: StatutesState,
    kind: MutationKind,
    current: Sequence[TRecord],
    replacement: TRecord,
) -> tuple[StatuteMutation[TRecord], tuple[TRecord, ...], StatutesState]:
    expected_type = {
        MutationKind.COLLECTION: CollectionStatute,
        MutationKind.ORACLE: OracleRound,
        MutationKind.ROUTE: BridgeRoute,
        MutationKind.PAUSE: ScopedPause,
    }.get(kind)
    if expected_type is None:
        raise ValueError("record mutation requires a keyed registry kind")
    if not isinstance(replacement, expected_type):
        raise ValueError("record type does not match the mutation kind")
    if any(not isinstance(record, expected_type) for record in current):
        raise ValueError("current witness contains the wrong record type")
    old_root = keyed_root(current)
    expected_old_root = {
        MutationKind.COLLECTION: state.collections_root,
        MutationKind.ORACLE: state.oracle_root,
        MutationKind.ROUTE: state.routes_root,
        MutationKind.PAUSE: state.pauses_root,
    }[kind]
    if old_root != expected_old_root:
        raise ValueError("record witness does not match the current root")
    updated = upsert_record(current, replacement)
    new_root = keyed_root(updated)
    next_state = _state_with_root(state, kind, new_root)
    return (
        StatuteMutation(
            kind=kind,
            key=_record_key(replacement),
            value=replacement,
            old_root=old_root,
            new_root=new_root,
            old_version=state.registry_version,
            new_version=next_state.registry_version,
            old_state_hash=state.content_hash,
            new_state_hash=next_state.content_hash,
        ),
        updated,
        next_state,
    )


__all__ = [
    "MAX_BPS",
    "MAX_EXCHANGE_FEE_BPS",
    "MIN_ORACLE_SOURCES",
    "UPGRADE_DELAY_SECONDS",
    "ParameterIndex",
    "MutationKind",
    "BillTag",
    "PermanentRules",
    "ProtocolParameters",
    "CollectionStatute",
    "OracleRound",
    "BridgeRoute",
    "ScopedPause",
    "StatutesState",
    "StatuteMutation",
    "keyed_root",
    "upsert_record",
    "initial_state",
    "build_parameter_mutation",
    "build_record_mutation",
]
