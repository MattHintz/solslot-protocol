"""Typed RC22 pool state for protocol-only SmartDeed/Sols swaps."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from solslot_puzzles.protocol_statutes_v1 import (
    CollectionStatute,
    ProtocolParameters,
    ScopedPause,
    StatutesState,
)
from solslot_puzzles.sols_economics_v3 import (
    DeedToSolsQuote,
    SolsEconomicState,
    SolsToDeedQuote,
    SHARE_PPM_DENOMINATOR,
    ceil_div,
    quote_deed_to_sols,
    quote_sols_to_deed,
)


DEED_TO_SOLS = 1
SOLS_TO_DEED = 2
INVENTORY_AVAILABLE = 1
SWAP_OPERATION_TAG = b"PSOL"


def _bytes32(label: str, value: bytes | bytes32) -> bytes32:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError(f"{label} must be 32 bytes")
    return bytes32(raw)


def _uint64(label: str, value: int, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    minimum = 1 if positive else 0
    if value < minimum or value >= 2**64:
        qualifier = "positive " if positive else ""
        raise ValueError(f"{label} must be a {qualifier}uint64")
    return value


@dataclass(frozen=True)
class PoolInventoryRecord:
    deed_launcher_id: bytes32
    custody_coin_id: bytes32
    deed_commitment: bytes32
    collection_id: bytes32
    share_ppm: int
    deed_value_micro_usd: int
    nav_version: int
    valid_until: int
    settlement_state: int = INVENTORY_AVAILABLE

    def validate(self) -> "PoolInventoryRecord":
        _bytes32("deed_launcher_id", self.deed_launcher_id)
        _bytes32("custody_coin_id", self.custody_coin_id)
        _bytes32("deed_commitment", self.deed_commitment)
        _bytes32("collection_id", self.collection_id)
        _uint64("share_ppm", self.share_ppm, positive=True)
        if self.share_ppm > SHARE_PPM_DENOMINATOR:
            raise ValueError("share_ppm exceeds 1,000,000")
        _uint64(
            "deed_value_micro_usd",
            self.deed_value_micro_usd,
            positive=True,
        )
        _uint64("nav_version", self.nav_version, positive=True)
        _uint64("valid_until", self.valid_until, positive=True)
        if self.settlement_state != INVENTORY_AVAILABLE:
            raise ValueError("only available deeds belong in swap inventory")
        return self

    def as_program_value(self) -> list[object]:
        self.validate()
        return [
            self.deed_launcher_id,
            self.custody_coin_id,
            self.deed_commitment,
            self.collection_id,
            self.share_ppm,
            self.deed_value_micro_usd,
            self.nav_version,
            self.valid_until,
            self.settlement_state,
        ]


def canonical_inventory(
    records: Sequence[PoolInventoryRecord],
) -> tuple[PoolInventoryRecord, ...]:
    normalized = tuple(sorted(records, key=lambda item: bytes(item.deed_launcher_id)))
    for record in normalized:
        record.validate()
    ids = [record.deed_launcher_id for record in normalized]
    custody_ids = [record.custody_coin_id for record in normalized]
    commitments = [record.deed_commitment for record in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("inventory deed launcher IDs must be unique")
    if len(custody_ids) != len(set(custody_ids)):
        raise ValueError("inventory custody coin IDs must be unique")
    if len(commitments) != len(set(commitments)):
        raise ValueError("inventory deed commitments must be unique")
    return normalized


def inventory_root(records: Sequence[PoolInventoryRecord]) -> bytes32:
    normalized = canonical_inventory(records)
    return bytes32(
        Program.to(
            [record.as_program_value() for record in normalized]
        ).get_tree_hash()
    )


@dataclass(frozen=True)
class SolsPoolStateV4:
    inventory_root: bytes32
    economics: SolsEconomicState
    state_version: int

    def validate(
        self,
        inventory: Sequence[PoolInventoryRecord],
    ) -> "SolsPoolStateV4":
        _bytes32("inventory_root", self.inventory_root)
        _uint64("state_version", self.state_version, positive=True)
        self.economics.validate()
        normalized = canonical_inventory(inventory)
        if inventory_root(normalized) != self.inventory_root:
            raise ValueError("inventory witness does not match inventory_root")
        if len(normalized) != self.economics.deed_count:
            raise ValueError("inventory witness does not match deed_count")
        if (
            sum(record.deed_value_micro_usd for record in normalized)
            != self.economics.inventory_nav_micro_usd
        ):
            raise ValueError("inventory witness does not match inventory NAV")
        return self

    @property
    def commitment_hash(self) -> bytes32:
        economic = self.economics.validate()
        return bytes32(
            Program.to(
                [
                    self.inventory_root,
                    int(economic.bootstrap_complete),
                    economic.inventory_nav_micro_usd,
                    economic.treasury_assets_micro_usd,
                    economic.proven_liabilities_micro_usd,
                    economic.deed_count,
                    economic.total_sols_mojos,
                    economic.reserve_sols_mojos,
                    self.state_version,
                ]
            ).get_tree_hash()
        )


@dataclass(frozen=True)
class SwapReceipt:
    direction: int
    operation_hash: bytes32
    current_state: SolsPoolStateV4
    next_state: SolsPoolStateV4
    inventory: tuple[PoolInventoryRecord, ...]
    next_inventory: tuple[PoolInventoryRecord, ...]
    record: PoolInventoryRecord
    deed_to_sols_quote: DeedToSolsQuote | None = None
    sols_to_deed_quote: SolsToDeedQuote | None = None


def _validate_statutes(
    *,
    direction: int,
    collection: CollectionStatute,
    pause: ScopedPause | None,
    parameters: ProtocolParameters,
    statutes_state: StatutesState,
    quote_expires_at: int,
) -> None:
    collection.validate()
    parameters.validate()
    statutes_state.validate()
    _uint64("quote_expires_at", quote_expires_at, positive=True)
    if direction == DEED_TO_SOLS and collection.status != 1:
        raise ValueError("deed deposits require an active collection")
    if (
        direction == SOLS_TO_DEED
        and collection.status not in (1, 3)
    ):
        raise ValueError(
            "deed acquisition requires an active or settled collection"
        )
    if direction not in (DEED_TO_SOLS, SOLS_TO_DEED):
        raise ValueError("unsupported swap direction")
    if pause is not None:
        pause.validate()
        if pause.scope_id != collection.collection_id:
            raise ValueError("pause does not match collection")
        if pause.paused == 1:
            raise ValueError("collection swaps are paused")
    if collection.valid_until - collection.valid_after > (
        parameters.nav_validity_seconds
    ):
        raise ValueError("collection NAV exceeds governed validity window")
    if quote_expires_at > collection.valid_until:
        raise ValueError("quote outlives collection NAV")


def governed_deed_value(
    collection: CollectionStatute,
    share_ppm: int,
) -> int:
    collection.validate()
    _uint64("share_ppm", share_ppm, positive=True)
    if share_ppm > SHARE_PPM_DENOMINATOR:
        raise ValueError("share_ppm exceeds 1,000,000")
    return ceil_div(
        collection.nav_micro_usd * share_ppm,
        SHARE_PPM_DENOMINATOR,
    )


def _operation_hash(
    *,
    direction: int,
    pool_coin_id: bytes32,
    current_state: SolsPoolStateV4,
    next_state: SolsPoolStateV4,
    record: PoolInventoryRecord,
    vault_launcher_id: bytes32,
    vault_coin_id: bytes32,
    counterparty_puzzle_hash: bytes32,
    principal_or_payout: int,
    protocol_fee: int,
    rewards_fee: int,
    quote_expires_at: int,
    statutes_state: StatutesState,
) -> bytes32:
    return bytes32(
        Program.to(
            [
                SWAP_OPERATION_TAG,
                direction,
                pool_coin_id,
                current_state.commitment_hash,
                next_state.commitment_hash,
                record.as_program_value(),
                vault_launcher_id,
                vault_coin_id,
                counterparty_puzzle_hash,
                principal_or_payout,
                protocol_fee,
                rewards_fee,
                quote_expires_at,
                statutes_state.content_hash,
                statutes_state.registry_version,
            ]
        ).get_tree_hash()
    )


def prepare_deed_to_sols(
    *,
    pool_coin_id: bytes32,
    state: SolsPoolStateV4,
    inventory: Sequence[PoolInventoryRecord],
    deed_launcher_id: bytes32,
    custody_coin_id: bytes32,
    deed_commitment: bytes32,
    collection: CollectionStatute,
    share_ppm: int,
    parameters: ProtocolParameters,
    statutes_state: StatutesState,
    pause: ScopedPause | None,
    vault_launcher_id: bytes32,
    vault_coin_id: bytes32,
    seller_sols_puzzle_hash: bytes32,
    quote_expires_at: int,
) -> SwapReceipt:
    normalized = canonical_inventory(inventory)
    state.validate(normalized)
    _validate_statutes(
        direction=DEED_TO_SOLS,
        collection=collection,
        pause=pause,
        parameters=parameters,
        statutes_state=statutes_state,
        quote_expires_at=quote_expires_at,
    )
    deed_id = _bytes32("deed_launcher_id", deed_launcher_id)
    commitment = _bytes32("deed_commitment", deed_commitment)
    if any(record.deed_launcher_id == deed_id for record in normalized):
        raise ValueError("deed is already held by the pool")
    deed_value = governed_deed_value(collection, share_ppm)
    held_collection_value = sum(
        record.deed_value_micro_usd
        for record in normalized
        if record.collection_id == collection.collection_id
    )
    if held_collection_value + deed_value > (
        collection.allocation_ceiling_micro_usd
    ):
        raise ValueError("collection allocation ceiling exceeded")
    record = PoolInventoryRecord(
        deed_launcher_id=deed_id,
        custody_coin_id=_bytes32("custody_coin_id", custody_coin_id),
        deed_commitment=commitment,
        collection_id=collection.collection_id,
        share_ppm=share_ppm,
        deed_value_micro_usd=deed_value,
        nav_version=collection.nav_version,
        valid_until=collection.valid_until,
    ).validate()
    quote = quote_deed_to_sols(
        state.economics,
        deed_value_micro_usd=deed_value,
    )
    next_inventory = canonical_inventory((*normalized, record))
    next_state = SolsPoolStateV4(
        inventory_root=inventory_root(next_inventory),
        economics=quote.next_state,
        state_version=state.state_version + 1,
    ).validate(next_inventory)
    operation_hash = _operation_hash(
        direction=DEED_TO_SOLS,
        pool_coin_id=_bytes32("pool_coin_id", pool_coin_id),
        current_state=state,
        next_state=next_state,
        record=record,
        vault_launcher_id=_bytes32("vault_launcher_id", vault_launcher_id),
        vault_coin_id=_bytes32("vault_coin_id", vault_coin_id),
        counterparty_puzzle_hash=_bytes32(
            "seller_sols_puzzle_hash",
            seller_sols_puzzle_hash,
        ),
        principal_or_payout=quote.seller_sols_mojos,
        protocol_fee=0,
        rewards_fee=0,
        quote_expires_at=quote_expires_at,
        statutes_state=statutes_state,
    )
    return SwapReceipt(
        direction=DEED_TO_SOLS,
        operation_hash=operation_hash,
        current_state=state,
        next_state=next_state,
        inventory=normalized,
        next_inventory=next_inventory,
        record=record,
        deed_to_sols_quote=quote,
    )


def prepare_sols_to_deed(
    *,
    pool_coin_id: bytes32,
    state: SolsPoolStateV4,
    inventory: Sequence[PoolInventoryRecord],
    deed_launcher_id: bytes32,
    collection: CollectionStatute,
    parameters: ProtocolParameters,
    statutes_state: StatutesState,
    pause: ScopedPause | None,
    vault_launcher_id: bytes32,
    vault_coin_id: bytes32,
    destination_p2_vault_hash: bytes32,
    quote_expires_at: int,
) -> SwapReceipt:
    normalized = canonical_inventory(inventory)
    state.validate(normalized)
    _validate_statutes(
        direction=SOLS_TO_DEED,
        collection=collection,
        pause=pause,
        parameters=parameters,
        statutes_state=statutes_state,
        quote_expires_at=quote_expires_at,
    )
    matches = [
        record
        for record in normalized
        if record.deed_launcher_id == deed_launcher_id
    ]
    if len(matches) != 1:
        raise ValueError("deed must exist exactly once in pool inventory")
    record = matches[0]
    if record.collection_id != collection.collection_id:
        raise ValueError("deed collection does not match governed statute")
    expected_value = governed_deed_value(collection, record.share_ppm)
    if (
        record.deed_value_micro_usd != expected_value
        or record.nav_version != collection.nav_version
        or record.valid_until != collection.valid_until
    ):
        raise ValueError("deed inventory requires governed revaluation")
    quote = quote_sols_to_deed(
        state.economics,
        deed_value_micro_usd=record.deed_value_micro_usd,
        exchange_fee_bps=parameters.exchange_fee_bps,
        protocol_fee_bps=parameters.protocol_fee_bps,
        sgt_rewards_fee_bps=parameters.sgt_rewards_fee_bps,
    )
    next_inventory = tuple(
        item
        for item in normalized
        if item.deed_launcher_id != record.deed_launcher_id
    )
    next_state = SolsPoolStateV4(
        inventory_root=inventory_root(next_inventory),
        economics=quote.next_state,
        state_version=state.state_version + 1,
    ).validate(next_inventory)
    operation_hash = _operation_hash(
        direction=SOLS_TO_DEED,
        pool_coin_id=_bytes32("pool_coin_id", pool_coin_id),
        current_state=state,
        next_state=next_state,
        record=record,
        vault_launcher_id=_bytes32("vault_launcher_id", vault_launcher_id),
        vault_coin_id=_bytes32("vault_coin_id", vault_coin_id),
        counterparty_puzzle_hash=_bytes32(
            "destination_p2_vault_hash",
            destination_p2_vault_hash,
        ),
        principal_or_payout=quote.principal_sols_mojos,
        protocol_fee=quote.fee_split.protocol_fee_sols_mojos,
        rewards_fee=quote.fee_split.sgt_rewards_fee_sols_mojos,
        quote_expires_at=quote_expires_at,
        statutes_state=statutes_state,
    )
    return SwapReceipt(
        direction=SOLS_TO_DEED,
        operation_hash=operation_hash,
        current_state=state,
        next_state=next_state,
        inventory=normalized,
        next_inventory=next_inventory,
        record=record,
        sols_to_deed_quote=quote,
    )


__all__ = [
    "DEED_TO_SOLS",
    "SOLS_TO_DEED",
    "INVENTORY_AVAILABLE",
    "SWAP_OPERATION_TAG",
    "PoolInventoryRecord",
    "SolsPoolStateV4",
    "SwapReceipt",
    "canonical_inventory",
    "inventory_root",
    "governed_deed_value",
    "prepare_deed_to_sols",
    "prepare_sols_to_deed",
]
