"""Canonical integer economics for the Sols SmartDeed market.

This module defines the RC22 economic contract before the matching CLVM is
introduced. Values use micro-USD (six decimals) and Sols CAT mojos (three
decimals). Every calculation is integer-only and states its rounding direction.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from fractions import Fraction
from typing import Iterable


USD_MICRO_PER_DOLLAR = 1_000_000
SOLS_MOJOS_PER_SOLS = 1_000
BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS = 3_330_000
SHARE_PPM_DENOMINATOR = 1_000_000
FEE_BPS_DENOMINATOR = 10_000
DEFAULT_EXCHANGE_FEE_BPS = 100
DEFAULT_PROTOCOL_FEE_BPS = 30
DEFAULT_SGT_REWARDS_FEE_BPS = 70
MAX_EXCHANGE_FEE_BPS = 100


def floor_div(numerator: int, denominator: int) -> int:
    if numerator < 0:
        raise ValueError("numerator must be non-negative")
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    return numerator // denominator


def ceil_div(numerator: int, denominator: int) -> int:
    if numerator < 0:
        raise ValueError("numerator must be non-negative")
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    return (numerator + denominator - 1) // denominator


@dataclass(frozen=True)
class SolsEconomicState:
    bootstrap_complete: bool
    inventory_nav_micro_usd: int
    treasury_assets_micro_usd: int
    proven_liabilities_micro_usd: int
    deed_count: int
    total_sols_mojos: int
    reserve_sols_mojos: int

    def validate(self) -> "SolsEconomicState":
        values = {
            "inventory_nav_micro_usd": self.inventory_nav_micro_usd,
            "treasury_assets_micro_usd": self.treasury_assets_micro_usd,
            "proven_liabilities_micro_usd": self.proven_liabilities_micro_usd,
            "deed_count": self.deed_count,
            "total_sols_mojos": self.total_sols_mojos,
            "reserve_sols_mojos": self.reserve_sols_mojos,
        }
        for label, value in values.items():
            if value < 0:
                raise ValueError(f"{label} must be non-negative")
        if self.reserve_sols_mojos > self.total_sols_mojos:
            raise ValueError("reserve_sols_mojos cannot exceed total_sols_mojos")
        if self.deed_count == 0 and self.inventory_nav_micro_usd != 0:
            raise ValueError("inventory NAV requires at least one pool-held deed")
        if not self.bootstrap_complete and (
            self.deed_count != 0
            or self.inventory_nav_micro_usd != 0
            or self.total_sols_mojos != 0
            or self.reserve_sols_mojos != 0
        ):
            raise ValueError("an unbootstrapped pool cannot have inventory or Sols")
        return self

    @property
    def backing_micro_usd(self) -> int:
        self.validate()
        return (
            self.inventory_nav_micro_usd
            + self.treasury_assets_micro_usd
            - self.proven_liabilities_micro_usd
        )

    @property
    def circulating_sols_mojos(self) -> int:
        self.validate()
        return self.total_sols_mojos - self.reserve_sols_mojos

    @property
    def nav_micro_usd_per_sols(self) -> Fraction:
        backing = self.backing_micro_usd
        circulating = self.circulating_sols_mojos
        if backing <= 0:
            raise ValueError("Sols backing must be positive")
        if circulating <= 0:
            raise ValueError("circulating Sols must be positive")
        return Fraction(
            backing * SOLS_MOJOS_PER_SOLS,
            circulating,
        )


@dataclass(frozen=True)
class FeeSplit:
    total_fee_sols_mojos: int
    protocol_fee_sols_mojos: int
    sgt_rewards_fee_sols_mojos: int


@dataclass(frozen=True)
class DeedToSolsQuote:
    deed_value_micro_usd: int
    seller_sols_mojos: int
    reserve_sols_mojos_paid: int
    fresh_sols_mojos_minted: int
    used_bootstrap_price: bool
    next_state: SolsEconomicState


@dataclass(frozen=True)
class SolsToDeedQuote:
    deed_value_micro_usd: int
    principal_sols_mojos: int
    fee_split: FeeSplit
    buyer_total_sols_mojos: int
    next_state: SolsEconomicState


@dataclass(frozen=True)
class SettlementShare:
    deed_id: str
    share_ppm: int


@dataclass(frozen=True)
class SettlementAllocation:
    deed_id: str
    share_ppm: int
    amount_micro_usd: int


def fee_split_for_principal(
    principal_sols_mojos: int,
    *,
    exchange_fee_bps: int = DEFAULT_EXCHANGE_FEE_BPS,
    protocol_fee_bps: int = DEFAULT_PROTOCOL_FEE_BPS,
    sgt_rewards_fee_bps: int = DEFAULT_SGT_REWARDS_FEE_BPS,
) -> FeeSplit:
    if principal_sols_mojos <= 0:
        raise ValueError("principal_sols_mojos must be positive")
    if exchange_fee_bps < 0 or exchange_fee_bps > MAX_EXCHANGE_FEE_BPS:
        raise ValueError("exchange fee exceeds the permanent 1% cap")
    if protocol_fee_bps < 0 or sgt_rewards_fee_bps < 0:
        raise ValueError("fee split bps must be non-negative")
    if protocol_fee_bps + sgt_rewards_fee_bps != exchange_fee_bps:
        raise ValueError("protocol and SGT reward bps must equal exchange fee bps")

    total = ceil_div(
        principal_sols_mojos * exchange_fee_bps,
        FEE_BPS_DENOMINATOR,
    )
    protocol = min(
        total,
        ceil_div(
            principal_sols_mojos * protocol_fee_bps,
            FEE_BPS_DENOMINATOR,
        ),
    )
    return FeeSplit(
        total_fee_sols_mojos=total,
        protocol_fee_sols_mojos=protocol,
        sgt_rewards_fee_sols_mojos=total - protocol,
    )


def _dynamic_sols_for_value(
    state: SolsEconomicState,
    value_micro_usd: int,
    *,
    round_up: bool,
) -> int:
    state.validate()
    if not state.bootstrap_complete:
        raise ValueError("dynamic pricing requires a bootstrapped pool")
    if value_micro_usd <= 0:
        raise ValueError("value_micro_usd must be positive")
    backing = state.backing_micro_usd
    circulating = state.circulating_sols_mojos
    if backing <= 0:
        raise ValueError("Sols backing must be positive")
    if circulating <= 0:
        raise ValueError("circulating Sols must be positive")
    numerator = value_micro_usd * circulating
    return (
        ceil_div(numerator, backing)
        if round_up
        else floor_div(numerator, backing)
    )


def quote_deed_to_sols(
    state: SolsEconomicState,
    *,
    deed_value_micro_usd: int,
) -> DeedToSolsQuote:
    """Quote an automatic verified-vault SmartDeed deposit.

    The first confirmed deposit uses the fixed $3.33 bootstrap price. Later
    deposits pay the seller at pre-transaction dynamic NAV, rounded down.
    Reserve Sols move first and only the exact shortfall is minted.
    """
    state.validate()
    if deed_value_micro_usd <= 0:
        raise ValueError("deed_value_micro_usd must be positive")
    if state.bootstrap_complete:
        seller_amount = _dynamic_sols_for_value(
            state,
            deed_value_micro_usd,
            round_up=False,
        )
    else:
        seller_amount = floor_div(
            deed_value_micro_usd * SOLS_MOJOS_PER_SOLS,
            BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS,
        )
    if seller_amount <= 0:
        raise ValueError("deed value is below the minimum Sols precision")

    reserve_paid = min(state.reserve_sols_mojos, seller_amount)
    fresh_mint = seller_amount - reserve_paid
    next_state = SolsEconomicState(
        bootstrap_complete=True,
        inventory_nav_micro_usd=(
            state.inventory_nav_micro_usd + deed_value_micro_usd
        ),
        treasury_assets_micro_usd=state.treasury_assets_micro_usd,
        proven_liabilities_micro_usd=state.proven_liabilities_micro_usd,
        deed_count=state.deed_count + 1,
        total_sols_mojos=state.total_sols_mojos + fresh_mint,
        reserve_sols_mojos=state.reserve_sols_mojos - reserve_paid,
    ).validate()
    return DeedToSolsQuote(
        deed_value_micro_usd=deed_value_micro_usd,
        seller_sols_mojos=seller_amount,
        reserve_sols_mojos_paid=reserve_paid,
        fresh_sols_mojos_minted=fresh_mint,
        used_bootstrap_price=not state.bootstrap_complete,
        next_state=next_state,
    )


def quote_sols_to_deed(
    state: SolsEconomicState,
    *,
    deed_value_micro_usd: int,
    exchange_fee_bps: int = DEFAULT_EXCHANGE_FEE_BPS,
    protocol_fee_bps: int = DEFAULT_PROTOCOL_FEE_BPS,
    sgt_rewards_fee_bps: int = DEFAULT_SGT_REWARDS_FEE_BPS,
) -> SolsToDeedQuote:
    """Quote the purchase of one pool-held secondary SmartDeed.

    Principal rounds up and returns to the canonical reserve. Supply is never
    melted. The buyer-only exchange fee remains circulating outside reserve.
    """
    state.validate()
    if state.deed_count <= 0:
        raise ValueError("pool has no SmartDeeds")
    if deed_value_micro_usd <= 0:
        raise ValueError("deed_value_micro_usd must be positive")
    if deed_value_micro_usd > state.inventory_nav_micro_usd:
        raise ValueError("deed value exceeds pool inventory NAV")

    principal = _dynamic_sols_for_value(
        state,
        deed_value_micro_usd,
        round_up=True,
    )
    if principal > state.circulating_sols_mojos:
        raise ValueError("deed requires more than the circulating Sols supply")
    fees = fee_split_for_principal(
        principal,
        exchange_fee_bps=exchange_fee_bps,
        protocol_fee_bps=protocol_fee_bps,
        sgt_rewards_fee_bps=sgt_rewards_fee_bps,
    )
    next_state = SolsEconomicState(
        bootstrap_complete=True,
        inventory_nav_micro_usd=(
            state.inventory_nav_micro_usd - deed_value_micro_usd
        ),
        treasury_assets_micro_usd=state.treasury_assets_micro_usd,
        proven_liabilities_micro_usd=state.proven_liabilities_micro_usd,
        deed_count=state.deed_count - 1,
        total_sols_mojos=state.total_sols_mojos,
        reserve_sols_mojos=state.reserve_sols_mojos + principal,
    ).validate()
    return SolsToDeedQuote(
        deed_value_micro_usd=deed_value_micro_usd,
        principal_sols_mojos=principal,
        fee_split=fees,
        buyer_total_sols_mojos=principal + fees.total_fee_sols_mojos,
        next_state=next_state,
    )


def contribute_treasury_assets(
    state: SolsEconomicState,
    *,
    amount_micro_usd: int,
) -> SolsEconomicState:
    state.validate()
    if amount_micro_usd <= 0:
        raise ValueError("amount_micro_usd must be positive")
    return replace(
        state,
        treasury_assets_micro_usd=(
            state.treasury_assets_micro_usd + amount_micro_usd
        ),
    ).validate()


def set_proven_liabilities(
    state: SolsEconomicState,
    *,
    amount_micro_usd: int,
) -> SolsEconomicState:
    state.validate()
    if amount_micro_usd < 0:
        raise ValueError("amount_micro_usd must be non-negative")
    return replace(
        state,
        proven_liabilities_micro_usd=amount_micro_usd,
    ).validate()


def revalue_pool_inventory(
    state: SolsEconomicState,
    *,
    previous_collection_inventory_micro_usd: int,
    next_collection_inventory_micro_usd: int,
) -> SolsEconomicState:
    """Apply one governed collection revaluation to pool-held deeds only."""
    state.validate()
    if previous_collection_inventory_micro_usd < 0:
        raise ValueError("previous collection inventory must be non-negative")
    if next_collection_inventory_micro_usd < 0:
        raise ValueError("next collection inventory must be non-negative")
    if previous_collection_inventory_micro_usd > state.inventory_nav_micro_usd:
        raise ValueError("previous collection inventory exceeds total inventory NAV")
    return replace(
        state,
        inventory_nav_micro_usd=(
            state.inventory_nav_micro_usd
            - previous_collection_inventory_micro_usd
            + next_collection_inventory_micro_usd
        ),
    ).validate()


def allocate_settlement(
    total_micro_usd: int,
    shares: Iterable[SettlementShare],
) -> tuple[SettlementAllocation, ...]:
    """Allocate an exact funded settlement using largest-remainder rounding."""
    if total_micro_usd <= 0:
        raise ValueError("total_micro_usd must be positive")
    normalized = tuple(shares)
    if not normalized:
        raise ValueError("settlement must contain at least one deed")
    deed_ids = [item.deed_id for item in normalized]
    if any(not deed_id for deed_id in deed_ids):
        raise ValueError("deed_id must not be empty")
    if len(set(deed_ids)) != len(deed_ids):
        raise ValueError("settlement deed ids must be unique")
    if any(item.share_ppm <= 0 for item in normalized):
        raise ValueError("share_ppm must be positive")
    if sum(item.share_ppm for item in normalized) != SHARE_PPM_DENOMINATOR:
        raise ValueError("settlement shares must total exactly 1_000_000 ppm")

    rows: list[dict[str, int | str]] = []
    allocated = 0
    for item in normalized:
        numerator = total_micro_usd * item.share_ppm
        base = floor_div(numerator, SHARE_PPM_DENOMINATOR)
        rows.append(
            {
                "deed_id": item.deed_id,
                "share_ppm": item.share_ppm,
                "amount": base,
                "remainder": numerator % SHARE_PPM_DENOMINATOR,
            }
        )
        allocated += base
    leftover = total_micro_usd - allocated
    ranked = sorted(
        rows,
        key=lambda item: (-int(item["remainder"]), str(item["deed_id"])),
    )
    for row in ranked[:leftover]:
        row["amount"] = int(row["amount"]) + 1

    by_id = {str(row["deed_id"]): row for row in rows}
    return tuple(
        SettlementAllocation(
            deed_id=item.deed_id,
            share_ppm=item.share_ppm,
            amount_micro_usd=int(by_id[item.deed_id]["amount"]),
        )
        for item in normalized
    )


__all__ = [
    "USD_MICRO_PER_DOLLAR",
    "SOLS_MOJOS_PER_SOLS",
    "BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS",
    "SHARE_PPM_DENOMINATOR",
    "FEE_BPS_DENOMINATOR",
    "DEFAULT_EXCHANGE_FEE_BPS",
    "DEFAULT_PROTOCOL_FEE_BPS",
    "DEFAULT_SGT_REWARDS_FEE_BPS",
    "MAX_EXCHANGE_FEE_BPS",
    "SolsEconomicState",
    "FeeSplit",
    "DeedToSolsQuote",
    "SolsToDeedQuote",
    "SettlementShare",
    "SettlementAllocation",
    "floor_div",
    "ceil_div",
    "fee_split_for_principal",
    "quote_deed_to_sols",
    "quote_sols_to_deed",
    "contribute_treasury_assets",
    "set_proven_liabilities",
    "revalue_pool_inventory",
    "allocate_settlement",
]
