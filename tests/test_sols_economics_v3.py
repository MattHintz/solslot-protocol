from __future__ import annotations

from fractions import Fraction

import pytest

from solslot_puzzles.sols_economics_v3 import (
    BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS,
    MAX_EXCHANGE_FEE_BPS,
    SOLS_MOJOS_PER_SOLS,
    SettlementShare,
    SolsEconomicState,
    allocate_settlement,
    contribute_treasury_assets,
    fee_split_for_principal,
    quote_deed_to_sols,
    quote_sols_to_deed,
    revalue_pool_inventory,
    set_proven_liabilities,
)


def live_state(*, reserve: int = 100_000, total: int = 500_000) -> SolsEconomicState:
    return SolsEconomicState(
        bootstrap_complete=True,
        inventory_nav_micro_usd=999_000_000,
        treasury_assets_micro_usd=333_000_000,
        proven_liabilities_micro_usd=0,
        deed_count=6,
        total_sols_mojos=total,
        reserve_sols_mojos=reserve,
    )


def test_bootstrap_uses_exact_three_dollars_and_thirty_three_cents() -> None:
    state = SolsEconomicState(False, 0, 0, 0, 0, 0, 0)
    quote = quote_deed_to_sols(state, deed_value_micro_usd=333_000_000)

    assert BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS == 3_330_000
    assert SOLS_MOJOS_PER_SOLS == 1_000
    assert quote.used_bootstrap_price is True
    assert quote.seller_sols_mojos == 100_000
    assert quote.reserve_sols_mojos_paid == 0
    assert quote.fresh_sols_mojos_minted == 100_000
    assert quote.next_state.bootstrap_complete is True
    assert quote.next_state.nav_micro_usd_per_sols == Fraction(3_330_000, 1)


def test_bootstrap_seller_rounding_favors_existing_backing() -> None:
    quote = quote_deed_to_sols(
        SolsEconomicState(False, 0, 0, 0, 0, 0, 0),
        deed_value_micro_usd=100_000_000,
    )
    assert quote.seller_sols_mojos == 30_030
    assert quote.next_state.nav_micro_usd_per_sols > Fraction(3_330_000, 1)


def test_deed_to_sols_uses_reserve_before_minting() -> None:
    quote = quote_deed_to_sols(
        live_state(),
        deed_value_micro_usd=166_500_000,
    )
    assert quote.seller_sols_mojos == 50_000
    assert quote.reserve_sols_mojos_paid == 50_000
    assert quote.fresh_sols_mojos_minted == 0
    assert quote.next_state.total_sols_mojos == 500_000
    assert quote.next_state.reserve_sols_mojos == 50_000
    assert quote.next_state.circulating_sols_mojos == 450_000
    assert quote.next_state.nav_micro_usd_per_sols == Fraction(3_330_000, 1)


def test_deed_to_sols_mints_only_exact_reserve_shortfall() -> None:
    quote = quote_deed_to_sols(
        live_state(reserve=20_000, total=420_000),
        deed_value_micro_usd=166_500_000,
    )
    assert quote.seller_sols_mojos == 50_000
    assert quote.reserve_sols_mojos_paid == 20_000
    assert quote.fresh_sols_mojos_minted == 30_000
    assert quote.next_state.total_sols_mojos == 450_000
    assert quote.next_state.reserve_sols_mojos == 0
    assert quote.next_state.nav_micro_usd_per_sols == Fraction(3_330_000, 1)


def test_sols_to_deed_returns_principal_to_reserve_without_melt() -> None:
    quote = quote_sols_to_deed(
        live_state(),
        deed_value_micro_usd=166_500_000,
    )
    assert quote.principal_sols_mojos == 50_000
    assert quote.fee_split.total_fee_sols_mojos == 500
    assert quote.fee_split.protocol_fee_sols_mojos == 150
    assert quote.fee_split.sgt_rewards_fee_sols_mojos == 350
    assert quote.buyer_total_sols_mojos == 50_500
    assert quote.next_state.total_sols_mojos == 500_000
    assert quote.next_state.reserve_sols_mojos == 150_000
    assert quote.next_state.circulating_sols_mojos == 350_000
    assert quote.next_state.nav_micro_usd_per_sols == Fraction(3_330_000, 1)


def test_exchange_fee_cannot_exceed_one_percent() -> None:
    with pytest.raises(ValueError, match="permanent 1% cap"):
        fee_split_for_principal(
            50_000,
            exchange_fee_bps=MAX_EXCHANGE_FEE_BPS + 1,
            protocol_fee_bps=31,
            sgt_rewards_fee_bps=70,
        )


def test_treasury_contribution_raises_nav_without_minting() -> None:
    state = live_state()
    next_state = contribute_treasury_assets(
        state,
        amount_micro_usd=33_300_000,
    )
    assert next_state.total_sols_mojos == state.total_sols_mojos
    assert next_state.reserve_sols_mojos == state.reserve_sols_mojos
    assert next_state.nav_micro_usd_per_sols == Fraction(3_413_250, 1)


def test_zero_or_negative_backing_blocks_nav_pricing() -> None:
    zero = set_proven_liabilities(
        live_state(),
        amount_micro_usd=1_332_000_000,
    )
    assert zero.backing_micro_usd == 0
    with pytest.raises(ValueError, match="backing must be positive"):
        quote_deed_to_sols(zero, deed_value_micro_usd=166_500_000)
    with pytest.raises(ValueError, match="backing must be positive"):
        quote_sols_to_deed(zero, deed_value_micro_usd=166_500_000)


def test_collection_revaluation_changes_only_inventory_backing() -> None:
    state = live_state()
    next_state = revalue_pool_inventory(
        state,
        previous_collection_inventory_micro_usd=333_000_000,
        next_collection_inventory_micro_usd=399_600_000,
    )
    assert next_state.inventory_nav_micro_usd == 1_065_600_000
    assert next_state.treasury_assets_micro_usd == state.treasury_assets_micro_usd
    assert next_state.total_sols_mojos == state.total_sols_mojos
    assert next_state.nav_micro_usd_per_sols == Fraction(3_496_500, 1)


def test_settlement_allocation_uses_largest_remainder() -> None:
    allocations = allocate_settlement(
        100_000_001,
        (
            SettlementShare("deed-a", 333_333),
            SettlementShare("deed-b", 333_333),
            SettlementShare("deed-c", 333_334),
        ),
    )
    assert [item.amount_micro_usd for item in allocations] == [
        33_333_300,
        33_333_300,
        33_333_401,
    ]
    assert sum(item.amount_micro_usd for item in allocations) == 100_000_001


def test_settlement_allocation_breaks_equal_remainders_by_deed_id() -> None:
    allocations = allocate_settlement(
        1,
        (
            SettlementShare("deed-b", 500_000),
            SettlementShare("deed-a", 500_000),
        ),
    )
    assert [(item.deed_id, item.amount_micro_usd) for item in allocations] == [
        ("deed-b", 0),
        ("deed-a", 1),
    ]


def test_settlement_requires_unique_deeds_and_exact_ppm() -> None:
    with pytest.raises(ValueError, match="unique"):
        allocate_settlement(
            10,
            (
                SettlementShare("deed-a", 500_000),
                SettlementShare("deed-a", 500_000),
            ),
        )
    with pytest.raises(ValueError, match="exactly 1_000_000"):
        allocate_settlement(
            10,
            (
                SettlementShare("deed-a", 500_000),
                SettlementShare("deed-b", 499_999),
            ),
        )
