"""Generate the language-neutral Sols Economics V3 fixture."""
from __future__ import annotations

import json
from dataclasses import asdict
from fractions import Fraction
from pathlib import Path
from typing import Any

from solslot_puzzles.sols_economics_v3 import (
    BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS,
    DEFAULT_EXCHANGE_FEE_BPS,
    DEFAULT_PROTOCOL_FEE_BPS,
    DEFAULT_SGT_REWARDS_FEE_BPS,
    FEE_BPS_DENOMINATOR,
    MAX_EXCHANGE_FEE_BPS,
    SHARE_PPM_DENOMINATOR,
    SOLS_MOJOS_PER_SOLS,
    USD_MICRO_PER_DOLLAR,
    SettlementShare,
    SolsEconomicState,
    allocate_settlement,
    contribute_treasury_assets,
    quote_deed_to_sols,
    quote_sols_to_deed,
    revalue_pool_inventory,
    set_proven_liabilities,
)


def _integer_strings(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        return {key: _integer_strings(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_integer_strings(item) for item in value]
    return value


def _state(state: SolsEconomicState) -> dict[str, Any]:
    result = _integer_strings(asdict(state))
    result["backing_micro_usd"] = str(state.backing_micro_usd)
    result["circulating_sols_mojos"] = str(state.circulating_sols_mojos)
    try:
        nav = state.nav_micro_usd_per_sols
    except ValueError:
        result["nav_micro_usd_per_sols"] = None
    else:
        result["nav_micro_usd_per_sols"] = _fraction(nav)
    return result


def _fraction(value: Fraction) -> dict[str, str]:
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
    }


def _deed_to_sols(quote: Any) -> dict[str, Any]:
    result = _integer_strings(asdict(quote))
    result["next_state"] = _state(quote.next_state)
    return result


def _sols_to_deed(quote: Any) -> dict[str, Any]:
    result = _integer_strings(asdict(quote))
    result["next_state"] = _state(quote.next_state)
    return result


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


def build_fixture() -> dict[str, Any]:
    empty = SolsEconomicState(False, 0, 0, 0, 0, 1, 1)
    base = live_state()
    settlement_shares = (
        SettlementShare("deed-a", 333_333),
        SettlementShare("deed-b", 333_333),
        SettlementShare("deed-c", 333_334),
    )
    return {
        "schema": "solslot.sols-economics.v3",
        "constants": _integer_strings(
            {
                "usd_micro_per_dollar": USD_MICRO_PER_DOLLAR,
                "sols_mojos_per_sols": SOLS_MOJOS_PER_SOLS,
                "bootstrap_value_micro_usd_per_sols": (
                    BOOTSTRAP_VALUE_MICRO_USD_PER_SOLS
                ),
                "share_ppm_denominator": SHARE_PPM_DENOMINATOR,
                "fee_bps_denominator": FEE_BPS_DENOMINATOR,
                "default_exchange_fee_bps": DEFAULT_EXCHANGE_FEE_BPS,
                "default_protocol_fee_bps": DEFAULT_PROTOCOL_FEE_BPS,
                "default_sgt_rewards_fee_bps": DEFAULT_SGT_REWARDS_FEE_BPS,
                "max_exchange_fee_bps": MAX_EXCHANGE_FEE_BPS,
            }
        ),
        "permanent_invariants": [
            "sgt-asset-identity-and-total-supply",
            "sols-asset-identity",
            "zkpassport-smartdeed-acquisition-and-redemption",
            "treasury-non-withdrawal",
            "vote-conservation",
            "replay-protection",
            "one-percent-maximum-exchange-fee",
            "no-sols-melt",
            "protocol-only-smartdeed-sols-swaps",
            "no-primary-smartdeed-purchase-with-sols",
        ],
        "adjustable_statutes": [
            "voting-window",
            "support-threshold",
            "proposal-stake",
            "nav-validity",
            "oracle-source-and-limits",
            "asset-haircuts",
            "collection-allocation-ceilings",
            "exchange-fee-and-split-within-cap",
            "reward-epochs",
            "bridge-route-activation",
            "scoped-operational-pauses",
        ],
        "base_state": _state(base),
        "bootstrap_deed_to_sols": {
            "inputs": {
                "state": _state(empty),
                "deed_value_micro_usd": "333000000",
            },
            "expected": _deed_to_sols(
                quote_deed_to_sols(
                    empty,
                    deed_value_micro_usd=333_000_000,
                )
            ),
        },
        "bootstrap_rounding": {
            "inputs": {
                "state": _state(empty),
                "deed_value_micro_usd": "100000000",
            },
            "expected": _deed_to_sols(
                quote_deed_to_sols(
                    empty,
                    deed_value_micro_usd=100_000_000,
                )
            ),
        },
        "dynamic_deed_to_sols_reserve_first": {
            "inputs": {
                "state": _state(base),
                "deed_value_micro_usd": "166500000",
            },
            "expected": _deed_to_sols(
                quote_deed_to_sols(
                    base,
                    deed_value_micro_usd=166_500_000,
                )
            ),
        },
        "dynamic_deed_to_sols_exact_mint": {
            "inputs": {
                "state": _state(live_state(reserve=20_000, total=420_000)),
                "deed_value_micro_usd": "166500000",
            },
            "expected": _deed_to_sols(
                quote_deed_to_sols(
                    live_state(reserve=20_000, total=420_000),
                    deed_value_micro_usd=166_500_000,
                )
            ),
        },
        "sols_to_deed": {
            "inputs": {
                "state": _state(base),
                "deed_value_micro_usd": "166500000",
            },
            "expected": _sols_to_deed(
                quote_sols_to_deed(
                    base,
                    deed_value_micro_usd=166_500_000,
                )
            ),
        },
        "treasury_contribution": {
            "inputs": {
                "state": _state(base),
                "amount_micro_usd": "33300000",
            },
            "expected_state": _state(
                contribute_treasury_assets(
                    base,
                    amount_micro_usd=33_300_000,
                )
            ),
        },
        "zero_backing_pause": {
            "inputs": {
                "state": _state(base),
                "proven_liabilities_micro_usd": "1332000000",
            },
            "expected_state": _state(
                set_proven_liabilities(
                    base,
                    amount_micro_usd=1_332_000_000,
                )
            ),
            "deed_to_sols_blocked": True,
            "sols_to_deed_blocked": True,
        },
        "collection_revaluation": {
            "inputs": {
                "state": _state(base),
                "previous_collection_inventory_micro_usd": "333000000",
                "next_collection_inventory_micro_usd": "399600000",
            },
            "expected_state": _state(
                revalue_pool_inventory(
                    base,
                    previous_collection_inventory_micro_usd=333_000_000,
                    next_collection_inventory_micro_usd=399_600_000,
                )
            ),
        },
        "settlement_allocation": {
            "inputs": {
                "total_micro_usd": "100000001",
                "shares": _integer_strings(
                    [asdict(item) for item in settlement_shares]
                ),
            },
            "expected": _integer_strings(
                [
                    asdict(item)
                    for item in allocate_settlement(
                        100_000_001,
                        settlement_shares,
                    )
                ]
            ),
        },
        "settlement_tie_break": {
            "inputs": {
                "total_micro_usd": "1",
                "shares": _integer_strings(
                    [
                        asdict(SettlementShare("deed-b", 500_000)),
                        asdict(SettlementShare("deed-a", 500_000)),
                    ]
                ),
            },
            "expected": _integer_strings(
                [
                    asdict(item)
                    for item in allocate_settlement(
                        1,
                        (
                            SettlementShare("deed-b", 500_000),
                            SettlementShare("deed-a", 500_000),
                        ),
                    )
                ]
            ),
        },
    }


def fixture_destination() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "sols-economics-v3.fixtures.json"
    )


def main() -> None:
    fixture = build_fixture()
    destination = fixture_destination()
    destination.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"wrote fixture to {destination}")


if __name__ == "__main__":
    main()
