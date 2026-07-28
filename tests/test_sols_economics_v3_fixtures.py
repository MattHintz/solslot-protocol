from __future__ import annotations

import json

from scripts.dump_sols_economics_v3_fixtures import (
    build_fixture,
    fixture_destination,
)


def test_sols_economics_v3_fixture_is_current() -> None:
    destination = fixture_destination()
    assert destination.exists(), (
        "Sols Economics V3 fixture is missing. Run "
        "`.venv/bin/python scripts/dump_sols_economics_v3_fixtures.py`."
    )
    assert json.loads(destination.read_text()) == build_fixture(), (
        "Sols Economics V3 fixture is stale. Run "
        "`.venv/bin/python scripts/dump_sols_economics_v3_fixtures.py`."
    )


def test_sols_economics_v3_fixture_has_expected_contract() -> None:
    fixture = build_fixture()
    assert fixture["schema"] == "solslot.sols-economics.v3"
    assert fixture["constants"]["bootstrap_value_micro_usd_per_sols"] == "3330000"
    assert fixture["constants"]["max_exchange_fee_bps"] == "100"
    assert "no-sols-melt" in fixture["permanent_invariants"]
    assert "protocol-only-smartdeed-sols-swaps" in fixture["permanent_invariants"]
    assert fixture["bootstrap_deed_to_sols"]["expected"]["seller_sols_mojos"] == "100000"
    assert fixture["sols_to_deed"]["expected"]["fee_split"] == {
        "total_fee_sols_mojos": "500",
        "protocol_fee_sols_mojos": "150",
        "sgt_rewards_fee_sols_mojos": "350",
    }
