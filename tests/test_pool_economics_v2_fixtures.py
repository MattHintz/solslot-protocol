"""Guard the cross-repo Pool Economic V2 portal fixture."""
from __future__ import annotations

import json

from scripts.dump_pool_economics_v2_fixtures import (
    build_fixture,
    fixture_destination,
)


def test_fixture_is_current() -> None:
    dest = fixture_destination()
    assert dest.exists(), (
        f"Fixture missing at {dest}. Run "
        "`.venv/bin/python scripts/dump_pool_economics_v2_fixtures.py`."
    )
    assert json.loads(dest.read_text()) == build_fixture(), (
        f"Fixture {dest} is stale. Re-run "
        "`.venv/bin/python scripts/dump_pool_economics_v2_fixtures.py`."
    )


def test_fixture_top_level_schema_keys() -> None:
    fixture = build_fixture()
    assert set(fixture.keys()) == {
        "constants",
        "common",
        "specific_deed_swap",
        "true_redemption",
        "reserve_acquisition",
    }


def test_action_sections_have_inputs_and_expected() -> None:
    fixture = build_fixture()
    for section in ("specific_deed_swap", "true_redemption", "reserve_acquisition"):
        assert set(fixture[section].keys()) == {"inputs", "expected"}


def test_expected_action_spec_surface() -> None:
    fixture = build_fixture()
    expected_keys = {
        "action_tag",
        "quote",
        "next_state",
        "nav_evidence_message",
        "required_nav_evidence_message",
        "deed_commitment",
        "pool_action_message",
        "deed_message",
        "token_outputs",
        "token_authorizations",
        "inner_solution_hex",
        "pool_full_solution_hex",
        "pool_coin_spend",
    }
    assert expected_keys | {"token_settlement_payment_message"} == set(
        fixture["specific_deed_swap"]["expected"].keys()
    )
    assert expected_keys == set(fixture["true_redemption"]["expected"].keys())
    assert expected_keys == set(fixture["reserve_acquisition"]["expected"].keys())


def test_prefixed_messages_are_0x53_plus_hash() -> None:
    fixture = build_fixture()
    for section in ("specific_deed_swap", "true_redemption", "reserve_acquisition"):
        expected = fixture[section]["expected"]
        for key in (
            "required_nav_evidence_message",
            "pool_action_message",
            "deed_message",
        ):
            value = expected[key]
            assert value.startswith("0x53")
            assert len(value) == 2 + 1 * 2 + 32 * 2
