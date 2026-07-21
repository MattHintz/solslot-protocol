"""Guard the cross-repo SGT VOTE spend fixture.

The portal's Karma test reads
``solslot-portal/src/app/services/sgt-driver/sgt-vote-spend.fixtures.json``
to assert its TS spend-builder matches Python byte-for-byte.  This pytest
re-runs the dumper and asserts the on-disk fixture is up to date so PRs
that change ``sgt_driver.build_sgt_lock_coin_spend`` or
``build_tracker_vote_coin_spend`` without updating the fixture fail CI here
rather than at the portal Karma layer.
"""
from __future__ import annotations

import json
from pathlib import Path

from scripts.dump_sgt_vote_spend_fixtures import (
    build_cat_mod_hex_module,
    build_fixture,
    cat_mod_hex_destination,
    fixture_destination,
)


def test_fixture_is_current() -> None:
    dest = fixture_destination()
    assert dest.exists(), (
        f"Fixture missing at {dest}. Run "
        "`.venv/bin/python scripts/dump_sgt_vote_spend_fixtures.py`."
    )
    expected = build_fixture()
    on_disk = json.loads(dest.read_text())
    assert on_disk == expected, (
        f"Fixture {dest} is stale. Re-run "
        "`.venv/bin/python scripts/dump_sgt_vote_spend_fixtures.py`."
    )


def test_cat_mod_hex_module_is_current() -> None:
    dest = cat_mod_hex_destination()
    assert dest.exists(), (
        f"CAT mod hex module missing at {dest}. Run "
        "`.venv/bin/python scripts/dump_sgt_vote_spend_fixtures.py`."
    )
    expected = build_cat_mod_hex_module()
    on_disk = dest.read_text()
    assert on_disk == expected, (
        f"CAT mod hex module {dest} is stale. Re-run "
        "`.venv/bin/python scripts/dump_sgt_vote_spend_fixtures.py`."
    )


def test_fixture_schema_keys() -> None:
    fix = build_fixture()
    assert set(fix.keys()) == {"constants", "sgt_lock", "tracker_vote"}
    assert set(fix["sgt_lock"].keys()) == {"inputs", "expected"}
    assert set(fix["tracker_vote"].keys()) == {"inputs", "expected"}
    for section in ("sgt_lock", "tracker_vote"):
        exp = fix[section]["expected"]
        assert exp["puzzle_reveal_hex"].startswith("0x")
        assert exp["solution_hex"].startswith("0x")
        assert exp["coin_spend_hex"].startswith("0x")
        coin = exp["coin"]
        assert set(coin.keys()) == {"parentCoinInfo", "puzzleHash", "amount"}
