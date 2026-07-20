from __future__ import annotations

import json

from scripts.dump_payment_artifacts_v2_fixtures import (
    build_fixture,
    fixture_destination,
)


def test_payment_artifact_fixture_is_current() -> None:
    destination = fixture_destination()
    assert destination.exists(), (
        f"Fixture missing at {destination}. Run "
        "`.venv/bin/python scripts/dump_payment_artifacts_v2_fixtures.py`."
    )
    assert json.loads(destination.read_text()) == build_fixture(), (
        f"Fixture {destination} is stale. Re-run "
        "`.venv/bin/python scripts/dump_payment_artifacts_v2_fixtures.py`."
    )


def test_payment_artifact_fixture_covers_each_rail_and_transition() -> None:
    fixture = build_fixture()
    assert set(fixture["purchaseArtifacts"]) == {
        "stripe",
        "evmTestUsdBaseSepolia",
        "chiaXch",
        "chiaCat",
    }
    assert set(fixture["vaultAuthorizations"]) == {
        "chiaBls",
        "evmEip712",
    }
    assert set(fixture["paymentAttestations"]) == {
        "pending",
        "succeeded",
        "manualRelease",
    }
    for value in fixture["purchaseArtifacts"].values():
        assert value["programHex"].startswith("0x")
        assert len(value["artifactHash"]) == 66
        assert len(value["purchaseId"]) == 66
