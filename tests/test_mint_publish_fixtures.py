"""Guard the cross-repo mint-publish fixture (Phase 4b).

The portal's Karma test (sub-brick 4c) reads the protocol-owned
``fixtures/mint-proposal-v2/mint-publish.fixtures.json`` artifact
to assert its TS port of ``build_mint_publish_artifacts`` matches the Python
driver byte-for-byte.  This pytest re-runs the dumper and asserts the on-disk
fixture is up to date so PRs that change
:mod:`solslot_puzzles.mint_publish_driver` (or any of its upstream puzzles)
without refreshing the fixture fail CI here rather than at the portal Karma
layer.
"""
from __future__ import annotations

import json

from scripts.dump_mint_publish_fixtures import (
    build_fixture,
    fixture_destination,
)


def test_fixture_is_current() -> None:
    dest = fixture_destination()
    assert dest.exists(), (
        f"Fixture missing at {dest}. Run "
        "`.venv/bin/python scripts/dump_mint_publish_fixtures.py`."
    )
    expected = build_fixture()
    on_disk = json.loads(dest.read_text())
    assert on_disk == expected, (
        f"Fixture {dest} is stale. Re-run "
        "`.venv/bin/python scripts/dump_mint_publish_fixtures.py`."
    )


def test_fixture_top_level_schema_keys() -> None:
    fix = build_fixture()
    assert set(fix.keys()) == {
        "constants",
        "inputs",
        "expected",
        # Sub-brick 4d.1 spend-bundle sections (each {inputs, expected}).
        "proposal_eve_launch",
        "tracker_propose",
        "pgt_first_vote",
        "property_registry_registration",
    }


def test_spend_sections_have_inputs_and_expected() -> None:
    """Every spend section follows the ``{inputs, expected}`` shape."""
    fix = build_fixture()
    for section in (
        "proposal_eve_launch",
        "tracker_propose",
        "pgt_first_vote",
        "property_registry_registration",
    ):
        assert set(fix[section].keys()) == {"inputs", "expected"}, (
            f"section {section!r} has unexpected keys: {set(fix[section].keys())}"
        )


def test_proposal_eve_launch_expected_keys() -> None:
    fix = build_fixture()
    exp = fix["proposal_eve_launch"]["expected"]
    assert set(exp.keys()) == {
        "parent_conditions_hex",
        "launcher_coin",
        "launcher_puzzle_reveal_hex",
        "launcher_solution_hex",
        "launcher_coin_spend_hex",
        "eve_coin",
        "eve_full_puzzle_hash",
    }
    # parent_conditions_hex is a list of 0x-hex strings.
    assert isinstance(exp["parent_conditions_hex"], list)
    assert len(exp["parent_conditions_hex"]) >= 2  # CREATE_COIN + ASSERT_COIN_ANN
    for cond in exp["parent_conditions_hex"]:
        assert cond.startswith("0x")


def test_tracker_propose_expected_keys() -> None:
    fix = build_fixture()
    exp = fix["tracker_propose"]["expected"]
    assert set(exp.keys()) == {
        "coin",
        "puzzle_reveal_hex",
        "solution_hex",
        "coin_spend_hex",
    }
    assert exp["coin_spend_hex"].startswith("0x")


def test_pgt_first_vote_expected_keys() -> None:
    fix = build_fixture()
    exp = fix["pgt_first_vote"]["expected"]
    assert set(exp.keys()) == {
        "coin",
        "puzzle_reveal_hex",
        "solution_hex",
        "coin_spend_hex",
    }
    assert exp["coin_spend_hex"].startswith("0x")


def test_property_registry_registration_expected_keys() -> None:
    fix = build_fixture()
    exp = fix["property_registry_registration"]["expected"]
    assert set(exp.keys()) == {
        "coin",
        "puzzle_reveal_hex",
        "solution_hex",
        "coin_spend_hex",
        "announcement_id",
        "new_inner_puzzle_hash",
        "new_registered_ids_root",
        "agg_sig_me_message",
    }
    assert exp["coin_spend_hex"].startswith("0x")
    for key in (
        "announcement_id",
        "new_inner_puzzle_hash",
        "new_registered_ids_root",
        "agg_sig_me_message",
    ):
        assert exp[key].startswith("0x")
        assert len(exp[key]) == 2 + 64


def test_fixture_constants_keys() -> None:
    """Pin the constants block — drift here means a TS mirror needs an update."""
    fix = build_fixture()
    assert set(fix["constants"].keys()) == {
        "bill_mint_tag",
        "singleton_amount",
        "singleton_mod_hash",
        "singleton_launcher_hash",
        "protocol_did_singleton_struct_hex",
        "protocol_did_singleton_struct_hash",
        "protocol_did_launcher_id",
    }
    # Pin the literal BILL_MINT tag — it's part of the on-chain wire format.
    assert fix["constants"]["bill_mint_tag"] == 0x4D
    assert fix["constants"]["singleton_amount"] == 1


def test_fixture_inputs_keys() -> None:
    """Pin the input field surface that the TS service must accept."""
    fix = build_fixture()
    assert set(fix["inputs"].keys()) == {
        "property_id_canon",
        "collection_id_canon",
        "share_ppm",
        "par_value_mojos",
        "asset_class",
        "jurisdiction_hex",
        "royalty_puzhash",
        "royalty_bps",
        "quorum_threshold",
        "owner_member_hash",
        "gov_member_hash",
        "deed_launcher_parent_coin_name",
        "proposal_launcher_parent_coin_name",
        "protocol_did_puzhash",
        "p2_pool_mod_hash",
        "p2_vault_mod_hash",
        "property_registry_puzzle_hash",
    }


def test_fixture_expected_keys() -> None:
    """Pin the expected-output surface the TS service must reproduce."""
    fix = build_fixture()
    assert set(fix["expected"].keys()) == {
        # 4 computed.*_puzhash row.
        "smart_deed_inner_puzhash",
        "eve_inner_puzhash",
        "deed_full_puzhash",
        "proposal_hash",
        # Launcher coin ids.
        "deed_launcher_id",
        "proposal_singleton_launcher_id",
        # Artifact A binding hash.
        "proposal_data_hash",
        # Auxiliary programs (each serialized as hex + paired with tree hash).
        "bill_op_program_hex",
        "bill_op_program_hash",
        "deed_singleton_struct_program_hex",
        "deed_singleton_struct_program_hash",
        "proposal_singleton_struct_program_hex",
        "proposal_singleton_struct_program_hash",
    }


def test_fixture_hash_fields_are_0x_prefixed_32_bytes() -> None:
    """Every hash field is ``0x`` + 64 hex chars; programs are ``0x`` + N hex."""
    fix = build_fixture()
    hash_fields = {
        "smart_deed_inner_puzhash",
        "eve_inner_puzhash",
        "deed_full_puzhash",
        "proposal_hash",
        "deed_launcher_id",
        "proposal_singleton_launcher_id",
        "proposal_data_hash",
        "bill_op_program_hash",
        "deed_singleton_struct_program_hash",
        "proposal_singleton_struct_program_hash",
    }
    for k in hash_fields:
        v = fix["expected"][k]
        assert v.startswith("0x"), f"{k} not 0x-prefixed: {v!r}"
        assert len(v) == 2 + 64, f"{k} not 32 bytes hex: {v!r}"

    # Program hex fields are 0x-prefixed but length-varying.
    for k in (
        "bill_op_program_hex",
        "deed_singleton_struct_program_hex",
        "proposal_singleton_struct_program_hex",
    ):
        v = fix["expected"][k]
        assert v.startswith("0x"), f"{k} not 0x-prefixed: {v!r}"
        assert len(v) > 2, f"{k} empty: {v!r}"


def test_fixture_matches_pinned_golden_vector() -> None:
    """Cross-check: fixture's expected values match the test_mint_publish_driver pin.

    This is a redundant safety net — both this fixture and
    ``TestBuildMintPublishArtifacts::test_golden_vector`` independently pin
    the same hash computation against the same inputs.  If a future driver
    change updates one pin but not the other, this test surfaces the drift.
    """
    fix = build_fixture()
    expected = fix["expected"]
    # Pinned in tests/test_mint_publish_driver.py::TestBuildMintPublishArtifacts.
    assert expected["smart_deed_inner_puzhash"] == (
        "0x7c136b467c78029bad205002a0c2f57bdd92a5f87dcaedc2bac233d378e3e0dd"
    )
    assert expected["eve_inner_puzhash"] == (
        "0xa88e74279e1f8b22d052d469f8e6505bbacba24aea48d5f18aa43d20d232383f"
    )
    assert expected["deed_full_puzhash"] == (
        "0xfbabfd153e14099e9b4f6241c12a3a955ba734ba6ab63213ad3095c587a24a83"
    )
    assert expected["proposal_hash"] == (
        "0x2687dd7f1541480a5b0167bca6d938b353ad4f93e21d6a0adaf9fda742afacda"
    )
    assert expected["deed_launcher_id"] == (
        "0x1310b78bf387ea58bb9365e261ff099a6971fd2ca5cc98e750b1d07e92e29b1d"
    )
    assert expected["proposal_singleton_launcher_id"] == (
        "0x1e92dd4960d1ddfbd84b857b4836285eb4f3abe13efd639f16fb3f25ee8af534"
    )
    assert expected["proposal_data_hash"] == (
        "0xf55fe9821001f5012b34cf0b3f87d97386fb9ab8b9f89813500479b58eb0fa95"
    )
