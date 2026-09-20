"""Executed synthetic CLVM controls; not a live payment or review receipt."""
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.puzzles.singleton_top_layer_v1_1 import lineage_proof_for_coinsol
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint64

from solslot_puzzles import load_puzzle, verify_puzzle_checksum, PUZZLE_FILENAMES, FROZEN_CHECKSUM
from solslot_puzzles.alpha_payment_profile import BASE_MAINNET_ALPHA_TEST_ASSET_ID, alpha_payment_profile
from solslot_puzzles.inventory_activation import validate_inventory_activation, validate_inventory_recovery
from solslot_puzzles.payment_artifacts_v2 import PaymentRail, PaymentArtifactError
from solslot_puzzles.stripe_settlement_v1_driver import (
    build_inventory_reservation_spend, build_inventory_release_spend,
    build_inventory_extension_spend, inventory_terms_for_puzzle_hash, make_mint_offer_v5_inner,
)
from tests.test_inventory_available_v2 import fixture, execute, assert_output, assert_signed
from tests.test_stripe_settlement_v1_driver import b32
from tests.test_artifact_schema_v4 import _artifact
from tests.test_inventory_mint_activation import activation as legacy_activation


def mainnet_fixture():
    terms, struct, reservation, previous = fixture(PaymentRail.STRIPE, 3)
    a = reservation.artifact
    purchase = replace(a, rail=PaymentRail.EVM_TEST_USD, rail_chain_id=8453,
        rail_asset_id=BASE_MAINNET_ALPHA_TEST_ASSET_ID, rail_asset_decimals=6,
        rail_amount=a.subtotal_minor * 10000)
    reservation = replace(reservation, artifact=purchase)
    transition = build_inventory_reservation_spend(available_coin=previous.spend.coin,
        deed_singleton_struct=struct, lineage_proof=LineageProof(b32(90), amount=uint64(1)),
        reservation=reservation, signer_indices=(0, 2), terms=terms)
    return terms, struct, reservation, transition


def test_mainnet_test_token_reserves_extends_and_returns_to_the_same_inventory_version():
    terms, struct, reservation, transition = mainnet_fixture()
    conditions = execute(transition.spend)
    assert_output(transition.spend, conditions, transition.reserved_coin)
    assert_signed(transition.spend, conditions, transition.validator_message)
    for timed_out in (True, False):
        release = build_inventory_release_spend(reserved_coin=transition.reserved_coin,
            deed_singleton_struct=struct, lineage_proof=lineage_proof_for_coinsol(transition.spend),
            reservation=reservation, terms=terms, timed_out=timed_out, signer_indices=() if timed_out else (0, 2))
        released = execute(release.spend)
        assert_output(release.spend, released, release.next_coin)
        assert release.next_coin.puzzle_hash == transition.spend.coin.puzzle_hash
        if not timed_out:
            assert_signed(release.spend, released, release.validator_message)
    extension = build_inventory_extension_spend(reserved_coin=transition.reserved_coin,
        deed_singleton_struct=struct, lineage_proof=lineage_proof_for_coinsol(transition.spend),
        reservation=reservation, terms=terms, next_expires_at=reservation.expires_at + 60,
        signer_indices=(0, 2))
    extended = execute(extension.spend)
    assert_output(extension.spend, extended, extension.next_coin)
    assert_signed(extension.spend, extended, extension.validator_message)
    assert inventory_terms_for_puzzle_hash(replace(terms, inventory_version=2), struct,
        transition.spend.coin.puzzle_hash) == terms
    assert inventory_terms_for_puzzle_hash(replace(terms, inventory_version=2), struct,
        transition.reserved_coin.puzzle_hash, reservation=reservation) == terms


@pytest.mark.parametrize("position,value", [
    (11, 84532), (11, 1),
    (12, bytes.fromhex("000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913")),
    (12, bytes.fromhex("000000000000000000000000036cbd53842c5426634e7929541ec2318f3dcf7e")),
    (12, bytes(32)), (13, 18), (14, 1), (21, [0]), (21, [0, 0]), (21, [2, 0]),
])
def test_clvm_rejects_other_networks_usdc_tokens_amounts_and_quorums(position, value):
    _, _, _, transition = mainnet_fixture()
    solution = Program.from_bytes(bytes(transition.spend.solution)).as_python()
    solution[2][position] = value
    with pytest.raises(ValueError):
        Program.from_bytes(bytes(transition.spend.puzzle_reveal)).run_with_cost(11_000_000_000, Program.to(solution))


def test_new_driver_does_not_relabel_a_historical_purchase_or_coin():
    terms, struct, reservation, transition = mainnet_fixture()
    with pytest.raises(PaymentArtifactError, match="TEST-SOLS"):
        make_mint_offer_v5_inner(terms, replace(reservation, artifact=replace(reservation.artifact, rail_chain_id=84532)))
    with pytest.raises(PaymentArtifactError):
        build_inventory_release_spend(reserved_coin=transition.reserved_coin,
            deed_singleton_struct=struct, lineage_proof=lineage_proof_for_coinsol(transition.spend),
            reservation=reservation, terms=replace(terms, inventory_version=2), timed_out=True)
    with pytest.raises(PaymentArtifactError, match="Testnet11"):
        replace(terms, network="mainnet")


@pytest.mark.parametrize("rail", [PaymentRail.STRIPE, PaymentRail.CHIA_XCH, PaymentRail.CHIA_CAT])
def test_other_rails_still_execute_under_explicit_new_inventory(rail):
    _, _, _, transition = fixture(rail, 3)
    assert_output(transition.spend, execute(transition.spend), transition.reserved_coin)


def selected_artifact():
    a = _artifact()
    # Pure selection metadata only; validate_inventory_activation does not
    # authenticate a release. No fake signatures or review approval are made.
    a["enrollmentActivation"] = {"schema": "solslot.enrollment-activation.v2", "evmChainId": 8453}
    a["inventoryActivation"] = {**legacy_activation(a), "schema": "solslot.inventory-activation.v2",
        "inventoryVersion": 3, "adapterVersion": 2,
        "availableModuleHash": "0x" + load_puzzle("mint_offer_inventory_available_v3.clsp").get_tree_hash().hex(),
        "reservedModuleHash": "0x" + load_puzzle("mint_offer_delegate_v6.clsp").get_tree_hash().hex(),
        "paymentProfile": alpha_payment_profile()}
    return a


def test_activation_requires_new_schema_exact_profile_and_mainnet_enrollment():
    a = selected_artifact()
    assert validate_inventory_activation(a)["inventoryVersion"] == 3
    old = copy.deepcopy(a)
    old["inventoryActivation"]["schema"] = "solslot.inventory-activation.v1"
    with pytest.raises(ValueError): validate_inventory_activation(old)
    for enrollment in (None, {"schema": "solslot.enrollment-activation.v1", "evmChainId": 8453}):
        changed = copy.deepcopy(a); changed["enrollmentActivation"] = enrollment
        with pytest.raises(ValueError): validate_inventory_activation(changed)
    legacy = _artifact(); legacy["inventoryActivation"] = legacy_activation(legacy)
    assert validate_inventory_activation(legacy)["inventoryVersion"] == 2


@pytest.mark.parametrize("field,value", [("chainId",84532), ("tokenAddress","0x"+"11"*20),
    ("tokenDecimals",18), ("tokenSymbol","USDC"), ("assetNetwork","mainnet"),
    ("hasMonetaryValue",0), ("hasMonetaryValue",True), ("tokenRuntimeCodeHash","0x"+"12"*32)])
def test_activation_rejects_changed_payment_profile(field, value):
    a = selected_artifact(); a["inventoryActivation"]["paymentProfile"][field] = value
    with pytest.raises(ValueError): validate_inventory_activation(a)


def test_recovery_uses_explicit_version_without_reinterpreting_v1():
    a = selected_artifact(); active = a["inventoryActivation"]
    a["inventoryRecovery"] = dict(schema="solslot.inventory-recovery.v2", network="testnet11",
        environment=active["environment"], deploymentId=active["deploymentId"], inventoryVersion=3,
        adapterVersion=2, validatorLedgerVersion=10, minConfirmations=3,
        availableModuleHash=active["availableModuleHash"], sourceShas=a["sourceShas"],
        reviewEvidenceSha256="cd"*32, historicalArtifactHashes=[])
    assert validate_inventory_recovery(a)["inventoryVersion"] == 3
    a["inventoryRecovery"]["schema"] = "solslot.inventory-recovery.v1"
    with pytest.raises(ValueError): validate_inventory_recovery(a)


def test_manifest_pins_additions_and_all_historical_bytes():
    root = Path(__file__).parents[1]
    manifest = json.loads((root/"release-manifests/base-test-token-draft63-puzzle-hashes.json").read_text())
    assert manifest["deployable"] is False
    assert tuple(manifest["puzzleHashes"]) == PUZZLE_FILENAMES
    assert manifest["canonicalChecksum"] == FROZEN_CHECKSUM
    assert manifest["replacements"] == []
    verify_puzzle_checksum()
    for row in manifest["preserved"] + manifest["additions"]:
        for suffix, field in [("", "sourceSha256"), (".hex", "hexSha256")]:
            assert hashlib.sha256((root/"solslot_puzzles"/(row["filename"]+suffix)).read_bytes()).hexdigest() == row[field]
        assert load_puzzle(row["filename"]).get_tree_hash().hex() == row["treeHash"]
