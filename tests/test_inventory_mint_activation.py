import copy
import json
from pathlib import Path
import pytest

from solslot_puzzles import load_puzzle
from solslot_puzzles.inventory_activation import validate_inventory_activation
from solslot_puzzles.artifact_schema_v4 import artifact_hash, verify_public_artifact
from tests.test_artifact_schema_v4 import _artifact, _accept
from scripts.dump_inventory_mint_fixtures import build_inventory_fixture, constants


def activation(artifact):
    return dict(schema="solslot.inventory-activation.v1", network="testnet11", environment="staging-alpha",
        deploymentId=artifact["ceremony"]["ceremonyId"], inventoryVersion=2, adapterVersion=1,
        availableModuleHash="0x"+load_puzzle("mint_offer_inventory_available_v2.clsp").get_tree_hash().hex(),
        reservedModuleHash="0x"+load_puzzle("mint_offer_delegate_v5.clsp").get_tree_hash().hex(),
        sourceShas=copy.deepcopy(artifact["sourceShas"]), reviewEvidenceSha256="ab"*32)


def test_optional_extension_preserves_historical_artifact_and_binds_canonical_hash():
    value = _artifact()
    original = copy.deepcopy(value)
    assert validate_inventory_activation(value) is None
    with pytest.raises(ValueError): validate_inventory_activation(value, required=True)
    value["inventoryActivation"] = activation(value)
    with pytest.raises(ValueError, match="artifactHash"):
        verify_public_artifact(value, signature_verifier=_accept)
    value["artifactHash"] = artifact_hash(value)
    verify_public_artifact(value, signature_verifier=_accept)  # synthetic signature verifier, not approval
    assert value["puzzleHashes"] == original["puzzleHashes"]
    assert value["genesisPlan"] == original["genesisPlan"]
    with pytest.raises(ValueError): validate_inventory_activation(value, environment="production-alpha")


@pytest.mark.parametrize("field,value", [
    ("network", "mainnet"), ("inventoryVersion", 1), ("inventoryVersion", True), ("adapterVersion", True),
    ("deploymentId", "0x"+"00"*32), ("availableModuleHash", "0x"+"00"*32),
    ("reservedModuleHash", "0x"+"00"*32), ("sourceShas", {}), ("environment", "production-beta"),
    ("reviewEvidenceSha256", "00"*32), ("reviewEvidenceSha256", "missing")])
def test_mismatched_activation_rejected_even_with_updated_artifact_hash(field, value):
    artifact = _artifact(); artifact["inventoryActivation"] = activation(artifact)
    artifact["inventoryActivation"][field] = value
    artifact["artifactHash"] = artifact_hash(artifact)
    with pytest.raises(ValueError, match="activation"):
        verify_public_artifact(artifact, signature_verifier=_accept)


def test_generated_inventory_fixtures_and_embedded_puzzles_are_current():
    root = Path(__file__).resolve().parents[1]
    raw = (root/"fixtures/mint-proposal-v2/inventory-mint.fixtures.json").read_text()
    assert json.loads(raw) == build_inventory_fixture()
    portal = root.parent/"admin-portal/src/app/services/mint-proposal-v2"
    assert (portal/"inventory-mint.fixtures.json").read_text() == raw
    assert (portal/"inventory-puzzles.ts").read_text() == constants()
