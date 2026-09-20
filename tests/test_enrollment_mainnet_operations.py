import copy

import pytest

from solslot_puzzles.artifact_schema_v4 import (
    _rebuild_plan, artifact_hash, build_public_artifact, verify_public_artifact,
)
from solslot_puzzles.enrollment_activation import (
    activation_from_artifact, enrollment_identity_chain_id,
)
from solslot_puzzles.enrollment_networks import (
    BASE_MAINNET_ENROLLMENT_SCHEMA, enrollment_operational_chain_id,
)
from solslot_puzzles.genesis_signing import genesis_artifact_signing_typed_data
from tests.test_artifact_schema_v4 import _artifact, _accept
from tests.test_enrollment_activation import activation, selected_artifact


def mainnet_artifact():
    original = _artifact()
    plan = copy.deepcopy(original["genesisPlan"])
    selected = activation(original, "production-alpha", 8453)
    selected["schema"] = BASE_MAINNET_ENROLLMENT_SCHEMA
    plan["enrollmentActivation"] = selected
    plan["evmChainId"] = 8453
    return build_public_artifact(
        plan=_rebuild_plan({"genesisPlan": plan}),
        spend_bundle_id=original["ceremony"]["spendBundleId"],
        confirmed_block_index=1234,
        build_timestamp=original["buildTimestamp"],
        signatures=original["signatures"],
        review_class=original["reviewClass"],
    )


def test_mainnet_operations_reconstruct_with_testnet11_assets():
    value = mainnet_artifact()
    verify_public_artifact(value, signature_verifier=_accept)
    selected = activation_from_artifact(value, environment="production-alpha")
    assert enrollment_operational_chain_id(selected) == 8453
    assert enrollment_identity_chain_id(value) == 8453
    assert value["evmChainId"] == value["genesisPlan"]["evmChainId"] == 8453
    assert value["network"] == value["genesisPlan"]["network"] == "testnet11"
    assert genesis_artifact_signing_typed_data(value)["domain"]["chainId"] == 8453


@pytest.mark.parametrize("chain", [84532, 11155111, 1, True, "8453"])
def test_mainnet_profile_rejects_wrong_operational_domain(chain):
    value = mainnet_artifact()
    value["evmChainId"] = chain
    value["genesisPlan"]["evmChainId"] = chain
    value["artifactHash"] = artifact_hash(value)
    with pytest.raises(ValueError):
        verify_public_artifact(value, signature_verifier=_accept)
    with pytest.raises(ValueError):
        genesis_artifact_signing_typed_data(value)


def test_legacy_profiles_keep_their_original_domains_and_reject_relabeling():
    legacy = _artifact()
    assert genesis_artifact_signing_typed_data(legacy)["domain"]["chainId"] == 11155111
    for identity_chain in (8453, 84532):
        value = selected_artifact("production-alpha", identity_chain)
        assert genesis_artifact_signing_typed_data(value)["domain"]["chainId"] == 84532
        value["enrollmentActivation"]["schema"] = BASE_MAINNET_ENROLLMENT_SCHEMA
        value["genesisPlan"]["enrollmentActivation"]["schema"] = BASE_MAINNET_ENROLLMENT_SCHEMA
        value["artifactHash"] = artifact_hash(value)
        with pytest.raises(ValueError):
            verify_public_artifact(value, signature_verifier=_accept)


@pytest.mark.parametrize("value", [
    {}, [], False,
    {"schema": "solslot.enrollment-activation.v3", "evmChainId": 8453},
    {"schema": BASE_MAINNET_ENROLLMENT_SCHEMA, "evmChainId": 84532},
    {"schema": BASE_MAINNET_ENROLLMENT_SCHEMA, "evmChainId": "8453"},
])
def test_network_selection_has_no_implicit_mainnet_fallback(value):
    with pytest.raises(ValueError):
        enrollment_operational_chain_id(value)
