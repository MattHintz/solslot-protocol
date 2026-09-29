from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from solslot_puzzles.identity_deployment_amendment import (
    ConfirmedAmendmentAnchor,
    ZERO_HASH,
    amendment_hash,
    announcement_message,
    build_statement,
    canonical_json,
    parse_canonical_statement,
    resolve_effective_identity_deployment,
    verify_statement_against_records,
)


BASE_PATH = Path("/home/hiram/solslot-work/e2e-audit-draft144/evidence/public-artifact.json")
DEPLOYMENT_PATH = Path(
    "/home/hiram/secure/solslot-deployments/"
    "AE-SOLSLOT-IDENTITY-COMPATIBILITY-20260928-148/deployment.json"
)
PLAN_HASH = "0xdb9912f4e47ec349d6fb67aa95f78058f8c64c757a22a2244af8f0d9a73a381b"


@pytest.fixture()
def records():
    return json.loads(BASE_PATH.read_text()), json.loads(DEPLOYMENT_PATH.read_text())


@pytest.fixture()
def statement(records):
    base, deployment = records
    return build_statement(
        base_artifact=base,
        deployment_artifact=deployment,
        deployment_plan_hash=PLAN_HASH,
        activation_source_shas={"protocol": "1" * 40, "api": "2" * 40},
        activation_boundary={
            "authorityLauncherId": base["launcherIds"]["adminAuthority"],
            "authorityCoinId": "0x" + "aa" * 32,
            "authorityVersion": 2,
            "rosterIdentityCoinIds": ["0x" + f"{n:02x}" * 32 for n in (1, 2, 3)],
            "signerSlots": [0, 1],
            "signerIdentityCoinIds": ["0x" + f"{n:02x}" * 32 for n in (1, 2)],
        },
        revision=1,
        previous_amendment_hash=ZERO_HASH,
        approval_expires_at=2_000_000_000,
    )


def anchor_for(statement):
    digest = amendment_hash(statement)
    boundary = statement["activationBoundary"]
    return ConfirmedAmendmentAnchor(
        amendment_hash=digest,
        authority_launcher_id=boundary["authorityLauncherId"],
        spent_authority_coin_id=boundary["authorityCoinId"],
        authority_version=boundary["authorityVersion"],
        confirmed_height=4_800_000,
        confirmed_timestamp=1_999_999_900,
        announcement=announcement_message(digest),
    )


def test_resolves_without_mutating_genesis(records, statement):
    base, deployment = records
    original = copy.deepcopy(base)
    resolved = resolve_effective_identity_deployment(
        base_artifact=base,
        deployment_artifact=deployment,
        deployment_plan_hash=PLAN_HASH,
        statement=statement,
        anchor=anchor_for(statement),
    )
    assert base == original
    assert resolved["source"] == "confirmed-authority-amendment"
    assert resolved["addresses"]["verifierAdapter"] == deployment["verifierAdapterAddress"]
    assert resolved["acceptedProofVersions"] == ["0.20.0", "0.21.0"]
    assert base["evmAddresses"]["verifierAdapter"] != resolved["addresses"]["verifierAdapter"]


def test_canonical_round_trip_and_duplicate_rejection(statement):
    raw = canonical_json(statement)
    assert parse_canonical_statement(raw) == statement
    with pytest.raises(ValueError, match="not canonical"):
        parse_canonical_statement(json.dumps(statement))
    with pytest.raises(ValueError, match="duplicate JSON key"):
        parse_canonical_statement('{"schema":"a","schema":"b"}')


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("newDeployment", "acceptedProofVersions"), ["0.21.0"], "accepted proof versions"),
        (("identityPolicy", "domain"), "staging.solslot.com", "approved production policy"),
        (("identityPolicy", "minimumAge"), 21, "approved production policy"),
        (("identityPolicy", "devMode"), True, "approved production policy"),
        (("identityPolicy", "realDocumentOnly"), False, "approved production policy"),
        (("identityPolicy", "sanctions", "strict"), True, "approved production policy"),
        (("chiaBridgePolicyHash",), "0x" + "91" * 32, "bridge policy hash changed"),
        (("newDeployment", "runtimeCodeHashes", "forwarder"), "0x" + "92" * 32, "deployment evidence"),
        (("newDeployment", "transactions", "forwarder", "hash"), "0x" + "93" * 32, "deployment evidence"),
        (("newDeployment", "immutableBindings", "emitterForwarder"), "0x" + "94" * 20, "immutable contract bindings"),
    ],
)
def test_tampering_fails_closed(records, statement, path, replacement, message):
    base, deployment = records
    changed = copy.deepcopy(statement)
    cursor = changed
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = replacement
    with pytest.raises(ValueError, match=message):
        verify_statement_against_records(
            changed,
            base_artifact=base,
            deployment_artifact=deployment,
            deployment_plan_hash=PLAN_HASH,
        )


def test_schema_rejects_extra_fields(statement):
    statement["coordinatorApproved"] = True
    with pytest.raises(ValueError, match="fields mismatch"):
        amendment_hash(statement)


def test_activation_boundary_requires_owner_plus_one(statement):
    statement["activationBoundary"]["signerSlots"] = [1, 2]
    statement["activationBoundary"]["signerIdentityCoinIds"] = statement[
        "activationBoundary"
    ]["rosterIdentityCoinIds"][1:]
    with pytest.raises(ValueError, match="owner slot 0"):
        amendment_hash(statement)


def test_anchor_rejects_rollback_replay_and_expiry(statement):
    good = anchor_for(statement)
    stale = copy.deepcopy(statement)
    stale["activationBoundary"]["authorityCoinId"] = "0x" + "44" * 32
    with pytest.raises(ValueError, match="amendment hash mismatch"):
        good.verify(stale)
    expired = ConfirmedAmendmentAnchor(
        **{**good.__dict__, "confirmed_timestamp": statement["approvalExpiresAt"] + 1}
    )
    with pytest.raises(ValueError, match="after approval expiry"):
        expired.verify(statement)


def test_revision_chain_is_contiguous(records, statement):
    base, deployment = records
    statement["revision"] = 2
    statement["previousAmendmentHash"] = "0x" + "12" * 32
    with pytest.raises(ValueError, match="not contiguous"):
        verify_statement_against_records(
            statement,
            base_artifact=base,
            deployment_artifact=deployment,
            deployment_plan_hash=PLAN_HASH,
            previous_amendment_hash="0x" + "13" * 32,
        )


def test_mixed_or_unconfirmed_rollout_cannot_resolve(records, statement):
    base, deployment = records
    wrong_anchor = ConfirmedAmendmentAnchor(
        **{**anchor_for(statement).__dict__, "amendment_hash": "0x" + "bb" * 32}
    )
    with pytest.raises(ValueError, match="anchor amendment hash mismatch"):
        resolve_effective_identity_deployment(
            base_artifact=base,
            deployment_artifact=deployment,
            deployment_plan_hash=PLAN_HASH,
            statement=statement,
            anchor=wrong_anchor,
        )
