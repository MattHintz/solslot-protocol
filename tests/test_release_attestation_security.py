from __future__ import annotations

import copy

import pytest

from tests.test_testnet_genesis_preflight import preflight


def valid_attestation() -> tuple[dict, dict]:
    artifact = {
        "artifactHash": "0x" + "ab" * 32,
        "sourceShas": {name: str(index) * 40 for index, name in enumerate(preflight.CONSUMERS, 1)},
    }
    attestation = {
        "schemaVersion": preflight.ARTIFACT_SCHEMA_VERSION,
        "sourceManifestVersion": preflight.SOURCE_MANIFEST_VERSION,
        "protocolVersion": preflight.PROTOCOL_VERSION,
        "network": "testnet11",
        "artifactHash": artifact["artifactHash"],
        "writeLocks": {
            "alphaWritesEnabled": False,
            "mintingEnabled": False,
            "ceremonyModeEnabled": False,
        },
        "consumers": {
            name: {
                "reachable": True,
                "artifactHash": artifact["artifactHash"],
                "sourceSha": source,
                "observedAt": "informational-field-is-allowed",
            }
            for name, source in artifact["sourceShas"].items()
        },
    }
    return attestation, artifact


@pytest.mark.parametrize("field", ["writeLocks", "consumers", *preflight.CONSUMERS])
@pytest.mark.parametrize("value", [{}, None, [], False, ""])
def test_release_attestation_rejects_empty_and_wrong_type_evidence(field: str, value) -> None:
    attestation, artifact = valid_attestation()
    target = attestation if field in ("writeLocks", "consumers") else attestation["consumers"]
    target[field] = value
    findings: list[preflight.Finding] = []

    preflight._validate_release_attestation(attestation, artifact, findings)

    assert any(item.severity == "error" for item in findings)


@pytest.mark.parametrize("field", ["writeLocks", "consumers", *preflight.CONSUMERS])
def test_release_attestation_requires_every_evidence_object(field: str) -> None:
    attestation, artifact = valid_attestation()
    target = attestation if field in ("writeLocks", "consumers") else attestation["consumers"]
    del target[field]
    findings: list[preflight.Finding] = []

    preflight._validate_release_attestation(attestation, artifact, findings)

    assert any(item.severity == "error" for item in findings)


@pytest.mark.parametrize("value", [True, 0, 0.0, None, "false"])
@pytest.mark.parametrize("name", ["alphaWritesEnabled", "mintingEnabled", "ceremonyModeEnabled"])
def test_release_attestation_requires_explicit_closed_boolean_locks(name: str, value) -> None:
    attestation, artifact = valid_attestation()
    attestation["writeLocks"][name] = value
    findings: list[preflight.Finding] = []

    preflight._validate_release_attestation(attestation, artifact, findings)

    assert any(item.severity == "error" for item in findings)


def test_release_attestation_preserves_complete_locked_consumers_and_reports_errors(capsys) -> None:
    attestation, artifact = valid_attestation()
    findings: list[preflight.Finding] = []
    preflight._validate_release_attestation(attestation, artifact, findings)
    assert findings == []

    broken = copy.deepcopy(attestation)
    broken["consumers"]["api"] = {"reachable": True}
    preflight._validate_release_attestation(broken, artifact, findings)
    preflight.print_report("post-genesis", findings)
    report = capsys.readouterr().out
    assert "NOT READY" in report
    assert "READY: all offline evidence gates passed." not in report
    assert "api is not pinned" in report
