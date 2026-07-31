from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build_release_source_manifest.py"
SPEC = importlib.util.spec_from_file_location("build_release_source_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
manifest = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = manifest
SPEC.loader.exec_module(manifest)


def states():
    return [
        manifest.SourceState(
            name=name,
            repository=repository,
            commit=f"{index:x}" * 40,
            branch=manifest.RELEASE_BRANCH,
        )
        for index, (name, repository) in enumerate(
            manifest.SOURCE_REPOSITORIES.items(), start=1
        )
    ]


def test_manifest_binds_all_nine_release_sources() -> None:
    value = manifest.build_manifest(states())
    assert value["schemaVersion"] == 4
    assert value["releaseId"] == "solslot-v2-alpha-rc24-20260730"
    assert {
        source["branch"] for source in value["sources"].values()
    } == {"release/testnet-alpha-rc24-20260730"}
    assert tuple(value["sourceShas"]) == tuple(manifest.SOURCE_REPOSITORIES)
    assert len(value["sources"]) == 9
    dependency = value["dependencies"]["administratorRecovery"]
    assert dependency["commit"] == manifest.PINNED_CNI_WALLET_SDK_COMMIT
    assert dependency["manifestHash"] == (
        "0x" + manifest.RECOVERY_DEPENDENCY_MANIFEST_HASH
    )
    assert value["authoritySourceCommitment"] == (
        manifest.authority_source_commitment(value["sourceShas"])
    )
    assert value["manifestHash"] == manifest.manifest_hash(value)


def test_manifest_hash_detects_source_tampering() -> None:
    value = manifest.build_manifest(states())
    changed = copy.deepcopy(value)
    changed["sourceShas"]["samuel"] = "f" * 40
    assert changed["manifestHash"] != manifest.manifest_hash(changed)


def test_manifest_rejects_incomplete_source_set() -> None:
    with pytest.raises(ValueError, match="each repository exactly once"):
        manifest.build_manifest(states()[:-1])


def test_manifest_rejects_a_mixed_or_mismatched_release_branch() -> None:
    changed = states()
    changed[0] = manifest.SourceState(
        name=changed[0].name,
        repository=changed[0].repository,
        commit=changed[0].commit,
        branch="main",
    )
    with pytest.raises(ValueError, match="release branch"):
        manifest.build_manifest(changed)

    with pytest.raises(ValueError, match="correspond"):
        manifest.build_manifest(
            states(),
            release_id="solslot-v2-alpha-rc24-20260731",
        )


def test_launch_evidence_binds_manifest_puzzles_and_recovery() -> None:
    source_manifest = manifest.build_manifest(states())
    puzzle_inventory = {
        "schema": "solslot.puzzle-hashes.v1",
        "release": "RC24",
        "canonicalChecksum": manifest.FROZEN_CHECKSUM,
    }
    evidence = manifest.build_launch_evidence(
        source_manifest,
        manifest_file_sha256="a" * 64,
        puzzle_inventory=puzzle_inventory,
        puzzle_inventory_file_sha256="b" * 64,
        generated_at="2026-07-29T12:00:00Z",
        release_refs_verified=True,
    )
    assert evidence["schemaVersion"] == 5
    assert evidence["completeReleaseManifest"] is True
    assert evidence["sourceManifest"] == source_manifest
    assert evidence["protocolFreeze"][
        "recoveryDependencyManifestHash"
    ] == "0x" + manifest.RECOVERY_DEPENDENCY_MANIFEST_HASH
    assert evidence["readiness"][
        "independentAuthorityReviewReady"
    ] is False


def test_launch_evidence_refuses_unverified_release_refs() -> None:
    with pytest.raises(ValueError, match="origin/main"):
        manifest.build_launch_evidence(
            manifest.build_manifest(states()),
            manifest_file_sha256="a" * 64,
            puzzle_inventory={
                "schema": "solslot.puzzle-hashes.v1",
                "release": "RC24",
                "canonicalChecksum": manifest.FROZEN_CHECKSUM,
            },
            puzzle_inventory_file_sha256="b" * 64,
            generated_at="2026-07-29T12:00:00Z",
            release_refs_verified=False,
        )


@pytest.mark.parametrize(
    ("remote", "expected"),
    [
        ("git@github.com:solslot/Samuel.git", "https://github.com/solslot/Samuel"),
        ("https://github.com/solslot/solslot.git", "https://github.com/solslot/solslot"),
    ],
)
def test_remote_normalization(remote: str, expected: str) -> None:
    assert manifest.normalize_remote(remote) == expected


def test_remote_normalization_rejects_embedded_credentials() -> None:
    with pytest.raises(ValueError, match="credentials"):
        manifest.normalize_remote("https://token@github.com/solslot/Samuel.git")
