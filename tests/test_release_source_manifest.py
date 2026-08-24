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
    assert value["releaseId"] == "solslot-v2-alpha-rc27.35-20260823"
    assert {
        source["branch"] for source in value["sources"].values()
    } == {"release/testnet-alpha-rc27.35-20260823"}
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

    with pytest.raises(ValueError, match="coordinated RC27.35"):
        manifest.build_manifest(
            states(),
            release_id="solslot-v2-alpha-rc27.35-20260822",
        )


def test_launch_evidence_binds_manifest_puzzles_and_recovery() -> None:
    source_manifest = manifest.build_manifest(states())
    puzzle_inventory = {
        "schema": "solslot.puzzle-hashes.v1",
        "release": "RC27.35",
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
                "release": "RC27.35",
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


def test_source_inspection_requires_canonical_origin(monkeypatch) -> None:
    commit = "a" * 40

    def fake_git(_path: Path, *args: str) -> str:
        responses = {
            ("rev-parse", "HEAD"): commit,
            ("branch", "--show-current"): manifest.RELEASE_BRANCH,
            ("status", "--porcelain"): "",
            ("remote", "get-url", "origin"): (
                "https://github.com/attacker/protocol"
            ),
        }
        return responses[args]

    monkeypatch.setattr(manifest, "_git", fake_git)
    with pytest.raises(ValueError, match="origin is not the canonical"):
        manifest.inspect_source("protocol", Path("repo"))


def _release_ref_git(
    commit: str,
    *,
    remote_main: str | None = None,
    remote_release_branch: str | None = None,
    include_release_branch: bool = True,
    annotated: bool = True,
    local_tag_object: str | None = None,
    extra_ref: bool = False,
    duplicate_main: bool = False,
):
    tag_object = "b" * 40

    def fake_git(_path: Path, *args: str) -> str:
        if args[:3] == ("ls-remote", "--exit-code", "origin"):
            lines = [
                f"{remote_main or commit}\trefs/heads/main",
                f"{tag_object}\trefs/tags/{manifest.RELEASE_ID}",
            ]
            if include_release_branch:
                lines.append(
                    f"{remote_release_branch or commit}\t"
                    f"refs/heads/{manifest.RELEASE_BRANCH}"
                )
            if annotated:
                lines.append(
                    f"{commit}\trefs/tags/{manifest.RELEASE_ID}^{{}}"
                )
            if extra_ref:
                lines.append(f"{'c' * 40}\trefs/tags/unexpected")
            if duplicate_main:
                lines.append(f"{commit}\trefs/heads/main")
            return "\n".join(lines)
        if args == ("rev-parse", "origin/main^{commit}"):
            return commit
        if args == (
            "rev-parse",
            f"origin/{manifest.RELEASE_BRANCH}^{{commit}}",
        ):
            return commit
        if args == (
            "cat-file",
            "-t",
            f"refs/tags/{manifest.RELEASE_ID}",
        ):
            return "tag"
        if args == (
            "rev-parse",
            f"refs/tags/{manifest.RELEASE_ID}",
        ):
            return local_tag_object or tag_object
        if args == (
            "rev-parse",
            f"refs/tags/{manifest.RELEASE_ID}^{{commit}}",
        ):
            return commit
        raise AssertionError(args)

    return fake_git


def test_release_refs_require_live_main_and_annotated_tag(monkeypatch) -> None:
    commit = "a" * 40
    monkeypatch.setattr(manifest, "_git", _release_ref_git(commit))

    manifest.verify_release_refs(Path("repo"), commit)


def test_release_refs_reject_remote_main_drift(monkeypatch) -> None:
    commit = "a" * 40
    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, remote_main="c" * 40),
    )

    with pytest.raises(ValueError, match="live main"):
        manifest.verify_release_refs(Path("repo"), commit)


def test_release_refs_reject_remote_release_branch_drift(monkeypatch) -> None:
    commit = "a" * 40
    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, remote_release_branch="c" * 40),
    )

    with pytest.raises(ValueError, match="release/testnet-alpha-rc27.35"):
        manifest.verify_release_refs(Path("repo"), commit)


def test_release_refs_reject_missing_remote_release_branch(monkeypatch) -> None:
    commit = "a" * 40
    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, include_release_branch=False),
    )

    with pytest.raises(ValueError, match="release branch"):
        manifest.verify_release_refs(Path("repo"), commit)


def test_release_refs_reject_local_remote_tag_object_mismatch(
    monkeypatch,
) -> None:
    commit = "a" * 40
    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, local_tag_object="d" * 40),
    )

    with pytest.raises(ValueError, match="exact annotated"):
        manifest.verify_release_refs(Path("repo"), commit)


def test_release_refs_reject_lightweight_or_unexpected_remote_refs(
    monkeypatch,
) -> None:
    commit = "a" * 40
    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, annotated=False),
    )
    with pytest.raises(ValueError, match="annotated RC27.35"):
        manifest.verify_release_refs(Path("repo"), commit)

    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, duplicate_main=True),
    )
    with pytest.raises(ValueError, match="duplicate remote release ref"):
        manifest.verify_release_refs(Path("repo"), commit)

    monkeypatch.setattr(
        manifest,
        "_git",
        _release_ref_git(commit, extra_ref=True),
    )
    with pytest.raises(ValueError, match="annotated RC27.35"):
        manifest.verify_release_refs(Path("repo"), commit)
