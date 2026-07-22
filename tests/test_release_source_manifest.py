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
    assert value["schemaVersion"] == 3
    assert tuple(value["sourceShas"]) == tuple(manifest.SOURCE_REPOSITORIES)
    assert len(value["sources"]) == 9
    assert value["manifestHash"] == manifest.manifest_hash(value)


def test_manifest_hash_detects_source_tampering() -> None:
    value = manifest.build_manifest(states())
    changed = copy.deepcopy(value)
    changed["sourceShas"]["samuel"] = "f" * 40
    assert changed["manifestHash"] != manifest.manifest_hash(changed)


def test_manifest_rejects_incomplete_source_set() -> None:
    with pytest.raises(ValueError, match="each repository exactly once"):
        manifest.build_manifest(states()[:-1])


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
