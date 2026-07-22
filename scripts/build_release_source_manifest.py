#!/usr/bin/env python3
"""Build the deterministic nine-repository RC19 source manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit


RELEASE_ID = "solslot-v2-alpha-rc19-20260721"
RELEASE_BRANCH = "release/testnet-alpha-rc19-20260721"
SOURCE_MANIFEST_VERSION = 3
SOURCE_REPOSITORIES = {
    "protocol": "https://github.com/MattHintz/solslot-protocol",
    "evm": "https://github.com/MattHintz/solslot-evm",
    "omnichain": "https://github.com/solslot/omnichain",
    "api": "https://github.com/MattHintz/solslot-api",
    "legacyBackend": "https://github.com/solslot/solslot-backend",
    "keyOfSolomon": "https://github.com/solslot/KeyofSolomon",
    "samuel": "https://github.com/solslot/Samuel",
    "customerWeb": "https://github.com/solslot/solslot",
    "adminPortal": "https://github.com/MattHintz/solslot-portal",
}
ARGUMENT_NAMES = {
    "protocol": "protocol-repo",
    "evm": "evm-repo",
    "omnichain": "omnichain-repo",
    "api": "api-repo",
    "legacyBackend": "legacy-backend-repo",
    "keyOfSolomon": "key-of-solomon-repo",
    "samuel": "samuel-repo",
    "customerWeb": "customer-web-repo",
    "adminPortal": "admin-portal-repo",
}


@dataclass(frozen=True)
class SourceState:
    name: str
    repository: str
    commit: str
    branch: str


def canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def manifest_hash(value: Mapping[str, object]) -> str:
    unsigned = {key: item for key, item in value.items() if key != "manifestHash"}
    return "0x" + hashlib.sha256(canonical_json(unsigned)).hexdigest()


def normalize_remote(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("git@github.com:"):
        candidate = "https://github.com/" + candidate.removeprefix("git@github.com:")
    parts = urlsplit(candidate)
    if parts.scheme != "https" or parts.hostname != "github.com":
        raise ValueError("release repository remote must use github.com HTTPS or SSH")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("release repository remote must not contain credentials or metadata")
    path = parts.path.removesuffix(".git").rstrip("/")
    if len([item for item in path.split("/") if item]) != 2:
        raise ValueError("release repository remote must name one GitHub repository")
    return urlunsplit(("https", "github.com", path, "", ""))


def _git(path: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"cannot inspect release repository {path}: {exc}") from exc
    return result.stdout.strip()


def inspect_source(name: str, path: Path) -> SourceState:
    commit = _git(path, "rev-parse", "HEAD").lower()
    if len(commit) != 40:
        raise ValueError(f"{name} does not resolve to a full Git commit")
    int(commit, 16)
    branch = _git(path, "branch", "--show-current")
    if branch != RELEASE_BRANCH:
        raise ValueError(f"{name} must be checked out on {RELEASE_BRANCH}")
    if _git(path, "status", "--porcelain"):
        raise ValueError(f"{name} worktree is dirty")
    remotes = {
        normalize_remote(line.split()[1])
        for line in _git(path, "remote", "-v").splitlines()
        if line.endswith("(fetch)") and len(line.split()) >= 2
    }
    expected = normalize_remote(SOURCE_REPOSITORIES[name])
    if expected not in remotes:
        raise ValueError(f"{name} does not have the canonical repository remote")
    return SourceState(name, expected, commit, branch)


def build_manifest(states: Sequence[SourceState]) -> dict[str, object]:
    by_name = {item.name: item for item in states}
    if set(by_name) != set(SOURCE_REPOSITORIES) or len(states) != len(by_name):
        raise ValueError("release source states must contain each repository exactly once")
    payload: dict[str, object] = {
        "schemaVersion": SOURCE_MANIFEST_VERSION,
        "kind": "solslot-release-source-manifest",
        "releaseId": RELEASE_ID,
        "network": "testnet11",
        "testOnly": True,
        "sourceShas": {
            name: by_name[name].commit for name in SOURCE_REPOSITORIES
        },
        "sources": {
            name: {
                "repository": by_name[name].repository,
                "branch": by_name[name].branch,
                "commit": by_name[name].commit,
            }
            for name in SOURCE_REPOSITORIES
        },
    }
    payload["manifestHash"] = manifest_hash(payload)
    return payload


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name, argument in ARGUMENT_NAMES.items():
        parser.add_argument(f"--{argument}", dest=name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    states = [inspect_source(name, getattr(args, name)) for name in SOURCE_REPOSITORIES]
    manifest = build_manifest(states)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="ascii")
    os.replace(temporary, output)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
