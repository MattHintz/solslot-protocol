#!/usr/bin/env python3
"""Build the deterministic nine-repository RC24 source manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from solslot_puzzles.recovery_dependencies import (
    PINNED_CNI_WALLET_SDK_COMMIT,
    PINNED_CNI_WALLET_SDK_LICENSE,
    PINNED_CNI_WALLET_SDK_REPOSITORY,
    RECOVERY_DEPENDENCY_MANIFEST_HASH,
)
from solslot_puzzles import FROZEN_CHECKSUM


RELEASE_ID = "solslot-v2-alpha-rc24-20260730"
RELEASE_BRANCH = "release/testnet-alpha-rc24-20260730"
SOURCE_MANIFEST_VERSION = 4
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


def file_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def authority_source_commitment(source_shas: Mapping[str, str]) -> str:
    payload = {
        "version": SOURCE_MANIFEST_VERSION,
        "sources": dict(source_shas),
        "dependencies": {
            "administratorRecovery": (
                "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
            )
        },
    }
    return "0x" + hashlib.sha256(canonical_json(payload)).hexdigest()


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


def inspect_source(
    name: str,
    path: Path,
    *,
    release_branch: str = RELEASE_BRANCH,
) -> SourceState:
    commit = _git(path, "rev-parse", "HEAD").lower()
    if len(commit) != 40:
        raise ValueError(f"{name} does not resolve to a full Git commit")
    int(commit, 16)
    branch = _git(path, "branch", "--show-current")
    if branch != release_branch:
        raise ValueError(f"{name} must be checked out on {release_branch}")
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


def build_manifest(
    states: Sequence[SourceState],
    *,
    release_id: str = RELEASE_ID,
    release_branch: str = RELEASE_BRANCH,
) -> dict[str, object]:
    by_name = {item.name: item for item in states}
    if set(by_name) != set(SOURCE_REPOSITORIES) or len(states) != len(by_name):
        raise ValueError("release source states must contain each repository exactly once")
    if not release_id.startswith("solslot-v2-alpha-rc24-"):
        raise ValueError("release_id must identify an RC24 alpha release")
    expected_branch = (
        "release/testnet-alpha-"
        + release_id.removeprefix("solslot-v2-alpha-")
    )
    if release_branch != expected_branch:
        raise ValueError("release branch must correspond to release_id")
    if {item.branch for item in states} != {release_branch}:
        raise ValueError("all source states must use the release branch")
    source_shas = {
        name: by_name[name].commit for name in SOURCE_REPOSITORIES
    }
    payload: dict[str, object] = {
        "schemaVersion": SOURCE_MANIFEST_VERSION,
        "kind": "solslot-release-source-manifest",
        "releaseId": release_id,
        "network": "testnet11",
        "testOnly": True,
        "sourceShas": source_shas,
        "dependencies": {
            "administratorRecovery": {
                "repository": PINNED_CNI_WALLET_SDK_REPOSITORY,
                "commit": PINNED_CNI_WALLET_SDK_COMMIT,
                "license": PINNED_CNI_WALLET_SDK_LICENSE,
                "manifestHash": (
                    "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
                ),
            }
        },
        "authoritySourceCommitment": authority_source_commitment(
            source_shas
        ),
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


def verify_release_refs(path: Path, commit: str) -> None:
    main_commit = _git(path, "rev-parse", "origin/main^{commit}").lower()
    tag_commit = _git(path, "rev-list", "-n", "1", RELEASE_ID).lower()
    if main_commit != commit or tag_commit != commit:
        raise ValueError(
            f"{path} must have the exact RC24 commit on origin/main and {RELEASE_ID}"
        )


def build_launch_evidence(
    manifest: Mapping[str, Any],
    *,
    manifest_file_sha256: str,
    puzzle_inventory: Mapping[str, Any],
    puzzle_inventory_file_sha256: str,
    generated_at: str,
    release_refs_verified: bool,
) -> dict[str, Any]:
    if (
        manifest.get("schemaVersion") != SOURCE_MANIFEST_VERSION
        or manifest.get("releaseId") != RELEASE_ID
        or manifest.get("manifestHash") != manifest_hash(manifest)
    ):
        raise ValueError("RC24 source manifest is invalid")
    if release_refs_verified is not True:
        raise ValueError(
            "launch evidence requires exact origin/main and RC24 tag verification"
        )
    if (
        puzzle_inventory.get("schema") != "solslot.puzzle-hashes.v1"
        or puzzle_inventory.get("release") != "RC24"
        or puzzle_inventory.get("canonicalChecksum") != FROZEN_CHECKSUM
    ):
        raise ValueError("RC24 puzzle inventory is stale")
    try:
        parsed_time = datetime.fromisoformat(
            generated_at.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("generated_at must be ISO-8601") from exc
    if parsed_time.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    return {
        "schemaVersion": 5,
        "kind": "solslot-rc24-launch-source-evidence",
        "releaseTag": RELEASE_ID,
        "releaseId": RELEASE_ID,
        "generatedAt": generated_at,
        "network": "testnet11",
        "testOnly": True,
        "auditStatus": "pending-external-review",
        "completeReleaseManifest": True,
        "releaseRefsVerified": True,
        "manifestHash": manifest["manifestHash"],
        "sourceManifestFileSha256": manifest_file_sha256,
        "sourceManifest": dict(manifest),
        "protocolFreeze": {
            "puzzleInventory": dict(puzzle_inventory),
            "puzzleInventoryFileSha256": (
                puzzle_inventory_file_sha256
            ),
            "canonicalPuzzleChecksum": FROZEN_CHECKSUM,
            "recoveryDependencyManifestHash": (
                "0x" + RECOVERY_DEPENDENCY_MANIFEST_HASH
            ),
        },
        "readiness": {
            "sourceFreezeReady": True,
            "independentAuthorityReviewReady": False,
            "freshFundingVerified": False,
            "ceremonyPackageReady": False,
            "settlementRehearsalReady": False,
            "freshAdministratorEnrollmentComplete": False,
        },
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name, argument in ARGUMENT_NAMES.items():
        parser.add_argument(f"--{argument}", dest=name, type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence-output", type=Path)
    parser.add_argument(
        "--puzzle-inventory",
        type=Path,
        default=(
            Path(__file__).resolve().parents[1]
            / "release-manifests"
            / "rc24-puzzle-hashes.json"
        ),
    )
    parser.add_argument("--generated-at")
    parser.add_argument(
        "--require-release-refs",
        action="store_true",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    states = [
        inspect_source(
            name,
            getattr(args, name),
            release_branch=RELEASE_BRANCH,
        )
        for name in SOURCE_REPOSITORIES
    ]
    if args.evidence_output and not args.require_release_refs:
        raise ValueError(
            "--evidence-output requires --require-release-refs"
        )
    if args.require_release_refs:
        for state in states:
            verify_release_refs(
                getattr(args, state.name),
                state.commit,
            )
    manifest = build_manifest(states)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    manifest_bytes = (
        json.dumps(manifest, indent=2) + "\n"
    ).encode("ascii")
    temporary.write_bytes(manifest_bytes)
    os.replace(temporary, output)
    if args.evidence_output:
        puzzle_inventory_path = args.puzzle_inventory.resolve()
        puzzle_inventory_bytes = puzzle_inventory_path.read_bytes()
        puzzle_inventory = json.loads(puzzle_inventory_bytes)
        if not isinstance(puzzle_inventory, Mapping):
            raise ValueError("RC24 puzzle inventory must be an object")
        generated_at = args.generated_at or (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
        evidence = build_launch_evidence(
            manifest,
            manifest_file_sha256=file_sha256(manifest_bytes),
            puzzle_inventory=puzzle_inventory,
            puzzle_inventory_file_sha256=file_sha256(
                puzzle_inventory_bytes
            ),
            generated_at=generated_at,
            release_refs_verified=True,
        )
        evidence_output = args.evidence_output.resolve()
        evidence_output.parent.mkdir(parents=True, exist_ok=True)
        evidence_temporary = evidence_output.with_name(
            evidence_output.name + ".tmp"
        )
        evidence_temporary.write_text(
            json.dumps(evidence, indent=2) + "\n",
            encoding="ascii",
        )
        os.replace(evidence_temporary, evidence_output)
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
